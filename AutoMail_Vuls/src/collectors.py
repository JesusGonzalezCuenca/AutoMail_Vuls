import requests
import json
from datetime import datetime
import xml.etree.ElementTree as ET
import re
import html

MSRC_API_BASE_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/"
MSRC_UPDATES_URL = f"{MSRC_API_BASE_URL}updates"

XML_NAMESPACES = {
    'vuln': 'http://www.icasi.org/CVRF/schema/vuln/1.1',
    'cvrf': 'http://www.icasi.org/CVRF/schema/cvrf/1.1'
}


def get_xml_text(element, path, default=None):
    """Función auxiliar para obtener texto de un elemento XML, manejando namespaces."""
    if element is None:  # Añadido para seguridad
        return default
    try:
        node = element.find(path, XML_NAMESPACES)
        if node is not None and node.text is not None:
            return node.text.strip()  # Añadido strip() aquí también
        return default
    except AttributeError:
        return default


def fetch_msrc_vulnerabilities():
    """
    Obtiene las últimas vulnerabilidades del Microsoft Security Response Center (MSRC).
    """
    try:
        response_updates = requests.get(MSRC_UPDATES_URL)
        response_updates.raise_for_status()
        updates_data = response_updates.json()

        if not updates_data.get('value'):
            print("No se encontraron actualizaciones mensuales de MSRC.")
            return []

        sorted_updates = sorted(
            updates_data['value'],
            key=lambda x: datetime.strptime(
                x['InitialReleaseDate'], '%Y-%m-%dT%H:%M:%SZ'),
            reverse=True
        )

        if not sorted_updates:
            print("No se pudieron ordenar las actualizaciones.")
            return []

        latest_update_doc_summary = sorted_updates[0]
        print(
            f"Procesando el documento de actualización: {latest_update_doc_summary.get('ID')}")

        cvrf_url = latest_update_doc_summary.get('CvrfUrl')
        if not cvrf_url:
            print(
                f"No se encontró CvrfUrl para el documento {latest_update_doc_summary.get('ID')}")
            return []

        response_cvrf = requests.get(cvrf_url)
        response_cvrf.raise_for_status()

        print(f"Status Code de CVRF: {response_cvrf.status_code}")
        # print(f"Contenido de CVRF (texto): {response_cvrf.text[:1000]}")

        root = ET.fromstring(response_cvrf.content)
        doc_tracking = root.find('cvrf:DocumentTracking', XML_NAMESPACES)
        cvrf_release_date = get_xml_text(
            doc_tracking, 'cvrf:InitialReleaseDate')

        parsed_vulnerabilities = []
        for vuln_node in root.findall('vuln:Vulnerability', XML_NAMESPACES):
            cve_id = get_xml_text(vuln_node, 'vuln:CVE')

            title_node = vuln_node.find('vuln:Title', XML_NAMESPACES)
            title = None
            if title_node is not None and title_node.text and title_node.text.strip():
                title = title_node.text.strip()
            else:
                continue

            description = None  # Inicializar
            description_node_found_but_empty = False  # Nuevo flag

            notes_node = vuln_node.find('vuln:Notes', XML_NAMESPACES)
            if notes_node is not None:
                for note in notes_node.findall('vuln:Note', XML_NAMESPACES):
                    if note.get('Title') == 'Description' and note.get('Type') == 'Description':
                        raw_text_content = "".join(note.itertext()).strip()
                        if raw_text_content:  # Si hay contenido real
                            unescaped_text = html.unescape(raw_text_content)
                            plain_text = re.sub(r'<[^>]+>', '', unescaped_text)
                            clean_description = re.sub(
                                r'\s+', ' ', plain_text).strip()
                            if clean_description and clean_description.lower() != 'none':
                                description = clean_description
                            # else: description permanece None si es solo "none" o vacío después de limpiar
                        # El nodo de descripción existe pero está vacío (ej: <Note .../>)
                        else:
                            description_node_found_but_empty = True
                            # description permanece None, o podrías poner description = "" aquí si lo prefieres
                        # Encontramos la nota de descripción (con o sin contenido)
                        break

            # Modificar la condición para saltar:
            # Saltar solo si NO se encontró un nodo de descripción O si se encontró pero estaba vacío Y NO quieres incluirlo.
            # Si quieres incluirlo incluso si la descripción es vacía (pero el nodo existe), ajusta esto.
            # El comportamiento actual es: si description es None (porque no se encontró nota o estaba vacía y no se procesó), se salta.
            if description is None and not description_node_found_but_empty:
                # Esto significa que no se encontró NINGUNA nota con Title="Description"
                # Opcionalmente, si quieres saltar también si description_node_found_but_empty es True:
                # if description is None: # Esto cubre ambos casos: no nota, o nota vacía que no llenó 'description'
                #     continue
                # Para tu caso actual, donde quieres saltar si la descripción efectiva es None:
                if description is None:  # Si después de todo el proceso, description sigue siendo None
                    # if cve_id: print(f"[DEBUG] Saltando CVE {cve_id} por falta de descripción final.")
                    continue

            latest_published_date = None
            revision_history_node = vuln_node.find(
                'vuln:RevisionHistory', XML_NAMESPACES)
            if revision_history_node is not None:
                all_revision_dates = []
                for revision_node in revision_history_node.findall('vuln:Revision', XML_NAMESPACES):
                    date_str = get_xml_text(revision_node, 'cvrf:Date')
                    if date_str:
                        try:
                            try:
                                dt_obj = datetime.strptime(
                                    date_str, '%Y-%m-%dT%H:%M:%SZ')
                            except ValueError:
                                dt_obj = datetime.strptime(
                                    date_str, '%Y-%m-%dT%H:%M:%S')
                            all_revision_dates.append(dt_obj)
                        except ValueError as ve:
                            pass

                if all_revision_dates:
                    latest_published_date = max(
                        all_revision_dates).strftime('%Y-%m-%dT%H:%M:%S')

            published_date = latest_published_date

            severity = None
            threats_node = vuln_node.find('vuln:Threats', XML_NAMESPACES)
            if threats_node is not None:
                for threat in threats_node.findall('vuln:Threat', XML_NAMESPACES):
                    if threat.get('Type') == 'Severity':
                        severity_desc_node = threat.find(
                            'vuln:Description', XML_NAMESPACES)
                        if severity_desc_node is not None:
                            if severity_desc_node.text and severity_desc_node.text.strip():
                                severity = severity_desc_node.text.strip()
                            else:
                                severity = "N/A"
                        break

            cvss_base_score = None
            cvss_vector = None
            cvss_score_sets_node = vuln_node.find(
                'vuln:CVSSScoreSets', XML_NAMESPACES)
            if cvss_score_sets_node is not None:
                score_set_node = cvss_score_sets_node.find(
                    'vuln:ScoreSet', XML_NAMESPACES)
                if score_set_node is not None:
                    cvss_base_score = get_xml_text(
                        score_set_node, 'vuln:BaseScore')
                    cvss_vector = get_xml_text(score_set_node, 'vuln:Vector')

            if cve_id:
                parsed_vulnerabilities.append({
                    'id': cve_id,
                    'title': title,
                    'published_date': published_date,
                    'description': description,
                    'severity': severity,
                    'cvss_base_score': cvss_base_score,
                    'cvss_vector': cvss_vector,
                    'source': 'MSRC',
                })

        print(
            f"Parseadas {len(parsed_vulnerabilities)} vulnerabilidades del documento {latest_update_doc_summary.get('ID')}.")
        return parsed_vulnerabilities

    except requests.exceptions.RequestException as e:
        print(f"Error de red o HTTP al obtener datos de MSRC: {e}")
        return []
    except ET.ParseError as e:
        print(f"Error al parsear XML de MSRC: {e}")
        return []
    except json.JSONDecodeError as e:
        print(f"Error al decodificar JSON de la lista de updates de MSRC: {e}")
        return []
    except Exception as e:
        print(f"Error inesperado al procesar datos de MSRC: {e}")
        import traceback
        traceback.print_exc()
        return []


if __name__ == '__main__':
    print("Obteniendo Vulnerabilidades de MSRC...")
    msrc_vulnerabilities = fetch_msrc_vulnerabilities()
    if msrc_vulnerabilities:
        print(
            f"\nSe encontraron {len(msrc_vulnerabilities)} vulnerabilidades en el último informe de MSRC:")

        print("\n--- Últimas 20 vulnerabilidades del MSRC (o todas si son menos de 20) ---")
        start_index = max(0, len(msrc_vulnerabilities) - 20)
        for vuln in msrc_vulnerabilities[start_index:]:
            print(json.dumps(vuln, indent=2, ensure_ascii=False))

    else:
        print("No se encontraron vulnerabilidades de MSRC o hubo un error.")
