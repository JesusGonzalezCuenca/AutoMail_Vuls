import requests
import json
from datetime import datetime
import xml.etree.ElementTree as ET
import re
import html
import traceback

# --- CONSTANTES GLOBALES ---
# URL base de la API de MSRC para CVRF v3.0
MSRC_API_BASE_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/"
# URL específica para obtener la lista de actualizaciones de documentos CVRF
MSRC_UPDATES_URL = f"{MSRC_API_BASE_URL}updates"

# Diccionario de namespaces XML utilizados en los documentos CVRF de MSRC
XML_NAMESPACES = {
    'vuln': 'http://www.icasi.org/CVRF/schema/vuln/1.1',
    'cvrf': 'http://www.icasi.org/CVRF/schema/cvrf/1.1'
}

# Mapa para convertir número de mes a abreviatura en inglés (usado en IDs de MSRC)
MONTH_ABBREVIATIONS = {
    1: "Jan", 2: "Feb", 3: "Mar", 4: "Apr", 5: "May", 6: "Jun",
    7: "Jul", 8: "Aug", 9: "Sep", 10: "Oct", 11: "Nov", 12: "Dec"
}

# --- FUNCIONES AUXILIARES ---


def get_xml_text(element, path, default=None):
    """
    Función auxiliar para obtener el texto de un subelemento XML dado un path,
    manejando los namespaces definidos en XML_NAMESPACES.
    Devuelve un valor por defecto si el elemento no se encuentra o está vacío.
    """
    if element is None:
        return default
    try:
        node = element.find(path, XML_NAMESPACES)
        if node is not None and node.text is not None:
            text = node.text.strip()
            # Devuelve el texto si no está vacío después de quitar espacios, sino el valor por defecto
            return text if text else default
        return default
    except AttributeError:  # pragma: no cover
        # En caso de un error de atributo (poco probable con la comprobación de element is None)
        return default


def _clean_xml_text_content(raw_text_content):
    """
    Limpia el contenido de texto extraído de XML.
    Realiza las siguientes operaciones:
    1. Desescapa entidades HTML (ej. &lt; -> <).
    2. Elimina etiquetas HTML.
    3. Normaliza los espacios en blanco (múltiples espacios a uno solo).
    4. Devuelve None si el texto resultante está vacío o es la cadena "none" (insensible a mayúsculas).
    """
    if not raw_text_content:
        return None
    unescaped_text = html.unescape(raw_text_content)
    # Elimina etiquetas HTML
    plain_text = re.sub(r'<[^>]+>', '', unescaped_text)
    # Normaliza espacios en blanco y quita espacios al inicio/final
    clean_text = re.sub(r'\s+', ' ', plain_text).strip()
    if clean_text and clean_text.lower() != 'none':
        return clean_text
    return None  # Devuelve None si está vacío después de limpiar o era "none"


def _parse_notes(vuln_node, clean_func):
    """
    Parsea la sección <vuln:Notes> de un nodo de vulnerabilidad XML.
    Extrae la descripción principal, FAQs, tags, información CNA y acción del cliente.
    Utiliza la función clean_func para limpiar el contenido de texto.
    """
    data = {
        'description': None,
        # Esta bandera es crucial para la lógica de filtro existente para la descripción
        'description_node_found_but_empty': False,
        'faq_list': [],
        'tags': [],
        'cna': None,
        'customer_action': None
    }
    notes_node = vuln_node.find('vuln:Notes', XML_NAMESPACES)
    if not notes_node:
        return data  # Si no hay sección de notas, devuelve los valores por defecto

    # Bandera para asegurar que 'description' y 'description_node_found_but_empty'
    # se establezcan basados en la *primera* nota de tipo "Description" encontrada,
    # imitando el comportamiento del código original que tenía un 'break'.
    description_filter_info_set = False
    for note in notes_node.findall('vuln:Note', XML_NAMESPACES):
        note_title_attr = note.get('Title')  # Atributo 'Title' de la nota
        note_type_attr = note.get('Type')   # Atributo 'Type' de la nota

        # Concatena todo el texto dentro del nodo <vuln:Note>, incluyendo sub-etiquetas
        raw_text_content = "".join(note.itertext()).strip()
        clean_note_text = clean_func(raw_text_content)  # Limpia el texto

        # Lógica para la descripción principal (usada en el filtro)
        if note_title_attr == 'Description' and note_type_attr == 'Description':
            if not description_filter_info_set:  # Procesar solo la primera para las banderas del filtro
                if clean_note_text:
                    data['description'] = clean_note_text
                # El nodo existe pero está vacío (ej. <Note .../> o <Note></Note>)
                elif not raw_text_content:
                    data['description_node_found_but_empty'] = True
                description_filter_info_set = True
        # Otras notas
        elif note_title_attr == 'FAQ' and clean_note_text:
            data['faq_list'].append(clean_note_text)
        elif note_title_attr == 'Tag' and clean_note_text:
            data['tags'].append(clean_note_text)
        elif note_title_attr == 'Microsoft' and note_type_attr == 'CNA' and clean_note_text:
            # Asume una sola nota CNA de Microsoft
            data['cna'] = clean_note_text
        elif note_title_attr == 'Customer Action Required' and clean_note_text:
            # Asume una sola nota de acción del cliente
            data['customer_action'] = clean_note_text
    return data


def _parse_cwe(vuln_node):
    """
    Parsea la sección <vuln:CWE> de un nodo de vulnerabilidad XML.
    Extrae el ID y la descripción del CWE.
    """
    cwe_node = vuln_node.find('vuln:CWE', XML_NAMESPACES)
    if cwe_node is not None:
        return {
            'id': cwe_node.get('ID'),  # Obtiene el atributo ID del nodo CWE
            'description': cwe_node.text.strip() if cwe_node.text and cwe_node.text.strip() else None
        }
    # Valores por defecto si no se encuentra CWE
    return {'id': None, 'description': None}


def _parse_product_statuses(vuln_node):
    """
    Parsea la sección <vuln:ProductStatuses> de un nodo de vulnerabilidad XML.
    Extrae una lista de IDs de productos afectados.
    """
    product_ids_affected = []
    product_statuses_node = vuln_node.find(
        'vuln:ProductStatuses', XML_NAMESPACES)
    if product_statuses_node is not None:
        # Itera sobre cada <vuln:Status>
        for status_node in product_statuses_node.findall('vuln:Status', XML_NAMESPACES):
            # Itera sobre cada <vuln:ProductID> dentro de <vuln:Status>
            for prod_id_node in status_node.findall('vuln:ProductID', XML_NAMESPACES):
                if prod_id_node.text and prod_id_node.text.strip():
                    product_ids_affected.append(prod_id_node.text.strip())
    return product_ids_affected


def _parse_revision_history(vuln_node, clean_func):
    """
    Parsea la sección <vuln:RevisionHistory> de un nodo de vulnerabilidad XML.
    Extrae el historial de revisiones y determina la fecha de publicación más reciente.
    Utiliza la función clean_func para limpiar las descripciones de las revisiones.
    """
    revision_history_list = []
    latest_published_date_obj = None  # Objeto datetime para la fecha más reciente
    revision_history_node = vuln_node.find(
        'vuln:RevisionHistory', XML_NAMESPACES)

    if revision_history_node is not None:
        # Lista para almacenar todas las fechas de revisión como objetos datetime
        all_revision_dates_objs = []
        for revision_node in revision_history_node.findall('vuln:Revision', XML_NAMESPACES):
            rev_number = get_xml_text(
                revision_node, 'cvrf:Number')  # Número de revisión
            # Fecha de revisión como string
            rev_date_str = get_xml_text(revision_node, 'cvrf:Date')

            rev_desc_node = revision_node.find(
                'cvrf:Description', XML_NAMESPACES)
            rev_description_text = None
            if rev_desc_node is not None:
                raw_desc_text = "".join(rev_desc_node.itertext()).strip()
                rev_description_text = clean_func(
                    raw_desc_text)  # Limpia la descripción

            revision_history_list.append({
                'number': rev_number,
                'date': rev_date_str,
                'description': rev_description_text
            })

            # Convierte la fecha de revisión a objeto datetime para encontrar la más reciente
            if rev_date_str:
                try:
                    # Intenta parsear con formato que incluye 'Z' (UTC)
                    dt_obj = datetime.strptime(
                        rev_date_str, '%Y-%m-%dT%H:%M:%SZ')
                except ValueError:
                    try:
                        # Intenta parsear con formato sin 'Z'
                        dt_obj = datetime.strptime(
                            rev_date_str, '%Y-%m-%dT%H:%M:%S')
                    except ValueError:
                        dt_obj = None  # pragma: no cover # Si falla, la fecha no es válida
                if dt_obj:
                    all_revision_dates_objs.append(dt_obj)

        if all_revision_dates_objs:
            # Obtiene la fecha más reciente
            latest_published_date_obj = max(all_revision_dates_objs)

    # Formatea la fecha más reciente a string, o None si no hay fechas válidas
    published_date_str = latest_published_date_obj.strftime(
        '%Y-%m-%dT%H:%M:%S') if latest_published_date_obj else None
    return revision_history_list, published_date_str


def _parse_threats(vuln_node):
    """
    Parsea la sección <vuln:Threats> de un nodo de vulnerabilidad XML.
    Extrae la severidad, descripción del impacto, IDs de productos impactados y estado de explotación.
    """
    data = {
        'severity': None,
        'impact_description': None,
        'impact_product_ids': [],
        'exploit_status_description': None
    }
    threats_node = vuln_node.find('vuln:Threats', XML_NAMESPACES)
    if threats_node is not None:
        for threat in threats_node.findall('vuln:Threat', XML_NAMESPACES):
            # Tipo de amenaza (Severity, Impact, Exploit Status)
            threat_type = threat.get('Type')
            # Descripción de la amenaza
            desc_text = get_xml_text(threat, 'vuln:Description')

            if threat_type == 'Severity':
                if desc_text:
                    data['severity'] = desc_text
                # Si el nodo Description existe pero está vacío, se considera "N/A"
                elif threat.find('vuln:Description', XML_NAMESPACES) is not None:
                    data['severity'] = "N/A"
            elif threat_type == 'Impact':
                data['impact_description'] = desc_text
                # Extrae ProductID dentro de la amenaza de tipo Impact
                for prod_id_node in threat.findall('vuln:ProductID', XML_NAMESPACES):
                    if prod_id_node.text and prod_id_node.text.strip():
                        data['impact_product_ids'].append(
                            prod_id_node.text.strip())
            elif threat_type == 'Exploit Status':
                data['exploit_status_description'] = desc_text
    return data


def _parse_cvss_scores(vuln_node):
    """
    Parsea la sección <vuln:CVSSScoreSets> de un nodo de vulnerabilidad XML.
    Extrae la puntuación base, vector, puntuación temporal y ProductID del primer ScoreSet.
    """
    data = {'base_score': None, 'vector': None,
            'temporal_score': None, 'product_id': None}
    cvss_score_sets_node = vuln_node.find('vuln:CVSSScoreSets', XML_NAMESPACES)
    if cvss_score_sets_node is not None:
        # Asume que tomamos el primer <vuln:ScoreSet> si hay múltiples
        score_set_node = cvss_score_sets_node.find(
            'vuln:ScoreSet', XML_NAMESPACES)
        if score_set_node is not None:
            data['base_score'] = get_xml_text(score_set_node, 'vuln:BaseScore')
            data['vector'] = get_xml_text(score_set_node, 'vuln:Vector')
            data['temporal_score'] = get_xml_text(
                score_set_node, 'vuln:TemporalScore')
            data['product_id'] = get_xml_text(score_set_node, 'vuln:ProductID')
    return data


def _parse_remediations(vuln_node):
    """
    Parsea la sección <vuln:Remediations> de un nodo de vulnerabilidad XML.
    Extrae una lista de descripciones de remediaciones.
    """
    remediations_list = []
    remediations_node = vuln_node.find('vuln:Remediations', XML_NAMESPACES)
    if remediations_node is not None:
        for rem_node in remediations_node.findall('vuln:Remediation', XML_NAMESPACES):
            # Descripción de la remediación
            rem_desc = get_xml_text(rem_node, 'vuln:Description')
            if rem_desc:
                remediations_list.append(rem_desc)
            # Fallback si la descripción está directamente en el texto del nodo Remediation
            elif rem_node.text and rem_node.text.strip():
                remediations_list.append(rem_node.text.strip())
        # Fallback si el texto está directamente en el nodo Remediations (no en subnodos Remediation)
        if not remediations_list and remediations_node.text and remediations_node.text.strip():
            remediations_list.append(remediations_node.text.strip())
    return remediations_list


def _parse_acknowledgments(vuln_node, clean_func):
    """
    Parsea la sección <vuln:Acknowledgments> de un nodo de vulnerabilidad XML.
    Extrae una lista de agradecimientos, cada uno con nombre y URL.
    Utiliza la función clean_func para limpiar los nombres.
    """
    acknowledgments_list = []
    acknowledgments_node = vuln_node.find(
        'vuln:Acknowledgments', XML_NAMESPACES)
    if acknowledgments_node is not None:
        for ack_node in acknowledgments_node.findall('vuln:Acknowledgment', XML_NAMESPACES):
            name_node = ack_node.find('vuln:Name', XML_NAMESPACES)
            ack_name = None
            if name_node is not None:
                raw_name_text = "".join(name_node.itertext()).strip()
                ack_name = clean_func(raw_name_text)  # Limpia el nombre

            # URL del agradecimiento
            ack_url = get_xml_text(ack_node, 'vuln:URL')
            if ack_name or ack_url:  # Añade si hay al menos nombre o URL
                acknowledgments_list.append({'name': ack_name, 'url': ack_url})
    return acknowledgments_list

# --- FUNCIÓN PRINCIPAL DEL COLECTOR DE MSRC ---


def fetch_msrc_vulnerabilities(target_year=2025, target_month=4):
    """
    Obtiene las vulnerabilidades del Microsoft Security Response Center (MSRC)
    para un mes y año específicos, o el más reciente si no se especifican.
    1. Obtiene la lista de documentos de actualización mensuales.
    2. Selecciona el documento para el target_year y target_month, o el más reciente.
    3. Descarga y parsea el documento CVRF (XML).
    4. Itera sobre cada vulnerabilidad en el documento.
    5. Aplica filtros (título y descripción no vacíos).
    6. Extrae información detallada de cada vulnerabilidad que pasa el filtro.
    7. Devuelve una lista de diccionarios, cada uno representando una vulnerabilidad.
    """
    try:
        # 1. Obtener la lista de actualizaciones mensuales
        response_updates = requests.get(MSRC_UPDATES_URL)
        response_updates.raise_for_status()  # Lanza excepción si hay error HTTP
        updates_data = response_updates.json()  # Parsea la respuesta JSON

        if not updates_data.get('value'):
            print("No se encontraron actualizaciones mensuales de MSRC.")
            return []

        selected_update_doc_summary = None

        if target_year and target_month:
            target_month_abbr = MONTH_ABBREVIATIONS.get(target_month)
            if not target_month_abbr:  # pragma: no cover
                print(
                    f"Mes inválido: {target_month}. No se puede generar el ID de búsqueda.")
                return []

            target_id_str = f"{target_year}-{target_month_abbr}"
            print(f"Buscando documento de MSRC con ID: {target_id_str}")

            for update_doc in updates_data['value']:
                if update_doc.get('ID') == target_id_str:
                    selected_update_doc_summary = update_doc
                    break

            if not selected_update_doc_summary:
                print(
                    f"No se encontró el documento de MSRC para {target_id_str} (Año: {target_year}, Mes: {target_month}).")
                available_ids = [doc.get('ID')
                                 for doc in updates_data['value'] if doc.get('ID')]
                print(
                    f"IDs de documentos disponibles en MSRC: {available_ids}")
                return []
        else:
            # Comportamiento original: Selecciona el documento más reciente
            sorted_updates = sorted(
                updates_data['value'],
                key=lambda x: datetime.strptime(
                    x['InitialReleaseDate'], '%Y-%m-%dT%H:%M:%SZ'),
                reverse=True
            )

            if not sorted_updates:  # pragma: no cover
                print("No se pudieron ordenar las actualizaciones.")
                return []
            selected_update_doc_summary = sorted_updates[0]
            print(
                f"Seleccionado el documento más reciente de MSRC: {selected_update_doc_summary.get('ID')}")

        print(
            f"Procesando el documento de actualización: {selected_update_doc_summary.get('ID')}")

        cvrf_url = selected_update_doc_summary.get(
            'CvrfUrl')  # URL del documento CVRF XML
        if not cvrf_url:  # pragma: no cover
            print(
                f"No se encontró CvrfUrl para el documento {selected_update_doc_summary.get('ID')}")
            return []

        # 3. Descargar el documento CVRF (XML)
        response_cvrf = requests.get(cvrf_url)
        response_cvrf.raise_for_status()
        print(f"Status Code de CVRF: {response_cvrf.status_code}")

        # Parsear el contenido XML
        root = ET.fromstring(response_cvrf.content)
        parsed_vulnerabilities = []  # Lista para almacenar las vulnerabilidades parseadas

        # 4. Iterar sobre cada nodo <vuln:Vulnerability> en el XML
        for vuln_node in root.findall('vuln:Vulnerability', XML_NAMESPACES):
            cve_id = get_xml_text(vuln_node, 'vuln:CVE')
            title = get_xml_text(vuln_node, 'vuln:Title')

            # 5. Aplicar filtro por título: si no hay título, se salta la vulnerabilidad
            if not title:
                continue

            # Parsear las notas para obtener la descripción y otras informaciones
            notes_data = _parse_notes(vuln_node, _clean_xml_text_content)
            description = notes_data['description']
            description_node_found_but_empty = notes_data['description_node_found_but_empty']

            # 5. Aplicar filtro por descripción (lógica original):
            # Si la descripción es None Y el nodo de descripción no fue encontrado (o sea, no es que esté vacío),
            # entonces se salta la vulnerabilidad.
            if description is None and not description_node_found_but_empty:
                continue

            # 6. Extraer información detallada usando las funciones de parseo auxiliares
            cwe_data = _parse_cwe(vuln_node)
            product_ids_affected = _parse_product_statuses(vuln_node)
            revision_history_list, published_date = _parse_revision_history(
                vuln_node, _clean_xml_text_content)
            threats_data = _parse_threats(vuln_node)
            cvss_data = _parse_cvss_scores(vuln_node)
            remediations_list = _parse_remediations(vuln_node)
            acknowledgments_list = _parse_acknowledgments(
                vuln_node, _clean_xml_text_content)

            # Construir el diccionario de la vulnerabilidad si tiene un CVE ID
            if cve_id:
                parsed_vulnerabilities.append({
                    'id': cve_id,
                    'title': title,
                    'published_date': published_date,
                    'description': description,
                    'cwe_id': cwe_data['id'],
                    'cwe_description': cwe_data['description'],
                    'severity': threats_data['severity'],
                    'cvss_base_score': cvss_data['base_score'],
                    'cvss_temporal_score': cvss_data['temporal_score'],
                    'cvss_vector': cvss_data['vector'],
                    'cvss_product_id': cvss_data['product_id'],
                    'affected_product_ids': product_ids_affected if product_ids_affected else None,
                    'threat_impact': threats_data['impact_description'],
                    'threat_impact_product_ids': threats_data['impact_product_ids'] if threats_data['impact_product_ids'] else None,
                    'threat_exploit_status': threats_data['exploit_status_description'],
                    'remediations': remediations_list if remediations_list else None,
                    'acknowledgments': acknowledgments_list if acknowledgments_list else None,
                    'revision_history': revision_history_list if revision_history_list else None,
                    'notes_faq': notes_data['faq_list'] if notes_data['faq_list'] else None,
                    'notes_tags': notes_data['tags'] if notes_data['tags'] else None,
                    'notes_cna': notes_data['cna'],
                    'notes_customer_action': notes_data['customer_action'],
                    'source': 'MSRC',  # Fuente de la vulnerabilidad
                })

        print(
            f"Parseadas {len(parsed_vulnerabilities)} vulnerabilidades del documento {selected_update_doc_summary.get('ID')}.")
        return parsed_vulnerabilities  # 7. Devolver la lista de vulnerabilidades

    # Manejo de excepciones
    except requests.exceptions.RequestException as e:  # pragma: no cover
        print(f"Error de red o HTTP al obtener datos de MSRC: {e}")
        return []
    except ET.ParseError as e:  # pragma: no cover
        print(f"Error al parsear XML de MSRC: {e}")
        return []
    except json.JSONDecodeError as e:  # pragma: no cover
        print(f"Error al decodificar JSON de la lista de updates de MSRC: {e}")
        return []
    except Exception as e:  # pragma: no cover
        print(f"Error inesperado al procesar datos de MSRC: {e}")
        traceback.print_exc()  # Imprime el traceback completo para depuración
        return []


# --- BLOQUE DE EJECUCIÓN PRINCIPAL (SOLO SI EL SCRIPT SE EJECUTA DIRECTAMENTE) ---
if __name__ == '__main__':  # pragma: no cover
    print("Obteniendo Vulnerabilidades de MSRC (prueba para el mes actual por defecto)...")
    # Llama a la función principal para obtener las vulnerabilidades (mes más reciente)
    # msrc_vulnerabilities = fetch_msrc_vulnerabilities()

    # Ejemplo para obtener vulnerabilidades de Abril 2025:
    print("\nObteniendo Vulnerabilidades de MSRC para Abril 2025...")
    msrc_vulnerabilities = fetch_msrc_vulnerabilities(target_year=2025, target_month=4)

    if msrc_vulnerabilities:
        print(
            f"\nSe encontraron {len(msrc_vulnerabilities)} vulnerabilidades en el último informe de MSRC que pasaron el filtro:")
        print(
            "\n--- Todas las vulnerabilidades del MSRC que pasaron el filtro (Consola) ---")
        # Imprime cada vulnerabilidad en formato JSON indentado en la consola
        for vuln in msrc_vulnerabilities:
            print(json.dumps(vuln, indent=2, ensure_ascii=False))
        import os
        # Obtener la ruta del directorio del script actual (src)
        script_dir = os.path.dirname(os.path.abspath(__file__))

        # Construir la ruta al archivo JSON de forma relativa a la ubicación del script
        # Sube un nivel desde 'src' a 'AutoMail_Vuls/AutoMail_Vuls', luego entra a 'data'
        json_file_path = os.path.abspath(os.path.join(
            script_dir, '..', 'data', 'microsoft_processed_vulnerabilities.json'))

        try:
            # Crear el directorio 'data' si no existe (el directorio padre del archivo json_file_path)
            os.makedirs(os.path.dirname(json_file_path), exist_ok=True)

            with open(json_file_path, 'w', encoding='utf-8') as f:
                json.dump(msrc_vulnerabilities, f,
                          indent=2, ensure_ascii=False)
            print(
                f"\n--- Datos guardados exitosamente en {json_file_path} ---")
        except IOError as e:
            print(f"\nError al guardar los datos en el archivo JSON: {e}")
        except Exception as e:
            print(f"\nOcurrió un error inesperado al guardar el JSON: {e}")

    else:
        print("No se encontraron vulnerabilidades de MSRC que pasaran el filtro o hubo un error.")
