import requests
import json
from datetime import datetime
import xml.etree.ElementTree as ET
import re
import html
import traceback

MSRC_API_BASE_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/"
MSRC_UPDATES_URL = f"{MSRC_API_BASE_URL}updates"

XML_NAMESPACES = {
    'vuln': 'http://www.icasi.org/CVRF/schema/vuln/1.1',
    'cvrf': 'http://www.icasi.org/CVRF/schema/cvrf/1.1'
}


def get_xml_text(element, path, default=None):
    """Función auxiliar para obtener texto de un elemento XML, manejando namespaces."""
    if element is None:
        return default
    try:
        node = element.find(path, XML_NAMESPACES)
        if node is not None and node.text is not None:
            return node.text.strip()
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

        root = ET.fromstring(response_cvrf.content)

        parsed_vulnerabilities = []
        for vuln_node in root.findall('vuln:Vulnerability', XML_NAMESPACES):
            cve_id = get_xml_text(vuln_node, 'vuln:CVE')

            title_node = vuln_node.find('vuln:Title', XML_NAMESPACES)
            title = None
            if title_node is not None and title_node.text and title_node.text.strip():
                title = title_node.text.strip()
            else:
                continue

            description = None
            description_node_found_but_empty = False
            notes_faq_list = []
            notes_tags = []
            notes_cna = None
            notes_customer_action = None

            notes_node = vuln_node.find('vuln:Notes', XML_NAMESPACES)
            if notes_node is not None:
                description_filter_info_set = False
                for note in notes_node.findall('vuln:Note', XML_NAMESPACES):
                    note_title_attr = note.get('Title')
                    note_type_attr = note.get('Type')

                    raw_text_content = "".join(note.itertext()).strip()
                    clean_note_text = None
                    if raw_text_content:
                        unescaped_text = html.unescape(raw_text_content)
                        plain_text = re.sub(r'<[^>]+>', '', unescaped_text)
                        temp_clean_text = re.sub(
                            r'\s+', ' ', plain_text).strip()
                        if temp_clean_text and temp_clean_text.lower() != 'none':
                            clean_note_text = temp_clean_text

                    if note_title_attr == 'Description' and note_type_attr == 'Description':
                        if not description_filter_info_set:
                            if clean_note_text:
                                description = clean_note_text
                            elif not raw_text_content:
                                description_node_found_but_empty = True
                            description_filter_info_set = True

                    elif note_title_attr == 'FAQ' and clean_note_text:
                        notes_faq_list.append(clean_note_text)
                    elif note_title_attr == 'Tag' and clean_note_text:
                        notes_tags.append(clean_note_text)
                    elif note_title_attr == 'Microsoft' and note_type_attr == 'CNA' and clean_note_text:
                        notes_cna = clean_note_text
                    elif note_title_attr == 'Customer Action Required' and clean_note_text:
                        notes_customer_action = clean_note_text

            if description is None and not description_node_found_but_empty:
                continue

            cwe_id_val = None
            cwe_description_val = None
            cwe_node = vuln_node.find('vuln:CWE', XML_NAMESPACES)
            if cwe_node is not None:
                cwe_id_val = cwe_node.get('ID')
                if cwe_node.text and cwe_node.text.strip():
                    cwe_description_val = cwe_node.text.strip()

            product_ids_affected = []
            product_statuses_node = vuln_node.find(
                'vuln:ProductStatuses', XML_NAMESPACES)
            if product_statuses_node is not None:
                for status_node in product_statuses_node.findall('vuln:Status', XML_NAMESPACES):
                    for prod_id_node in status_node.findall('vuln:ProductID', XML_NAMESPACES):
                        if prod_id_node.text and prod_id_node.text.strip():
                            product_ids_affected.append(
                                prod_id_node.text.strip())

            latest_published_date_obj = None
            revision_history_list = []
            revision_history_node = vuln_node.find(
                'vuln:RevisionHistory', XML_NAMESPACES)
            if revision_history_node is not None:
                all_revision_dates_objs = []
                for revision_node in revision_history_node.findall('vuln:Revision', XML_NAMESPACES):
                    rev_number = get_xml_text(revision_node, 'cvrf:Number')
                    rev_date_str = get_xml_text(revision_node, 'cvrf:Date')
                    rev_desc_node = revision_node.find(
                        'cvrf:Description', XML_NAMESPACES)
                    rev_description_text = None
                    if rev_desc_node is not None:
                        rev_description_text = "".join(
                            rev_desc_node.itertext()).strip()
                        rev_description_text = re.sub(
                            r'<[^>]+>', '', html.unescape(rev_description_text)).strip()
                        rev_description_text = re.sub(
                            r'\s+', ' ', rev_description_text).strip()

                    revision_history_list.append({
                        'number': rev_number,
                        'date': rev_date_str,
                        'description': rev_description_text if rev_description_text else None
                    })
                    if rev_date_str:
                        try:
                            dt_obj = datetime.strptime(
                                rev_date_str, '%Y-%m-%dT%H:%M:%SZ')
                        except ValueError:
                            try:
                                dt_obj = datetime.strptime(
                                    rev_date_str, '%Y-%m-%dT%H:%M:%S')
                            except ValueError:
                                dt_obj = None
                        if dt_obj:
                            all_revision_dates_objs.append(dt_obj)

                if all_revision_dates_objs:
                    latest_published_date_obj = max(all_revision_dates_objs)

            published_date = latest_published_date_obj.strftime(
                '%Y-%m-%dT%H:%M:%S') if latest_published_date_obj else None

            severity = None
            threat_impact_description = None
            threat_impact_product_ids = []
            threat_exploit_status_description = None

            threats_node = vuln_node.find('vuln:Threats', XML_NAMESPACES)
            if threats_node is not None:
                for threat in threats_node.findall('vuln:Threat', XML_NAMESPACES):
                    threat_type = threat.get('Type')
                    desc_text = get_xml_text(threat, 'vuln:Description')

                    if threat_type == 'Severity':
                        if desc_text:
                            severity = desc_text
                        elif threat.find('vuln:Description', XML_NAMESPACES) is not None:
                            severity = "N/A"
                    elif threat_type == 'Impact':
                        threat_impact_description = desc_text
                        for prod_id_node in threat.findall('vuln:ProductID', XML_NAMESPACES):
                            if prod_id_node.text and prod_id_node.text.strip():
                                threat_impact_product_ids.append(
                                    prod_id_node.text.strip())
                    elif threat_type == 'Exploit Status':
                        threat_exploit_status_description = desc_text

            cvss_base_score = None
            cvss_vector = None
            cvss_temporal_score = None
            cvss_product_id_in_scoreset = None

            cvss_score_sets_node = vuln_node.find(
                'vuln:CVSSScoreSets', XML_NAMESPACES)
            if cvss_score_sets_node is not None:
                score_set_node = cvss_score_sets_node.find(
                    'vuln:ScoreSet', XML_NAMESPACES)
                if score_set_node is not None:
                    cvss_base_score = get_xml_text(
                        score_set_node, 'vuln:BaseScore')
                    cvss_vector = get_xml_text(score_set_node, 'vuln:Vector')
                    cvss_temporal_score = get_xml_text(
                        score_set_node, 'vuln:TemporalScore')
                    cvss_product_id_in_scoreset = get_xml_text(
                        score_set_node, 'vuln:ProductID')

            remediations_list = []
            remediations_node = vuln_node.find(
                'vuln:Remediations', XML_NAMESPACES)
            if remediations_node is not None:
                for rem_node in remediations_node.findall('vuln:Remediation', XML_NAMESPACES):
                    rem_desc = get_xml_text(rem_node, 'vuln:Description')
                    if rem_desc:
                        remediations_list.append(rem_desc)
                    elif rem_node.text and rem_node.text.strip():
                        remediations_list.append(rem_node.text.strip())
                if not remediations_list and remediations_node.text and remediations_node.text.strip():
                    remediations_list.append(remediations_node.text.strip())

            acknowledgments_list = []
            acknowledgments_node = vuln_node.find(
                'vuln:Acknowledgments', XML_NAMESPACES)
            if acknowledgments_node is not None:
                for ack_node in acknowledgments_node.findall('vuln:Acknowledgment', XML_NAMESPACES):
                    name_node = ack_node.find('vuln:Name', XML_NAMESPACES)
                    ack_name = None
                    if name_node is not None:
                        ack_name_raw = "".join(name_node.itertext()).strip()
                        ack_name = re.sub(
                            r'<[^>]+>', '', html.unescape(ack_name_raw)).strip()
                        ack_name = re.sub(r'\s+', ' ', ack_name).strip()

                    ack_url = get_xml_text(ack_node, 'vuln:URL')
                    if ack_name or ack_url:
                        acknowledgments_list.append({
                            'name': ack_name if ack_name else None,
                            'url': ack_url if ack_url else None
                        })

            if cve_id:
                parsed_vulnerabilities.append({
                    'id': cve_id,
                    'title': title,
                    'published_date': published_date,
                    'description': description,
                    'cwe_id': cwe_id_val,
                    'cwe_description': cwe_description_val,
                    'severity': severity,
                    'cvss_base_score': cvss_base_score,
                    'cvss_temporal_score': cvss_temporal_score,
                    'cvss_vector': cvss_vector,
                    'cvss_product_id': cvss_product_id_in_scoreset,
                    'affected_product_ids': product_ids_affected if product_ids_affected else None,
                    'threat_impact': threat_impact_description,
                    'threat_impact_product_ids': threat_impact_product_ids if threat_impact_product_ids else None,
                    'threat_exploit_status': threat_exploit_status_description,
                    'remediations': remediations_list if remediations_list else None,
                    'acknowledgments': acknowledgments_list if acknowledgments_list else None,
                    'revision_history': revision_history_list if revision_history_list else None,
                    'notes_faq': notes_faq_list if notes_faq_list else None,
                    'notes_tags': notes_tags if notes_tags else None,
                    'notes_cna': notes_cna,
                    'notes_customer_action': notes_customer_action,
                    'source': 'MSRC',
                })
                # TODO: Checkear correspondencia de todos los cmapos
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
        traceback.print_exc()
        return []


if __name__ == '__main__':
    print("Obteniendo Vulnerabilidades de MSRC...")
    msrc_vulnerabilities = fetch_msrc_vulnerabilities()
    if msrc_vulnerabilities:
        print(
            f"\nSe encontraron {len(msrc_vulnerabilities)} vulnerabilidades en el último informe de MSRC que pasaron el filtro:")

        print("\n--- Todas las vulnerabilidades del MSRC que pasaron el filtro ---")
        for vuln in msrc_vulnerabilities:
            print(json.dumps(vuln, indent=2, ensure_ascii=False))

    else:
        print("No se encontraron vulnerabilidades de MSRC que pasaran el filtro o hubo un error.")
