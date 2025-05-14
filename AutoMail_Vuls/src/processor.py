import json  # Solo para la comparación robusta de revision_history si es necesario


def identify_new_or_updated_vulnerabilities(snapshot_vulnerabilities, historic_map):
    """
    Compara las vulnerabilidades del snapshot actual con el mapa histórico consolidado
    para identificar cuáles son nuevas o han sido actualizadas.

    Args:
        snapshot_vulnerabilities (list): Lista de objetos de vulnerabilidad del snapshot actual.
        Cada objeto debe tener al menos "id" y "revision_history".
        historic_map (dict): Mapa consolidado del histórico (id -> revision_history).

    Returns:
        list: Una lista de objetos de vulnerabilidad (del snapshot) que son nuevas o actualizadas.
        list: Una lista de diccionarios {"id": ..., "revision_history": ...} para las
        vulnerabilidades nuevas o actualizadas, para actualizar el histórico.
    """
    new_or_updated_for_processing = []
    new_or_updated_for_historic_update = []

    if not isinstance(snapshot_vulnerabilities, list):
        print(
            "Advertencia: snapshot_vulnerabilities no es una lista, no se puede procesar.")
        return [], []

    if not isinstance(historic_map, dict):
        print("Advertencia: historic_map no es un diccionario, no se puede procesar.")
        return [], []

    for current_vuln in snapshot_vulnerabilities:
        if not isinstance(current_vuln, dict):
            print(
                f"Advertencia: Elemento en snapshot no es un diccionario: {current_vuln}")
            continue

        vuln_id = current_vuln.get("id")
        current_revision_history = current_vuln.get("revision_history")

        if not vuln_id:
            print(
                f"Advertencia: Vulnerabilidad en snapshot sin ID: {current_vuln}")
            continue

        is_new = False
        is_updated = False

        if vuln_id not in historic_map:
            is_new = True
        else:
            stored_revision_history = historic_map.get(vuln_id)

            if current_revision_history != stored_revision_history:
                is_updated = True

        if is_new or is_updated:
            new_or_updated_for_processing.append(current_vuln)
            if current_revision_history is not None:
                new_or_updated_for_historic_update.append({
                    "id": vuln_id,
                    "revision_history": current_revision_history
                })
            elif is_new:
                new_or_updated_for_historic_update.append({
                    "id": vuln_id,
                    "revision_history": []
                })
    print(
        f"Identificadas {len(new_or_updated_for_processing)} vulnerabilidades nuevas o actualizadas para procesar.")
    return new_or_updated_for_processing, new_or_updated_for_historic_update
