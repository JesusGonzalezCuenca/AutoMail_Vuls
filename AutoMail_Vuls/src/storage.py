import json
import os
from datetime import datetime
# Necesitarás instalar python-dateutil: pip install python-dateutil
from dateutil.relativedelta import relativedelta

# Constantes para las rutas de los datos
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
HISTORIC_DIR = os.path.join(DATA_DIR, "historico")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(HISTORIC_DIR, exist_ok=True)


def _get_historic_filepath(year, month, source_prefix="msrc"):
    """
    Genera la ruta completa para un archivo histórico de un año y mes específicos.
    """
    year_month_str = f"{year:04d}-{month:02d}"
    filename = f"{source_prefix}_{year_month_str}.json"
    return os.path.join(HISTORIC_DIR, filename)


def _load_single_historic_file(filepath):
    """
    Carga un único archivo histórico y lo transforma en un mapa id -> revision_history.
    Devuelve un diccionario vacío si el archivo no existe o hay un error.
    """
    historic_data_map = {}
    if not os.path.exists(filepath):
        # No es un error si el archivo no existe (ej. mes anterior al inicio del uso del script)
        return historic_data_map

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            historic_list = json.load(f)
            for item in historic_list:
                if isinstance(item, dict) and "id" in item and "revision_history" in item:
                    historic_data_map[item["id"]] = item["revision_history"]
                else: 
                    print(
                        f"Advertencia: Elemento malformado encontrado en {filepath}: {item}")
    except json.JSONDecodeError:  
        print(
            f"Error: No se pudo decodificar JSON del archivo histórico {filepath}. Se tratará como vacío.")
    except Exception as e:  
        print(
            f"Error inesperado al cargar el archivo histórico {filepath}: {e}")

    return historic_data_map


def load_comparison_historic_map(source_prefix="msrc"):
    """
    Carga los archivos históricos del mes actual y del mes inmediatamente anterior,
    y los consolida en un único mapa de comparación (id -> revision_history).

    La información del mes actual tiene precedencia sobre la del mes anterior
    en caso de IDs duplicados.

    Devuelve:
        dict: Un diccionario consolidado para la comparación.
    """
    now = datetime.now()
    current_month_filepath = _get_historic_filepath(
        now.year, now.month, source_prefix)

    previous_month_date = now - relativedelta(months=1)
    previous_month_filepath = _get_historic_filepath(
        previous_month_date.year, previous_month_date.month, source_prefix)

    # Cargar primero el del mes anterior
    comparison_map = _load_single_historic_file(previous_month_filepath)

    # Cargar el del mes actual y fusionarlo, dando precedencia al actual
    current_month_data = _load_single_historic_file(current_month_filepath)
    # .update() sobrescribe claves existentes
    comparison_map.update(current_month_data)

    if not comparison_map:
        print("No se encontraron datos históricos para el mes actual ni para el anterior.")
    else:
        print(
            f"Mapa histórico de comparación cargado con {len(comparison_map)} entradas (combinando mes actual y anterior).")

    return comparison_map


def update_current_month_historic(processed_vulnerabilities_info, source_prefix="msrc"):
    """
    Actualiza el archivo histórico del mes actual con la información de las
    vulnerabilidades procesadas (nuevas o actualizadas) en esta ejecución.
    """
    now = datetime.now()
    historic_filepath = _get_historic_filepath(
        now.year, now.month, source_prefix)

    # Cargar los datos existentes del histórico del mes actual (si los hay)
    # Esto es importante para no perder lo que ya se había registrado en ejecuciones anteriores del mismo mes.
    current_month_data_map = _load_single_historic_file(
        historic_filepath)  # Usa la función auxiliar

    for vuln_info in processed_vulnerabilities_info:
        if isinstance(vuln_info, dict) and "id" in vuln_info and "revision_history" in vuln_info:
            current_month_data_map[vuln_info["id"]
                                   ] = vuln_info["revision_history"]

    updated_historic_list = []
    for cve_id, rev_history in current_month_data_map.items():
        updated_historic_list.append(
            {"id": cve_id, "revision_history": rev_history})

    try:
        with open(historic_filepath, 'w', encoding='utf-8') as f:
            json.dump(updated_historic_list, f, indent=2, ensure_ascii=False)
        print(
            f"Histórico del mes actual para {source_prefix} actualizado en: {historic_filepath}")
    except IOError as e: 
        print(
            f"Error al actualizar el histórico del mes actual para {source_prefix} en {historic_filepath}: {e}")
    except Exception as e:  
        print(
            f"Error inesperado al actualizar el histórico del mes actual para {source_prefix}: {e}")


def save_processed_vulnerabilities(vulnerabilities, filename="vulnerabilities_for_processing.json"):
    """
    Guarda la lista de vulnerabilidades (objetos completos) que necesitan ser procesadas
    en un archivo JSON dentro de la carpeta 'data'.
    Este archivo se sobrescribe en cada ejecución.
    """
    filepath = os.path.join(DATA_DIR, filename)
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(vulnerabilities, f, indent=2, ensure_ascii=False)
        print(
            f"Datos de vulnerabilidades para procesar guardados en: {filepath}")
    except IOError as e:  
        print(
            f"Error al guardar las vulnerabilidades para procesar en {filepath}: {e}")
    except Exception as e:  
        print(
            f"Error inesperado al guardar las vulnerabilidades para procesar: {e}")


def save_snapshot_data(vulnerabilities, source_prefix="msrc", filename_suffix="_snapshot.json"):
    """
    Guarda el snapshot completo de las vulnerabilidades obtenidas de una fuente.
    Este archivo se sobrescribe en cada ejecución.
    """
    filename = f"{source_prefix}{filename_suffix}"
    filepath = os.path.join(DATA_DIR, filename)
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(vulnerabilities, f, indent=2, ensure_ascii=False)
        print(f"Snapshot de {source_prefix} guardado en: {filepath}")
    except IOError as e: 
        print(
            f"Error al guardar el snapshot de {source_prefix} en {filepath}: {e}")
    except Exception as e:  
        print(
            f"Error inesperado al guardar el snapshot de {source_prefix}: {e}")
