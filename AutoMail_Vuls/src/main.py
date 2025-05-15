from processor import identify_new_or_updated_vulnerabilities
from storage import (
    save_snapshot_data,
    load_comparison_historic_map,
    save_processed_vulnerabilities,
    update_current_month_historic
)
from collectors import fetch_msrc_vulnerabilities
import sys
import os

# Añadir el directorio 'src' al PYTHONPATH para asegurar que los módulos se encuentren
# Esto es útil si ejecutas main.py directamente desde la raíz del proyecto o desde src.
# Si usas un entorno virtual y has instalado tu paquete, esto podría no ser estrictamente necesario,
# pero es una buena práctica para scripts.
current_dir = os.path.dirname(os.path.abspath(__file__))
# Asumiendo que src está un nivel dentro del proyecto
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)
if current_dir not in sys.path:  # Asegurar que src también esté para imports directos si es necesario
    sys.path.insert(0, current_dir)

# Importar funciones de recolección específicas
from collectors import fetch_msrc_vulnerabilities
# Cuando añadas CISA, importarías algo como:
# from collectors import fetch_cisa_vulnerabilities


def run_detection_process_for_source(source_name, fetch_function):
    """
    Orquesta el proceso completo de detección de vulnerabilidades para una fuente de datos específica:
    1. Obtiene el snapshot de vulnerabilidades.
    2. Guarda el snapshot.
    3. Carga el histórico de comparación.
    4. Identifica vulnerabilidades nuevas o actualizadas.
    5. Guarda las vulnerabilidades para procesamiento.
    6. Actualiza el histórico del mes actual.
    """
    print(f"Iniciando proceso de detección para la fuente: {source_name.upper()}...")

    # 1. Obtener el snapshot de vulnerabilidades
    print(f"Paso 1: Obteniendo snapshot de vulnerabilidades de {source_name.upper()}...")
    snapshot_vulnerabilities = fetch_function()

    if not snapshot_vulnerabilities:
        print(f"No se obtuvieron vulnerabilidades del snapshot de {source_name.upper()} o hubo un error. Finalizando proceso para esta fuente.")
        return

    # 2. Guardar el snapshot crudo
    print(
        f"Paso 2: Guardando snapshot de {source_name.upper()} ({len(snapshot_vulnerabilities)} vulnerabilidades)...")
    save_snapshot_data(snapshot_vulnerabilities, source_prefix=source_name)

    # 3. Cargar el mapa histórico de comparación (mes actual y anterior)
    print(f"Paso 3: Cargando mapa histórico de comparación para {source_name.upper()}...")
    historic_comparison_map = load_comparison_historic_map(
        source_prefix=source_name)

    # 4. Identificar vulnerabilidades nuevas o actualizadas
    print(f"Paso 4: Identificando vulnerabilidades nuevas o actualizadas para {source_name.upper()}...")
    vulnerabilities_for_processing, vulnerabilities_for_historic_update = \
        identify_new_or_updated_vulnerabilities(
            snapshot_vulnerabilities, historic_comparison_map)

    if not vulnerabilities_for_processing:
        print(
            f"No se identificaron vulnerabilidades nuevas o actualizadas en esta ejecución para {source_name.upper()}.")
    else:
        # 5. Guardar las vulnerabilidades nuevas/actualizadas para procesamiento posterior
        output_filename = f"{source_name}_vulnerabilities_for_processing.json"
        print(
            f"Paso 5: Guardando {len(vulnerabilities_for_processing)} vulnerabilidades de {source_name.upper()} para procesamiento en {output_filename}...")
        save_processed_vulnerabilities(vulnerabilities_for_processing,
                                       filename=output_filename)

        # 6. Actualizar el archivo histórico del mes actual
        print(
            f"Paso 6: Actualizando histórico del mes actual de {source_name.upper()} con {len(vulnerabilities_for_historic_update)} entradas...")
        update_current_month_historic(
            vulnerabilities_for_historic_update, source_prefix=source_name)

    print(f"Proceso de detección de vulnerabilidades para {source_name.upper()} finalizado.")


if __name__ == "__main__":
    # Definir las fuentes de datos a procesar
    # Cada entrada es una tupla: (nombre_prefijo_fichero, funcion_de_recoleccion)
    sources_to_process = [
        ("msrc", fetch_msrc_vulnerabilities),
        # Ejemplo para cuando añadas CISA:
        # ("cisa", fetch_cisa_vulnerabilities),
    ]

    for source_name, fetch_func in sources_to_process:
        run_detection_process_for_source(source_name, fetch_func)
        print("-" * 50)  # Separador entre fuentes

    print("Todos los procesos de detección de vulnerabilidades han finalizado.")
