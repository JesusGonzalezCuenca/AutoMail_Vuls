# AutoMail_Vuls

## Descripción del Proyecto

Herramienta automatizada desarrollada en Python diseñada para monitorear, procesar y notificar sobre nuevas y actualizadas vulnerabilidades de seguridad. El sistema recopila información de dos fuentes principales:

1.  **Microsoft Security Response Center (MSRC)**: A través de su API de CVRF (Common Vulnerability Reporting Framework) (`https://api.msrc.microsoft.com/cvrf/v3.0/swagger/v3/swagger.json`).
2.  **CISA Known Exploited Vulnerabilities Catalog**: Mediante el feed JSON proporcionado por la Cybersecurity and Infrastructure Security Agency (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`).

El flujo de trabajo principal es el siguiente:
1.  **Recopilación de Datos**: El sistema obtiene la información más reciente de las fuentes (ej. el último documento CVRF mensual de MSRC). Esta información completa se imprime en consola y se guarda en un archivo JSON local (ej. `data/msrc_snapshot.json`) que se sobrescribe en cada ejecución.
2.  **Detección de Novedades y Actualizaciones**:
    -   Se mantiene un **histórico persistente** de vulnerabilidades ya procesadas, almacenado en archivos JSON mensuales (ej. `data/historico/msrc_YYYY-MM.json`). Cada entrada en estos archivos guarda el ID de la vulnerabilidad y su `revision_history` completo.
    -   La información del snapshot actual se compara con el archivo histórico del **mes actual**.
    -   Una vulnerabilidad se considera "para procesar" si es genuinamente nueva (su ID no está en el histórico del mes anterior) o si su `revision_history` ha cambiado respecto a la versión registrada en el histórico del mes actual.
3.  **Procesamiento y Notificación**:
    -   Las vulnerabilidades identificadas como nuevas o actualizadas se guardan en un archivo JSON temporal (ej. `data/vulnerabilities_for_processing.json`), que también se sobrescribe en cada ejecución.
    -   Este conjunto de vulnerabilidades se enriquece convirtiéndolo a lenguaje natural y aplicando una plantilla de email directamente mediante la API de OpenAI (ChatGPT).
    -   Finalmente, el informe enriquecido se envía por correo electrónico a los destinatarios configurados.
4.  **Actualización del Histórico**: El `id` y `revision_history` de las vulnerabilidades procesadas (nuevas o actualizadas en esta ejecución) se registran en el archivo histórico del mes **actual** (`data/historico/msrc_YYYY-MM.json`). Este archivo se actualiza o crea si no existe, acumulando las vulnerabilidades procesadas durante el mes corriente.

Todo el proceso está diseñado para ejecutarse periódicamente, asegurando una vigilancia continua y oportuna.

## Etapas de Desarrollo y Funcionalidades

El desarrollo del proyecto se dividirá en las siguientes etapas:

### Etapa 1: Core de Scraping y Detección de Novedades
-   DONE: Módulo de Scraping de Microsoft MSRC:
    -   Implementar la lógica para realizar peticiones a la API de MSRC.
    -   Parsear la respuesta XML/JSON.
    -   Extraer la información relevante de las vulnerabilidades, incluyendo el `id` y el `revision_history` completo.
    -   Guardar el snapshot completo de la ejecución en un archivo JSON local (ej. `data/msrc_snapshot.json`), sobrescribiéndolo.
-   FUTURE: Módulo de Scraping de CISA KEV:
    -   Implementar la lógica para realizar peticiones a la API de CISA.
    -   Parsear la respuesta JSON.
    -   Extraer la información relevante.
    -   (Definir estrategia de snapshot e histórico similar a MSRC si aplica).
-   TODO: Sistema de Detección de Novedades y Actualizaciones:
    -   Implementar la carga del archivo histórico del mes actual (ej. `data/historico/msrc_YYYY-MM.json`).
    -   Comparar las vulnerabilidades del snapshot actual con el histórico del mes actual:
        -   Identificar vulnerabilidades genuinamente nuevas (ID no en el histórico del mes anterior).
        -   Identificar vulnerabilidades actualizadas (ID en el histórico del mes anterior, pero `revision_history` diferente).
    -   Guardar las vulnerabilidades nuevas o actualizadas (objetos completos del snapshot) en un archivo JSON temporal para procesamiento (ej. `data/vulnerabilities_for_processing.json`).
    -   Actualizar/guardar el `id` y `revision_history` de las vulnerabilidades procesadas en el archivo histórico del mes actual (`data/historico/msrc_YYYY-MM.json`).
-   TODO: Orquestador y Programador de Tareas:
    -   Integrar los módulos anteriores en un script principal.
    -   Utilizar una biblioteca (e.g., `schedule`, `APScheduler`) para ejecutar el proceso de scraping y detección periódicamente (configurable, por ejemplo, "cada X horas").

### Etapa 2: Enriquecimiento con IA y Notificaciones 
-   TODO: Integración con OpenAI (ChatGPT):
    -   Configurar el acceso a la API de OpenAI.
    -   Desarrollar la lógica para enviar el contenido de `data/vulnerabilities_for_processing.json` a ChatGPT, instruyéndole para enriquecer la información y aplicar una plantilla de email.
    -   Procesar la respuesta de la API para obtener el informe final formateado para email.
-   TODO: Módulo de Notificación por Correo Electrónico:
    -   Implementar la funcionalidad para construir y enviar correos electrónicos.
    -   Utilizar el informe enriquecido por IA como cuerpo del mensaje.
    -   Configurar destinatarios y parámetros del servidor SMTP (considerar el manejo seguro de credenciales).

### Etapa 3: Mejoras y Mantenimiento
-   TODO: Configuración Avanzada:
    -   Permitir la configuración de parámetros (URLs de API, frecuencia de ejecución, credenciales de API, configuración de correo, rutas de archivos de datos) a través de un archivo de configuración o variables de entorno.
-   TODO: Logging y Manejo de Errores:
    -   Implementar un sistema de logging robusto para rastrear la ejecución y diagnosticar problemas.
    -   Mejorar el manejo de errores en todas las etapas (fallos de red, errores de API, etc.).
-   TODO: Pruebas Unitarias:
    -   Desarrollar pruebas unitarias para los módulos clave.
-   TODO: Documentación:
    -   Mejorar la documentación del código y del proyecto.

## Tecnologías Propuestas
-   **Lenguaje:** Python 3.x
-   **Bibliotecas Principales:**
    -   `requests`: Para realizar peticiones HTTP.
    -   `schedule` o `APScheduler`: Para la programación de tareas.
    -   `openai`: Para la interacción con la API de ChatGPT.
    -   `smtplib`, `email` (Módulos estándar de Python): Para el envío de correos.
    -   `sqlite3` (Módulo estándar de Python, opcional): Para almacenamiento persistente de vulnerabilidades vistas.
    -   `Jinja2` (Opcional): Para plantillas de texto más complejas.