# AutoMail_Vuls

## Descripción del Proyecto

Herramienta automatizada desarrollada en Python diseñada para monitorear, procesar y notificar sobre nuevas vulnerabilidades de seguridad. El sistema recopila información de dos fuentes principales:

1.  **Microsoft Security Response Center (MSRC)**: A través de su API de CVRF (Common Vulnerability Reporting Framework) (`https://api.msrc.microsoft.com/cvrf/v3.0/swagger/v3/swagger.json`).
2.  **CISA Known Exploited Vulnerabilities Catalog**: Mediante el feed JSON proporcionado por la Cybersecurity and Infrastructure Security Agency (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`).

El objetivo principal es detectar nuevas vulnerabilidades tan pronto como se publiquen. Para cada nueva vulnerabilidad identificada, el sistema:
1.  Genera un informe inicial en formato de texto utilizando una plantilla predefinida.
2.  Enriquece este informe utilizando la API de OpenAI (ChatGPT) para proporcionar un contexto y análisis más detallado.
3.  Envía automáticamente el informe enriquecido por correo electrónico a los destinatarios configurados.

Todo el proceso está diseñado para ejecutarse periódicamente, asegurando una vigilancia continua y oportuna.

## Etapas de Desarrollo y Funcionalidades

El desarrollo del proyecto se dividirá en las siguientes etapas:

### Etapa 1: Core de Scraping y Detección de Novedades
*   **[x] Módulo de Scraping de Microsoft MSRC:**
    *   Implementar la lógica para realizar peticiones a la API de MSRC.
    *   Parsear la respuesta JSON.
    *   Extraer la información relevante de las vulnerabilidades.
*   **[ ] Módulo de Scraping de CISA KEV:**
    *   Implementar la lógica para realizar peticiones a la API de CISA.
    *   Parsear la respuesta JSON.
    *   Extraer la información relevante de las vulnerabilidades.
*   **[ ] Sistema de Detección de Novedades:**
    *   Diseñar e implementar un mecanismo para almacenar identificadores de vulnerabilidades ya procesadas (e.g., archivo local, base de datos SQLite).
    *   Comparar las vulnerabilidades obtenidas con las ya almacenadas para identificar las nuevas.
*   **[ ] Generación de Informes Iniciales:**
    *   Definir una plantilla base para los informes de vulnerabilidad.
    *   Implementar la funcionalidad para generar un archivo de texto por cada nueva vulnerabilidad, rellenando la plantilla con la información recopilada.
*   **[ ] Orquestador y Programador de Tareas:**
    *   Integrar los módulos anteriores en un script principal.
    *   Utilizar una biblioteca (e.g., `schedule`, `APScheduler`) para ejecutar el proceso de scraping y detección periódicamente (configurable, por ejemplo, "cada X horas").

### Etapa 2: Enriquecimiento con IA y Notificaciones 
*   **[ ] Integración con OpenAI (ChatGPT):**
    *   Configurar el acceso a la API de OpenAI.
    *   Desarrollar la lógica para enviar el contenido del informe inicial a ChatGPT para su enriquecimiento.
    *   Procesar la respuesta de la API y actualizar el informe.
*   **[ ] Módulo de Notificación por Correo Electrónico:**
    *   Implementar la funcionalidad para construir y enviar correos electrónicos.
    *   Utilizar el informe (inicial o enriquecido) como cuerpo del mensaje.
    *   Configurar destinatarios y parámetros del servidor SMTP (considerar el manejo seguro de credenciales).

### Etapa 3: Mejoras y Mantenimiento
*   **[ ] Configuración Avanzada:**
    *   Permitir la configuración de parámetros (URLs de API, frecuencia de ejecución, credenciales de API, configuración de correo) a través de un archivo de configuración o variables de entorno.
*   **[ ] Logging y Manejo de Errores:**
    *   Implementar un sistema de logging robusto para rastrear la ejecución y diagnosticar problemas.
    *   Mejorar el manejo de errores en todas las etapas (fallos de red, errores de API, etc.).
*   **[ ] Pruebas Unitarias:**
    *   Desarrollar pruebas unitarias para los módulos clave.
*   **[ ] Documentación:**
    *   Mejorar la documentación del código y del proyecto.

## Tecnologías Propuestas
*   **Lenguaje:** Python 3.x
*   **Bibliotecas Principales:**
    *   `requests`: Para realizar peticiones HTTP.
    *   `schedule` o `APScheduler`: Para la programación de tareas.
    *   `openai` (Opcional): Para la interacción con la API de ChatGPT.
    *   `smtplib`, `email` (Módulos estándar de Python): Para el envío de correos.
    *   `sqlite3` (Módulo estándar de Python, opcional): Para almacenamiento persistente de vulnerabilidades vistas.
    *   `Jinja2` (Opcional): Para plantillas de texto más complejas.