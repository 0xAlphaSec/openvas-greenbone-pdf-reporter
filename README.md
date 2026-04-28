# openvas_report_v2
 
Genera un PDF completo y formateado a partir de un reporte XML exportado desde **OpenVAS / Greenbone Security Manager (GSM)**.
 
A diferencia de la v1, esta versión no omite ni trunca ningún campo del XML original — el objetivo es producir un documento equivalente al reporte nativo de OpenVAS pero con un formato más limpio y legible.
 
---
 
## Requisitos
 
- Python 3.8 o superior
- [reportlab](https://pypi.org/project/reportlab/)
```bash
pip install reportlab
```
 
---
 
## Uso
 
```bash
# Uso básico — genera reporte_openvas_v2_<timestamp>.pdf
python openvas_report_v2.py reporte.xml
 
# Especificar nombre de salida
python openvas_report_v2.py reporte.xml -o informe_cliente.pdf
 
# Si -o es un directorio existente, el PDF se crea dentro con nombre automático
python openvas_report_v2.py reporte.xml -o /informes/
```
 
---
 
## Estructura del PDF generado
 
### 1. Cabecera del escaneo
Tabla con los metadatos globales extraídos del XML:
 
| Campo | Descripción |
|---|---|
| Input file | Nombre del archivo XML de origen |
| Task name / Task ID | Nombre e identificador de la tarea en OpenVAS |
| Scan start / Scan end | Timestamps de inicio y fin (con duración total) |
| Timezone | Zona horaria del escaneo |
| Hosts scanned | Número total de hosts alcanzados |
| Unique vulns (NVTs) | Vulnerabilidades únicas encontradas |
| Applications found | Aplicaciones detectadas |
| SSL/TLS certs found | Certificados SSL/TLS identificados |
| Results in report | Resultados incluidos en este PDF |
 
### 2. Distribución por severidad
Tabla con el recuento de resultados por nivel CVSS:
 
| Nivel | Rango CVSS |
|---|---|
| CRITICAL | 9.0 – 10.0 |
| HIGH | 7.0 – 8.9 |
| MEDIUM | 4.0 – 6.9 |
| LOW | 0.1 – 3.9 |
| INFO | 0.0 |
 
### 3. Hosts escaneados
Tabla resumen con todos los hosts del escaneo, incluyendo los que no tuvieron resultados:
 
| Columna | Descripción |
|---|---|
| IP | Dirección IP del host |
| Hostname | FQDN resuelto (si disponible) |
| OS | Sistema operativo detectado |
| Open ports | Puertos TCP abiertos |
| Med / Low / Tot | Conteo de resultados por severidad |
 
### 4. Detalle de vulnerabilidades
Agrupado por host. Para cada host se muestra primero un bloque informativo con OS, puertos, servicios, timestamps del escaneo individual y CVEs cerrados. A continuación, cada resultado incluye:
 
| Campo | Descripción |
|---|---|
| Port | Puerto y protocolo afectado |
| Threat level | Nivel textual (Medium, Low…) |
| CVSS score | Puntuación numérica (y original si difiere) |
| CVSS base (NVT) | Score base definido en el NVT |
| NVT family | Familia del plugin (ej: SSL and TLS, Windows) |
| NVT OID | Identificador único del plugin en OpenVAS |
| Solution type | Tipo de solución (Mitigation, VendorFix…) |
| QoD | Quality of Detection: valor % y tipo de detección |
| Summary | Resumen del problema |
| Insight | Detalles técnicos adicionales |
| Impact | Impacto potencial de la vulnerabilidad |
| Affected systems | Sistemas y versiones afectados |
| Detection method | Cómo fue detectada la vulnerabilidad |
| Raw output | Output literal del NVT sobre este host |
| Recommended solution | Pasos recomendados para remediar |
| Detection details | Producto y localización detectados activamente (si aplica) |
| References | CVEs, URLs y referencias CERT agrupados por tipo |
 
---
 
## Notas sobre las referencias
 
Cada resultado puede incluir tres tipos de referencias:
 
- **CVEs** — identificadores del National Vulnerability Database. Son los más relevantes para remediation.
- **URLs** — enlaces a advisories, documentación técnica y guías de configuración.
- **CERT-Bund / DFN-CERT** — advisories del BSI (gobierno federal alemán) y la red universitaria alemana DFN. Se muestran los 10 primeros de cada tipo con el recuento restante indicado. Son referencias válidas pero de ámbito principalmente alemán.
---
 
## Compatibilidad
 
El script es compatible con el formato XML estándar exportado desde OpenVAS / Greenbone. No requiere ninguna configuración adicional en la instancia de OpenVAS ni transformaciones XSLT personalizadas — funciona directamente sobre la exportación por defecto.
 
Probado con:
- OpenVAS / Greenbone Community Edition
- Formato de exportación XML estándar (sin filtros de severidad aplicados en la exportación)
---
 
## Diferencias respecto a v1
 
| Aspecto | v1 | v2 |
|---|---|---|
| Filtro de severidad | `--min-severity` configurable | Sin filtro — se incluye todo |
| Campos del NVT | Solo `summary` y `solution` | Todos: `insight`, `impact`, `affected`, `vuldetect`, `solution_type` |
| CVEs y referencias | No incluidos | Incluidos y agrupados por tipo |
| Descripción (raw output) | Truncada a 600 caracteres | Completa |
| Solución | Truncada a 800 caracteres | Completa |
| QoD | No incluido | Valor y tipo |
| Metadatos del host | Solo IP y hostname | OS, puertos, servicios, timestamps, closed CVEs |
| Metadatos globales | Fecha inicio y archivo | Task, duración, counts de apps/certs/hosts |
| Detection activa | No incluida | Incluida cuando existe |
 
---

## Author

**Jesús Fernández** — [jfg.sec](https://www.instagram.com/jfg.sec) — [LinkedIn](https://www.linkedin.com/in/jesus-fernandez-gervasi)
