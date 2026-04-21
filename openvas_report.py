"""
openvas_report.py
=================
Parsea un reporte XML de OpenVAS/Greenbone y genera un PDF limpio
con solo la información esencial de cada vulnerabilidad.

Uso:
    python openvas_report.py reporte.xml
    python openvas_report.py reporte.xml --min-severity 5.0
    python openvas_report.py reporte.xml --output mi_reporte.pdf

Autor: Jesús Fernández
"""
import xml.etree.ElementTree as ET  # Librería estándar de Python para XML
import re # Limpia HTML dentro del texto
import sys
import argparse
from datetime import datetime

# Reportlab: genera el PDF
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)

# =================
# 1. Parseo del XML
# =================


def limpiar_html(texto):
    """
    OpenVAS mete etiquetas HTML dentro de los campos de texto
    (ej: <br/>, <b>, <p>...)
    Esta función las elimina para obtener texto plano
    """

    if not texto:
        return ""
    # re.sub reemplaza todo lo que coincida con el patrón por ""
    # El patrón <[^>]+> significa: < seguido de cualquier cosa que no sea >
    texto_limpio = re.sub(r'<[^>]+>', ' ', texto)
    # Colapsar espacios múltiples en uno solo
    texto_limpio = re.sub(r'\s+', ' ', texto_limpio).strip()
    return texto_limpio

def obtener_texto(elemento, etiqueta, ns=None):
    """
    Busca una etiqueta dentro de un elemento XML y devuelve su .text.
    ns se usa por si existen namespaces, en este caso ya hemos detectado que no existen, por eso lo igualamos a None
    """

    if ns:
        etiqueta_completa = f"{{{ns}}}{etiqueta}"
    else:
        etiqueta_completa = etiqueta

    hijo = elemento.find(etiqueta_completa)
    return hijo.text if hijo is not None and hijo.text else ""

def detectar_namespace(root):
    """"
    Detecta automáticamente el namespace del XML, si existe.
    Devuelve el string del namespace o None si no hay
    Ejemplo:
    si root.tag == '{http://openvas.org}report'
    devuelve 'http://openvas.org'
    """

    tag = root.tag
    if tag.startswith('{'):
        # El formato es {namespace}etiqueta
        return tag[1:tag.index('}')]
    return None

def parsear_xml(ruta_xml, min_severity=0.0):
    """
    Lee el XML de OpenVAS y extrae la lista de vulnrabilidades.

    Parámetros:
        ruta_xml : ruta al archivo .xml exportado desde OpenVAS
        min_severity : float, filtra solo vulns con severidad >= este valor

    Retorna:
        - meta : dict con info general del escaneo (host, fecha, etc.)
        - vulns : lista de dicts, cada uno es una vunlerabilidad
    """

    # ET.parse() lee el archivo XML del disco y lo convierte en un árbol en memoria
    tree = ET.parse(ruta_xml)

    # getroot() obtiene el nodo raíz del árbol (la eqiqueta principal del XML)
    root = tree.getroot()

    # Detectar si el XML tiene namespaces
    ns = detectar_namespace(root)
    print(f"[INFO] Namespace detectado: {ns or 'ninguno'}")

    # Extraer metadatos del escaneo
    meta = {
        "fecha_escaneo": "",
        "hosts": set(), # usamos set para no repetir IPs
        "total_vulns": 0,
        "archivo": ruta_xml
    }

    # Buscar todos los resultados (cada resultado = una vulnerabilidad)

    # findall() devuelve una lista de todos los elementos que coincidan.
    # find() devuelve solo el primero (o None si no existe).
    # En OpenVAS el XML tiene esta estructura:
    #   <report>
    #     <results>
    #       <result id="...">
    #         <name>Nombre vuln</name>
    #         <host><ip>10.0.0.1</ip></host>
    #         <severity>7.5</severity>
    #         <solution>...</solution>
    #         ...
    #       </result>
    #     </results>
    #   </report>

    # Construir prefijo de namespace para buscar etiquetas
    def tag(nombre):
        return f"{{{ns}}}{nombre}" if ns else nombre
    
    
    # En OpenVAS, los <result> con datos completos son los que tienen valor <severity>.
    # Hay sub-results de detección dentro de <detection> que no tienen valor <severity> y hay que ignorarlos.
    todos_results = root.findall(".//result")
    resultados = [r for r in todos_results if r.find("severity") is not None]

    print(f"[INFO] Resultados totales en XML: {len(todos_results)}")
    print(f"[INFO] Resultados reales (con severity): {len(resultados)}")

    vulns = []

    for result in resultados:
        # Severidad
        severity_text = result.findtext("severity") or "0"
        try:
            severity = float(severity_text)
        except ValueError:
            severity = 0.0
        
        # Aplicar filtro mínimo
        if severity < min_severity:
            continue

        # Host afectado
        # En OpenVAS el texto de la IP está en host.text directamente
        host_elem = result.find("host")
        if host_elem is not None and host_elem.text:
            host = host_elem.text.strip()
        else:
            host = "Desconocido"
        
        meta["hosts"].add(host)

        # Nombre de la vulnerabilidad
        nombre = result.findtext("name") or "Sin nombre"

        # Puerto
        puerto = result.findtext("port") or "N/A"

        # NVT: aquí viven la solución y el resumen
        nvt_elem = result.find("nvt")

        # Solución A buscar en ntv/solution, si no se encuentra buscar en result/solution
        solucion = ""
        if nvt_elem is not None:
            sol_elem = nvt_elem.find("solution")
            if sol_elem is not None and sol_elem.text:
                solucion = limpiar_html(sol_elem.text)
        if not solucion:
            solucion = limpiar_html(result.findtext(".//solution") or "") or "No disponible"

        # Descripción corta (summary del campo tags)
        descripcion = ""
        if nvt_elem is not None:
            tags_elem = nvt_elem.find("tags")
            if tags_elem is not None and tags_elem.text:
                for parte in tags_elem.text.split("|"):
                    if parte.strip().startswith("summary="):
                        descripcion = limpiar_html(parte.replace("summary=", "").strip())
                        break

        # Threat (nivel: Critical/High/Medium/Low)
        threat = result.findtext("threat") or ""

        vulns.append({
            "nombre": nombre,
            "severity": severity,
            "host": host,
            "puerto": puerto,
            "solucion": solucion,
            "descripcion": descripcion,
            "threat": threat,
        })

    # Ordenar de mayor a menor severidad
    vulns.sort(key=lambda v: v["severity"], reverse=True)

    meta["total_vulns"] = len(vulns)

    # Intentar obtener la fecha del escaneo
    fecha_elem = root.find(".//scan_start")
    if fecha_elem is None:
        fecha_elem = root.find(".//creation_time")
    if fecha_elem is not None and fecha_elem.text:
        meta["fecha_escaneo"] = fecha_elem.text.strip()

    return meta, vulns
    
# ====================================
# 2. Clasificación de severidad (CVSS)
# ====================================

def clasificar_severidad(score):
    """
    Devuelve (etiqueta, color) según la escala CVSS estándar.
    """
    if score >= 9.0:
        return "CRÍTICA", colors.HexColor("#7B0000")
    elif score >= 7.0:
        return "ALTA", colors.HexColor("#CC0000")
    elif score >= 4.0:
        return "MEDIA", colors.HexColor("#E67300")
    elif score > 0.0:
        return "BAJA", colors.HexColor("#2E7D32")
    else:
        return "INFO", colors.HexColor("#1565C0")
    

# =====================
# 3. Generación del PDF
# =====================

def generar_pdf(meta, vulns, ruta_salida, min_severity):
    """
    Genera el PDF final con reportlab usando el layout Platypus
    (más flexible que canvas para documentos de varias páginas)
    """

    doc = SimpleDocTemplate(
        ruta_salida,
        pagesize=A4,
        leftMargin=2*cm,
        rightMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm,
    )

    # Estilos de texto
    estilos = getSampleStyleSheet()

    # Definimos estilos personalizados
    estilo_titulo = ParagraphStyle(
        "Titulo",
        parent=estilos["Title"],
        fontSize=20,
        textColor=colors.HexColor("#1A237E"),
        spaceAfter=6,
    )
    estilo_subtitulo = ParagraphStyle(
        "Subtitulo",
        parent=estilos["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#455A64"),
        spaceAfter=4,
    )
    estilo_seccion = ParagraphStyle(
        "Seccion",
        parent=estilos["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#1A237E"),
        spaceBefore=14,
        spaceAfter=4,
        borderPadding=4,
    )
    estilo_nombre_vuln = ParagraphStyle(
        "NombreVuln",
        parent=estilos["Normal"],
        fontSize=11,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#212121"),
        spaceAfter=2,
    )
    estilo_cuerpo = ParagraphStyle(
        "Cuerpo",
        parent=estilos["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#37474F"),
        spaceAfter=3,
        leading=13,
    )
    estilo_etiqueta = ParagraphStyle(
        "Etiqueta",
        parent=estilos["Normal"],
        fontSize=8,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#546E7A"),
        spaceAfter=1,
    )

    # Construcción del contenido (story)
    # En reportlab Platypus, el documento es una lista de "flowables"(objetos que saben cómo dibujarse a sí mismos)
    story = []

    # Portada/cabecera
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph("Reporte de Vulnerabilidades", estilo_titulo))
    story.append(Paragraph("Generado desde exportación XML de OpenVAS/Greenbone", estilo_subtitulo))
    story.append(Spacer(1, 0.3*cm))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1A237E")))
    story.append(Spacer(1, 0.5*cm))

    # Tabla de resumen
    fecha_gen = datetime.now().strftime("%d/%m/%Y %H:%M")
    hosts_str = ", ".join(sorted(meta["hosts"])) or "N/A"

    resumen_data = [
        ["Archivo de entrada", meta["archivo"]],
        ["Fecha de generación", fecha_gen],
        ["Fecha del escaneo", meta["fecha_escaneo"] or "No disponible"],
        ["Hosts escaneados", hosts_str],
        ["Severidad mínima aplicada", f">= {min_severity}"],
        ["Vulnerabilidades incluídas", str(meta["total_vulns"])],
    ]

    tabla_resumen = Table(resumen_data, colWidths=[5*cm, 12*cm])
    tabla_resumen.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E8EAF6")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (0, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#1A237E")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#212121")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#C5CAE9")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))

    story.append(tabla_resumen)
    story.append(Spacer(1, 0.8*cm))


    # Tabla de distribución por severidad
    conteo = {"CRITICA": 0, "ALTA": 0, "MEDIA": 0, "BAJA": 0, "INFO": 0}
    for v in vulns:
        etiq, _ = clasificar_severidad(v["severity"])
        etiq_key = etiq.replace("Í", "I").replace("É", "E")
        if etiq_key in conteo:
            conteo[etiq_key] += 1

    story.append(Paragraph("Distribución por severidad", estilo_seccion))

    dist_data = [["Nivel", "Rango CVSS", "Cantidad"]]
    niveles = [
        ("CRITICA", "9.0 - 10.0", colors.HexColor("#7B0000")),
        ("ALTA", "7.0 - 8.9", colors.HexColor("#CC0000")),
        ("MEDIA", "4.0 - 6.9", colors.HexColor("#E67300")),
        ("BAJA", "0.1 - 3.9", colors.HexColor("#2E7D32")),
        ("INFO", "0.0", colors.HexColor("#1565C0")),
    ]

    for nombre_nivel, rango, color_nivel in niveles:
        dist_data.append([nombre_nivel, rango, str(conteo.get(nombre_nivel, 0))])

    tabla_dist = Table(dist_data, colWidths=[4*cm, 5*cm, 3*cm])
    tabla_dist.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A237E")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#CFD8DC")),
        ("ALIGN",      (2, 0), (2, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
        ("PADDING",    (0, 0), (-1, -1), 6),
    ]))

    # Colorear la columna de nivel con el color correspondiente
    for i, (nombre_nivel, _, color_nivel) in enumerate(niveles, start=1):
        tabla_dist.setStyle(TableStyle([
            ("TEXTCOLOR", (0, i), (0, i), color_nivel),
            ("FONTNAME", (0, i), (0,i), "Helvetica-Bold"),
        ]))
    
    story.append(tabla_dist)
    story.append(PageBreak())

    # Detalle de vulnerabilidades
    story.append(Paragraph("Detalle de Vulnerabilidades", estilo_seccion))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#C5CAE9")))
    story.append(Spacer(1, 0.3*cm))


    for i, vuln in enumerate(vulns, start=1):
        etiqueta, color_sev = clasificar_severidad(vuln["severity"])

        # Cabecera de cada vuln
        badge_color = color_sev.hexval() if hasattr(color_sev, 'hexval') else "#333333"
        cabecera_data = [[
            Paragraph(f"{i}. {vuln['nombre']}", estilo_nombre_vuln),
            Paragraph(
                f'<font color="{badge_color}"><b>{etiqueta} {vuln["severity"]:.1f}</b></font>',
                ParagraphStyle("badge", parent=estilos["Normal"],
                               fontSize=10, alignment=2)
            )
        ]]
        tabla_cabecera = Table(cabecera_data, colWidths=[12.5*cm, 4.5*cm])
        tabla_cabecera.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ECEFF1")),
            ("LINEBELOW",  (0, 0), (-1, 0), 1.5, color_sev),
            ("PADDING",    (0, 0), (-1, -1), 6),
            ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(tabla_cabecera)
        story.append(Spacer(1, 0.2*cm))

        # Cuerpo: host, puerto, descripción, solución
        story.append(Paragraph("Host afectado:", estilo_etiqueta))
        story.append(Paragraph(f"{vuln['host']} | Puerto: {vuln['puerto']}", estilo_cuerpo))

        if vuln["descripcion"]:
            story.append(Paragraph("Descripción:", estilo_etiqueta))
            # Truncar descripciones muy largas para mantener el reporte legible
            desc = vuln["descripcion"]
            if len(desc) > 600:
                desc = desc[:597] + "..."
            story.append(Paragraph(desc, estilo_cuerpo))

        story.append(Paragraph("Solución recomendada:", estilo_etiqueta))
        sol = vuln["solucion"] or "No disponible"
        if len(sol) > 800:
            sol = sol[:797] + "..."
        story.append(Paragraph(sol, estilo_cuerpo))

        story.append(Spacer(1, 0.5*cm))

        # Salto de página cada 3 vulns

    # Pie del documento

    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CFD8DC")))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        f"Reporte generado el {fecha_gen} - Basado en exportación XML de OpenVAS/Greenbone",
        ParagraphStyle("pie", parent=estilos["Normal"],
        fontSize=7, textColor=colors.HexColor("#90A4AE"),
        alignment=1)
    ))

    # Construir PDF
    doc.build(story)
    print(f"[OK] PDF generado: {ruta_salida}")

# ===================
# 4. PUNTO DE ENTRADA
# ===================

def main():
    parser = argparse.ArgumentParser(
        description="Parsea un XML de OpenVAS y genera un PDF de reporte limpio."
    )
    parser.add_argument(
        "xml",
        help="Ruta del archivo XML exportado desde OpenVAS"
    )
    parser.add_argument(
        "--min-severity", "-s",
        type=float,
        default=0.0,
        help="Severidad mínima a incluir (default: 0.0 = todas. Ej: 7.0)"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Nombre del PDF de salida (default: reporte_openvas.pdf)"
    )
    args = parser.parse_args()

    # Nombre de salida automático si no se especifica
    if args.output is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        args.output = f"reporte_openvas_{timestamp}.pdf"

    print(f"[INFO] Procesando: {args.xml}")
    print(f"[INFO] Severidad mínima: {args.min_severity}")

    meta, vulns = parsear_xml(args.xml, args.min_severity)
    if not vulns:
        print("[AVISO] No se encontraron vulnerabilidades con esos criterios.")
        print("        Prueba a bajar --min-severity o revisa la estructura del XML")
        sys.exit(0)

    print(f"[INFO] Vulnerabilidades a incluir en el reporte: {len(vulns)}")
    generar_pdf(meta, vulns, args.output, args.min_severity)

if __name__ == "__main__":
    main()
