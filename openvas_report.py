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
import os
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
            host = "Unknown"

        # Nombre de la vulnerabilidad
        nombre = result.findtext("name") or "No name"

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
            solucion = limpiar_html(result.findtext(".//solution") or "") or "Not available"

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

    # Extraer los hosts escaneados desde los bloques <host> hijos directos del <report>.
    # Esta es la fuente correcta: incluye todos los hosts que el scanner tocó,
    # incluso los que no produjeron ninguna vulnerabilidad con la severidad mínima aplicada.
    # Leer solo de <result> produce un conteo incorrecto cuando hay hosts limpios.
    report_node = root.find("report")
    if report_node is None:
        report_node = root
    meta["hosts"] = {}  # dict ip -> hostname (puede ser "")
    for host_el in report_node.findall("host"):
        ip = host_el.findtext("ip")
        if ip:
            ip = ip.strip()
            # El hostname puede venir en <detail><n>hostname</n><v>...</v></detail>
            hostname = ""
            for detail in host_el.findall("detail"):
                if detail.findtext("name") == "hostname":
                    hostname = detail.findtext("value") or ""
                    break
            meta["hosts"][ip] = hostname

    # Ordenar de mayor a menor severidad
    vulns.sort(key=lambda v: v["severity"], reverse=True)

    meta["total_vulns"] = len(vulns)
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
        return "CRITICAL", colors.HexColor("#7B0000")
    elif score >= 7.0:
        return "HIGH", colors.HexColor("#CC0000")
    elif score >= 4.0:
        return "MEDIUM", colors.HexColor("#E67300")
    elif score > 0.0:
        return "LOW", colors.HexColor("#2E7D32")
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
    story.append(Paragraph("Vulnerability report", estilo_titulo))
    story.append(Paragraph("Generated from OpenVAS/Greenbone XML export", estilo_subtitulo))
    story.append(Spacer(1, 0.3*cm))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1A237E")))
    story.append(Spacer(1, 0.5*cm))

    # Tabla de resumen
    fecha_gen = datetime.now().strftime("%d/%m/%Y %H:%M")
    hosts_str = ", ".join(sorted(meta["hosts"])) or "N/A"

    resumen_data = [
        ["Input file", os.path.basename(meta["archivo"])],
        ["Generation date", fecha_gen],
        ["Scan date", meta["fecha_escaneo"] or "Not available"],
        ["Minimum severity applied", f">= {min_severity}"],
        ["Vulnerabilities included", str(meta["total_vulns"])],
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
    conteo = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for v in vulns:
        etiq, _ = clasificar_severidad(v["severity"])
        if etiq in conteo:
            conteo[etiq] += 1

    story.append(Paragraph("Severity distribution", estilo_seccion))

    dist_data = [["Level", "CVSS Range", "Count"]]
    niveles = [
        ("CRITICAL", "9.0 - 10.0", colors.HexColor("#7B0000")),
        ("HIGH", "7.0 - 8.9", colors.HexColor("#CC0000")),
        ("MEDIUM", "4.0 - 6.9", colors.HexColor("#E67300")),
        ("LOW", "0.1 - 3.9", colors.HexColor("#2E7D32")),
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
    story.append(Spacer(1, 0.8*cm))

    # Calcular conteo de vulnerabilidades por host desde la lista filtrada
    vulns_por_host = {}
    for v in vulns:
        vulns_por_host[v["host"]] = vulns_por_host.get(v["host"], 0) + 1

    story.append(Paragraph("Scanned hosts", estilo_seccion))

    hosts_data = [["Host", "Hostname", "Vulnerabilities"]]
    for ip in sorted(meta["hosts"].keys()):
        hostname = meta["hosts"].get(ip, "") or "—"
        count = str(vulns_por_host.get(ip, 0))
        hosts_data.append([ip, hostname, count])

    # Calcular ancho de columna Host según el texto más largo (mínimo 4cm, máximo 6cm)
    from reportlab.pdfbase.pdfmetrics import stringWidth
    max_ip_w = max((stringWidth(row[0], "Helvetica", 9) for row in hosts_data[1:]), default=0)
    col_ip_w = max(4*cm, min(max_ip_w + 0.6*cm, 6*cm))

    max_hn_w = max((stringWidth(row[1], "Helvetica", 9) for row in hosts_data[1:]), default=0)
    col_hn_w = max(4*cm, min(max_hn_w + 0.6*cm, 11*cm))

    col_vuln_w = 17*cm - col_ip_w - col_hn_w

    tabla_hosts = Table(hosts_data, colWidths=[col_ip_w, col_hn_w, col_vuln_w])
    tabla_hosts.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0), colors.HexColor("#1A237E")),
        ("TEXTCOLOR",      (0, 0), (-1, 0), colors.white),
        ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, -1), 9),
        ("GRID",           (0, 0), (-1, -1), 0.5, colors.HexColor("#CFD8DC")),
        ("ALIGN",          (2, 0), (2, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
        ("PADDING",        (0, 0), (-1, -1), 6),
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
    ]))

    story.append(tabla_hosts)
    story.append(PageBreak())

    # Detalle de vulnerabilidades agrupado por host, dentro de cada host por severidad
    story.append(Paragraph("Vulnerability Details", estilo_seccion))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#C5CAE9")))
    story.append(Spacer(1, 0.3*cm))

    # Estilo para el título de grupo de host
    estilo_host_grupo = ParagraphStyle(
        "HostGrupo",
        parent=estilos["Normal"],
        fontSize=11,
        fontName="Helvetica-Bold",
        textColor=colors.white,
        spaceAfter=4,
        spaceBefore=6,
    )

    # Agrupar vulns por host manteniendo orden alfabético de host
    # Dentro de cada host, las vulns ya vienen ordenadas por severidad desc desde parsear_xml
    from collections import defaultdict
    grupos = defaultdict(list)
    for v in vulns:
        grupos[v["host"]].append(v)

    vuln_num = 1  # Numeración global de vulnerabilidades
    for host in sorted(grupos.keys()):
        vulns_host = grupos[host]  # Ya ordenadas por severidad desc

        # Cabecera de grupo host: fondo azul oscuro, texto blanco
        host_header_data = [[
            Paragraph(f"Host: {host}", estilo_host_grupo),
            Paragraph(
                f'<font color="white">{len(vulns_host)} vulnerabilit{"y" if len(vulns_host) == 1 else "ies"}</font>',
                ParagraphStyle("host_count", parent=estilos["Normal"],
                               fontSize=10, alignment=2, textColor=colors.white)
            )
        ]]
        tabla_host_header = Table(host_header_data, colWidths=[12.5*cm, 4.5*cm])
        tabla_host_header.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A237E")),
            ("PADDING",    (0, 0), (-1, -1), 8),
            ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(tabla_host_header)
        story.append(Spacer(1, 0.2*cm))

        for vuln in vulns_host:
            etiqueta, color_sev = clasificar_severidad(vuln["severity"])

            # Cabecera de cada vuln
            badge_color = color_sev.hexval() if hasattr(color_sev, 'hexval') else "#333333"
            cabecera_data = [[
                Paragraph(f"{vuln_num}. {vuln['nombre']}", estilo_nombre_vuln),
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

            # Cuerpo: puerto, descripción, solución (host ya está en el grupo)
            story.append(Paragraph("Port:", estilo_etiqueta))
            story.append(Paragraph(vuln['puerto'], estilo_cuerpo))

            if vuln["descripcion"]:
                story.append(Paragraph("Description:", estilo_etiqueta))
                # Truncar descripciones muy largas para mantener el reporte legible
                desc = vuln["descripcion"]
                if len(desc) > 600:
                    desc = desc[:597] + "..."
                story.append(Paragraph(desc, estilo_cuerpo))

            story.append(Paragraph("Recommended solution:", estilo_etiqueta))
            sol = vuln["solucion"] or "Not available"
            if len(sol) > 800:
                sol = sol[:797] + "..."
            story.append(Paragraph(sol, estilo_cuerpo))

            story.append(Spacer(1, 0.4*cm))
            vuln_num += 1

        story.append(Spacer(1, 0.4*cm))

    # Pie del documento

    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CFD8DC")))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        f"Report generated on {fecha_gen} - Based on OpenVAS/Greenbone XML export",
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
    else:
        # Si -o es un directorio existente, poner el PDF dentro con nombre automático
        if os.path.isdir(args.output):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M")
            args.output = os.path.join(args.output, f"reporte_openvas_{timestamp}.pdf")

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
