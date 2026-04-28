"""
openvas_report_v2.py
====================
Parsea un reporte XML de OpenVAS/Greenbone y genera un PDF completo
con TODA la información del reporte, sin omitir datos.

Cambios respecto a v1:
  - Extrae todos los campos de <result>: CVEs, URLs, CERT refs, insight,
    impact, affected, vuldetect, solution_type, qod, description, detection
  - Extrae metadatos globales completos: task, timezone, scan_end, filters,
    conteo de hosts/vulns/apps/ssl_certs
  - Extrae datos completos del bloque <host>: OS, puertos abiertos,
    servicios, timestamps, closed CVEs, desglose de severidad
  - Sin truncado de textos
  - Las referencias se agrupan por tipo: CVE / URL / CERT-Bund / DFN-CERT
  - Sección de detección activa cuando existe

Uso:
    python openvas_report_v2.py reporte.xml
    python openvas_report_v2.py reporte.xml --output informe.pdf

Autor: Jesús Fernández
"""

import xml.etree.ElementTree as ET
import re
import sys
import argparse
import os
from datetime import datetime
from collections import defaultdict

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)

# ─────────────────────────────────────────────
# 1. UTILIDADES
# ─────────────────────────────────────────────

def limpiar_html(texto):
    """Elimina etiquetas HTML y colapsa espacios."""
    if not texto:
        return ""
    texto = re.sub(r'<[^>]+>', ' ', texto)
    texto = re.sub(r'\s+', ' ', texto).strip()
    return texto

def fmt_fecha(iso):
    """
    Convierte '2026-04-22T18:00:23Z' a '22/04/2026  18:00:23 UTC'.
    Si el formato no coincide devuelve el texto original.
    """
    if not iso:
        return "N/A"
    try:
        dt = datetime.strptime(iso.strip(), "%Y-%m-%dT%H:%M:%SZ")
        return dt.strftime("%d/%m/%Y  %H:%M:%S UTC")
    except ValueError:
        return iso.strip()

def duracion(iso_start, iso_end):
    """Calcula la duración entre dos timestamps ISO y devuelve 'Xh Ym Zs'."""
    try:
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        delta = datetime.strptime(iso_end.strip(), fmt) - datetime.strptime(iso_start.strip(), fmt)
        total = int(delta.total_seconds())
        h, rem = divmod(total, 3600)
        m, s = divmod(rem, 60)
        partes = []
        if h: partes.append(f"{h}h")
        if m: partes.append(f"{m}m")
        partes.append(f"{s}s")
        return " ".join(partes)
    except Exception:
        return ""

# ─────────────────────────────────────────────
# 2. PARSEO DEL XML
# ─────────────────────────────────────────────

def parsear_xml(ruta_xml):
    """
    Lee el XML de OpenVAS y extrae TODA la información disponible.

    Retorna:
        global_meta  : dict con metadatos del escaneo
        hosts_meta   : dict ip -> dict con datos del bloque <host>
        vulns        : lista de dicts, uno por resultado con host
    """
    tree = ET.parse(ruta_xml)
    root = tree.getroot()

    # El XML de OpenVAS anida <report><report>...</report></report>
    # El nodo interno es el que contiene los datos reales
    inner_found = root.find("report"); inner = inner_found if inner_found is not None else root

    # ── Metadatos globales ──────────────────────────────────────────
    global_meta = {
        "archivo":        ruta_xml,
        "task_name":      inner.findtext("task/name") or "",
        "task_id":        (inner.find("task").get("id", "") if inner.find("task") is not None else ""),
        "scan_start":     inner.findtext("scan_start") or "",
        "scan_end":       inner.findtext("scan_end") or "",
        "timezone":       inner.findtext("timezone") or "",
        "hosts_count":    inner.findtext("hosts/count") or "0",
        "vulns_count":    inner.findtext("vulns/count") or "0",
        "apps_count":     inner.findtext("apps/count") or "0",
        "ssl_certs_count":inner.findtext("ssl_certs/count") or "0",
        "filters":        inner.findtext("filters") or "",
        # Puertos globales (todos los puertos abiertos del escaneo)
        "ports": []
    }

    # Puertos globales: <ports><port host="...">general/tcp</port>
    for p in inner.findall("ports/port"):
        host_attr = p.get("host") or p.findtext("host") or ""
        global_meta["ports"].append({
            "host":   host_attr,
            "port":   (p.text or "").strip(),
            "severity": p.get("severity") or ""
        })

    # ── Bloques <host> (resumen por host) ──────────────────────────
    hosts_meta = {}  # ip -> dict

    for h in inner.findall("host"):
        ip = (h.findtext("ip") or "").strip()
        if not ip:
            continue

        # Conteo de resultados desde el resumen del host
        rc = h.find("result_count")
        conteo = {"total": "0", "critical": "0", "high": "0", "medium": "0", "low": "0"}
        if rc is not None:
            conteo["total"]    = rc.findtext("page") or "0"
            conteo["critical"] = rc.findtext("critical/page") or "0"
            conteo["high"]     = rc.findtext("high/page") or "0"
            # OpenVAS usa "warning" para medium en versiones antiguas
            conteo["medium"]   = rc.findtext("warning/page") or rc.findtext("medium/page") or "0"
            conteo["low"]      = rc.findtext("low/page") or "0"

        # Details: filtrar ruido (EXIT_CODE, OIDs de NVT, Cert raw base64)
        details = {}
        for d in h.findall("detail"):
            name  = (d.findtext("name")  or "").strip()
            value = (d.findtext("value") or "").strip()
            # Descartar entradas que no aportan valor al informe
            if not name:
                continue
            if name == "EXIT_CODE":
                continue
            if re.match(r'^1\.3\.6\.1\.4\.1\.\d', name):  # OIDs de NVT internos
                continue
            if name.startswith("Cert:"):               # Certificado raw base64
                continue
            details[name] = value

        hosts_meta[ip] = {
            "ip":         ip,
            "asset_id":   (h.find("asset").get("asset_id", "") if h.find("asset") is not None else ""),
            "start":      h.findtext("start") or "",
            "end":        h.findtext("end") or "",
            "port_count": h.findtext("port_count/page") or "0",
            "result_count": conteo,
            "hostname":   details.get("hostname", ""),
            "os":         details.get("best_os_txt", details.get("OS", "")),
            "os_cpe":     details.get("best_os_cpe", ""),
            "ports":      details.get("ports", details.get("tcp_ports", "")),
            "services":   details.get("Services", ""),
            "closed_cves":details.get("Closed CVE", ""),
            "details_raw":details,  # conservamos todo por si hay que mostrar algo más
        }

    # ── Resultados (<result>) ───────────────────────────────────────
    todos_results = root.findall(".//result")

    # Solo los que tienen <host> (texto con IP) y <severity>
    # Los auxiliares de tipo 3 no tienen <host> con IP
    resultados = [
        r for r in todos_results
        if r.find("host") is not None
        and (r.find("host").text or "").strip()
        and r.find("severity") is not None
    ]

    print(f"[INFO] Resultados en XML: {len(todos_results)}")
    print(f"[INFO] Resultados con host+severity: {len(resultados)}")

    vulns = []

    for result in resultados:
        # ── Campos básicos ──
        severity_text = result.findtext("severity") or "0"
        try:
            severity = float(severity_text)
        except ValueError:
            severity = 0.0

        host_elem = result.find("host")
        host_ip   = (host_elem.text or "").strip()

        # El hostname puede estar como subelemento <hostname> dentro de <host>
        host_hostname = ""
        if host_elem is not None:
            host_hostname = (host_elem.findtext("hostname") or "").strip()
        # Fallback: buscarlo en el bloque host
        if not host_hostname and host_ip in hosts_meta:
            host_hostname = hosts_meta[host_ip].get("hostname", "")

        nombre   = result.findtext("name") or "No name"
        puerto   = result.findtext("port") or "N/A"
        threat   = result.findtext("threat") or ""
        orig_sev = result.findtext("original_severity") or severity_text
        desc     = limpiar_html(result.findtext("description") or "")
        mod_time = result.findtext("modification_time") or ""
        comment  = limpiar_html(result.findtext("comment") or "")
        compliance = result.findtext("compliance") or ""

        # ── QoD ──
        qod_value = result.findtext("qod/value") or ""
        qod_type  = result.findtext("qod/type") or ""

        # ── NVT ──
        nvt_elem    = result.find("nvt")
        nvt_oid     = nvt_elem.get("oid", "") if nvt_elem is not None else ""
        nvt_type    = result.findtext("nvt/type") or ""
        nvt_family  = result.findtext("nvt/family") or ""
        nvt_cvss    = result.findtext("nvt/cvss_base") or ""
        nvt_solucion= limpiar_html(result.findtext("nvt/solution") or
                                   result.findtext(".//solution") or "")
        sol_type    = ""

        # ── Tags del NVT (pipe-separated key=value) ──
        tags = {
            "summary":       "",
            "insight":       "",
            "impact":        "",
            "affected":      "",
            "vuldetect":     "",
            "solution_type": "",
        }
        tags_elem = result.find("nvt/tags")
        if tags_elem is not None and tags_elem.text:
            for parte in tags_elem.text.split("|"):
                if "=" in parte:
                    k, _, v = parte.partition("=")
                    k = k.strip()
                    if k in tags:
                        tags[k] = limpiar_html(v.strip())

        # ── Referencias: CVE / URL / CERT ──
        refs = {"cve": [], "url": [], "cert-bund": [], "dfn-cert": [], "other": []}
        for ref in result.findall("nvt/refs/ref"):
            rtype = (ref.get("type") or "").lower()
            rid   = (ref.get("id") or "").strip()
            if not rid:
                continue
            if rtype == "cve":
                refs["cve"].append(rid)
            elif rtype == "url":
                refs["url"].append(rid)
            elif rtype == "cert-bund":
                refs["cert-bund"].append(rid)
            elif rtype == "dfn-cert":
                refs["dfn-cert"].append(rid)
            else:
                refs["other"].append(f"{rtype}:{rid}")

        # ── Detection (producto detectado activamente) ──
        detection = {}
        det_elem = result.find("detection/result/details")
        if det_elem is not None:
            for d in det_elem.findall("detail"):
                dn = (d.findtext("name")  or "").strip()
                dv = (d.findtext("value") or "").strip()
                if dn:
                    detection[dn] = dv

        vulns.append({
            "nombre":       nombre,
            "severity":     severity,
            "orig_severity":float(orig_sev) if orig_sev else severity,
            "threat":       threat,
            "host":         host_ip,
            "hostname":     host_hostname,
            "puerto":       puerto,
            "desc":         desc,
            "comment":      comment,
            "compliance":   compliance,
            "mod_time":     mod_time,
            "qod_value":    qod_value,
            "qod_type":     qod_type,
            "nvt_oid":      nvt_oid,
            "nvt_type":     nvt_type,
            "nvt_family":   nvt_family,
            "nvt_cvss":     nvt_cvss,
            "solucion":     nvt_solucion,
            "sol_type":     tags["solution_type"],
            "summary":      tags["summary"],
            "insight":      tags["insight"],
            "impact":       tags["impact"],
            "affected":     tags["affected"],
            "vuldetect":    tags["vuldetect"],
            "refs":         refs,
            "detection":    detection,
        })

    # Ordenar por severidad descendente
    vulns.sort(key=lambda v: v["severity"], reverse=True)

    return global_meta, hosts_meta, vulns


# ─────────────────────────────────────────────
# 3. CLASIFICACIÓN DE SEVERIDAD
# ─────────────────────────────────────────────

def clasificar_severidad(score):
    """Devuelve (etiqueta, color) según CVSS."""
    if score >= 9.0:
        return "CRITICAL", colors.HexColor("#7B0000")
    elif score >= 7.0:
        return "HIGH",     colors.HexColor("#CC0000")
    elif score >= 4.0:
        return "MEDIUM",   colors.HexColor("#E67300")
    elif score > 0.0:
        return "LOW",      colors.HexColor("#2E7D32")
    else:
        return "INFO",     colors.HexColor("#1565C0")


# ─────────────────────────────────────────────
# 4. HELPERS DE MAQUETACIÓN
# ─────────────────────────────────────────────

def tabla_kv(datos, estilos, col_key=5*cm, col_val=12*cm):
    """
    Genera una tabla de dos columnas clave-valor con estilo consistente.
    datos: lista de (clave, valor_str)  — se omiten las filas con valor vacío.
    """
    filas_validas = [(k, v) for k, v in datos if str(v).strip()]
    if not filas_validas:
        return None

    data = []
    for k, v in filas_validas:
        data.append([
            Paragraph(str(k), estilos["etiqueta"]),
            Paragraph(str(v), estilos["cuerpo"]),
        ])

    t = Table(data, colWidths=[col_key, col_val])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (0, -1), colors.HexColor("#E8EAF6")),
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1,-1), 9),
        ("TEXTCOLOR",   (0, 0), (0, -1), colors.HexColor("#1A237E")),
        ("TEXTCOLOR",   (1, 0), (1, -1), colors.HexColor("#212121")),
        ("GRID",        (0, 0), (-1,-1), 0.4, colors.HexColor("#C5CAE9")),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[colors.white, colors.HexColor("#F5F5F5")]),
        ("PADDING",     (0, 0), (-1,-1), 5),
        ("VALIGN",      (0, 0), (-1,-1), "TOP"),
    ]))
    return t


def estilos_doc():
    """Devuelve un dict con todos los ParagraphStyle usados en el documento."""
    base = getSampleStyleSheet()
    return {
        "titulo": ParagraphStyle(
            "Titulo", parent=base["Title"],
            fontSize=22, textColor=colors.HexColor("#1A237E"), spaceAfter=4,
        ),
        "subtitulo": ParagraphStyle(
            "Subtitulo", parent=base["Normal"],
            fontSize=10, textColor=colors.HexColor("#455A64"), spaceAfter=4,
        ),
        "seccion": ParagraphStyle(
            "Seccion", parent=base["Heading2"],
            fontSize=13, textColor=colors.HexColor("#1A237E"),
            spaceBefore=14, spaceAfter=4,
        ),
        "subseccion": ParagraphStyle(
            "Subseccion", parent=base["Heading3"],
            fontSize=11, textColor=colors.HexColor("#37474F"),
            spaceBefore=8, spaceAfter=3,
        ),
        "nombre_vuln": ParagraphStyle(
            "NombreVuln", parent=base["Normal"],
            fontSize=11, fontName="Helvetica-Bold",
            textColor=colors.HexColor("#212121"), spaceAfter=2,
        ),
        "cuerpo": ParagraphStyle(
            "Cuerpo", parent=base["Normal"],
            fontSize=9, textColor=colors.HexColor("#37474F"),
            spaceAfter=3, leading=13,
        ),
        "etiqueta": ParagraphStyle(
            "Etiqueta", parent=base["Normal"],
            fontSize=8, fontName="Helvetica-Bold",
            textColor=colors.HexColor("#546E7A"), spaceAfter=1,
        ),
        "pie": ParagraphStyle(
            "Pie", parent=base["Normal"],
            fontSize=7, textColor=colors.HexColor("#90A4AE"), alignment=1,
        ),
        "ref_cve": ParagraphStyle(
            "RefCve", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#7B0000"), leading=12,
        ),
        "ref_url": ParagraphStyle(
            "RefUrl", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#1565C0"), leading=12,
        ),
        "ref_cert": ParagraphStyle(
            "RefCert", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#4A148C"), leading=12,
        ),
        "host_header": ParagraphStyle(
            "HostHeader", parent=base["Normal"],
            fontSize=11, fontName="Helvetica-Bold",
            textColor=colors.white, spaceAfter=4, spaceBefore=6,
        ),
    }


# ─────────────────────────────────────────────
# 5. GENERACIÓN DEL PDF
# ─────────────────────────────────────────────

def generar_pdf(global_meta, hosts_meta, vulns, ruta_salida):
    doc = SimpleDocTemplate(
        ruta_salida,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm,  bottomMargin=2*cm,
        title="OpenVAS Security Report v2",
    )

    E = estilos_doc()
    story = []
    fecha_gen = datetime.now().strftime("%d/%m/%Y %H:%M")

    # ── Portada ────────────────────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph("Vulnerability Report", E["titulo"]))
    story.append(Paragraph("Generated from OpenVAS/Greenbone XML export — v2", E["subtitulo"]))
    story.append(Spacer(1, 0.3*cm))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1A237E")))
    story.append(Spacer(1, 0.5*cm))

    # ── Tabla de metadatos del escaneo ─────────────────────────────
    scan_dur = duracion(global_meta["scan_start"], global_meta["scan_end"])
    dur_str  = f"  ({scan_dur})" if scan_dur else ""

    resumen_data = [
        ("Input file",        os.path.basename(global_meta["archivo"])),
        ("Report generated",  fecha_gen),
        ("Task name",         global_meta["task_name"]),
        ("Task ID",           global_meta["task_id"]),
        ("Scan start",        fmt_fecha(global_meta["scan_start"])),
        ("Scan end",          fmt_fecha(global_meta["scan_end"]) + dur_str),
        ("Timezone",          global_meta["timezone"]),
        ("Hosts scanned",     global_meta["hosts_count"]),
        ("Unique vulns (NVTs)",global_meta["vulns_count"]),
        ("Applications found",global_meta["apps_count"]),
        ("SSL/TLS certs found",global_meta["ssl_certs_count"]),
        ("Results in report", str(len(vulns))),
    ]
    if global_meta["filters"]:
        resumen_data.append(("Filters applied", global_meta["filters"]))

    t = tabla_kv(resumen_data, E)
    if t:
        story.append(t)
    story.append(Spacer(1, 0.8*cm))

    # ── Distribución por severidad ─────────────────────────────────
    story.append(Paragraph("Severity distribution", E["seccion"]))
    conteo = {"CRITICAL":0, "HIGH":0, "MEDIUM":0, "LOW":0, "INFO":0}
    for v in vulns:
        etiq, _ = clasificar_severidad(v["severity"])
        conteo[etiq] = conteo.get(etiq, 0) + 1

    niveles = [
        ("CRITICAL", "9.0 – 10.0", colors.HexColor("#7B0000")),
        ("HIGH",     "7.0 – 8.9",  colors.HexColor("#CC0000")),
        ("MEDIUM",   "4.0 – 6.9",  colors.HexColor("#E67300")),
        ("LOW",      "0.1 – 3.9",  colors.HexColor("#2E7D32")),
        ("INFO",     "0.0",         colors.HexColor("#1565C0")),
    ]
    dist_data = [["Level", "CVSS range", "Count"]]
    for lbl, rng, _ in niveles:
        dist_data.append([lbl, rng, str(conteo.get(lbl, 0))])

    t_dist = Table(dist_data, colWidths=[4*cm, 5*cm, 3*cm])
    t_dist.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(-1,0), colors.HexColor("#1A237E")),
        ("TEXTCOLOR",  (0,0),(-1,0), colors.white),
        ("FONTNAME",   (0,0),(-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0),(-1,-1), 9),
        ("GRID",       (0,0),(-1,-1), 0.5, colors.HexColor("#CFD8DC")),
        ("ALIGN",      (2,0),(2,-1), "CENTER"),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#F5F5F5")]),
        ("PADDING",    (0,0),(-1,-1), 6),
    ]))
    for i, (_, _, col) in enumerate(niveles, start=1):
        t_dist.setStyle(TableStyle([
            ("TEXTCOLOR", (0,i),(0,i), col),
            ("FONTNAME",  (0,i),(0,i), "Helvetica-Bold"),
        ]))
    story.append(t_dist)
    story.append(Spacer(1, 0.8*cm))

    # ── Tabla de hosts ─────────────────────────────────────────────
    story.append(Paragraph("Scanned hosts", E["seccion"]))

    vulns_por_host = defaultdict(int)
    for v in vulns:
        vulns_por_host[v["host"]] += 1

    # Anchos fijos: pagina util 17cm exactos
    # IP=3.2, Hostname=4.5, OS=3.5, OpenPorts=2.5, Med=1.1, Low=1.1, Tot=1.1
    w_ip    = 3.2*cm
    w_hn    = 4.5*cm
    w_os    = 3.5*cm
    w_ports = 2.5*cm
    w_med   = 1.1*cm
    w_low   = 1.1*cm
    w_tot   = 1.1*cm

    estilo_celda = ParagraphStyle(
        "CeldaHost", parent=E["cuerpo"], fontSize=8, leading=11, spaceAfter=0,
    )
    estilo_cab_host = ParagraphStyle(
        "CabHost", parent=E["cuerpo"],
        fontSize=8, fontName="Helvetica-Bold",
        textColor=colors.white, leading=11, spaceAfter=0,
    )

    hosts_data = [[
        Paragraph("IP",         estilo_cab_host),
        Paragraph("Hostname",   estilo_cab_host),
        Paragraph("OS",         estilo_cab_host),
        Paragraph("Open ports", estilo_cab_host),
        Paragraph("Med",        estilo_cab_host),
        Paragraph("Low",        estilo_cab_host),
        Paragraph("Tot",        estilo_cab_host),
    ]]

    for ip in sorted(hosts_meta.keys()):
        hm = hosts_meta[ip]
        rc = hm["result_count"]
        hosts_data.append([
            Paragraph(ip,                    estilo_celda),
            Paragraph(hm["hostname"] or "-", estilo_celda),
            Paragraph(hm["os"] or "-",       estilo_celda),
            Paragraph(hm["ports"] or "-",    estilo_celda),
            Paragraph(rc["medium"],          estilo_celda),
            Paragraph(rc["low"],             estilo_celda),
            Paragraph(rc["total"],           estilo_celda),
        ])

    t_hosts = Table(
        hosts_data,
        colWidths=[w_ip, w_hn, w_os, w_ports, w_med, w_low, w_tot],
    )
    t_hosts.setStyle(TableStyle([
        ("BACKGROUND",     (0,0),(-1,0), colors.HexColor("#1A237E")),
        ("FONTSIZE",       (0,0),(-1,-1), 8),
        ("GRID",           (0,0),(-1,-1), 0.4, colors.HexColor("#CFD8DC")),
        ("ALIGN",          (4,0),(6,-1), "CENTER"),
        ("ROWBACKGROUNDS", (0,1),(-1,-1),[colors.white, colors.HexColor("#F5F5F5")]),
        ("PADDING",        (0,0),(-1,-1), 5),
        ("VALIGN",         (0,0),(-1,-1), "TOP"),
    ]))
    story.append(t_hosts)
    story.append(PageBreak())

    # ── Detalle de vulnerabilidades ────────────────────────────────
    story.append(Paragraph("Vulnerability Details", E["seccion"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#C5CAE9")))
    story.append(Spacer(1, 0.3*cm))

    grupos = defaultdict(list)
    for v in vulns:
        grupos[v["host"]].append(v)

    vuln_num = 1
    for host_ip in sorted(grupos.keys()):
        vulns_host = grupos[host_ip]
        hm = hosts_meta.get(host_ip, {})
        hostname = hm.get("hostname", "") or vulns_host[0].get("hostname", "")

        # Cabecera de host
        titulo_host = f"Host: {host_ip}"
        if hostname:
            titulo_host += f"  —  {hostname}"

        host_hdr = [[
            Paragraph(titulo_host, E["host_header"]),
            Paragraph(
                f'<font color="white">{len(vulns_host)} '
                f'result{"s" if len(vulns_host) != 1 else ""}</font>',
                ParagraphStyle("hc", parent=E["host_header"], alignment=2)
            )
        ]]
        t_hdr = Table(host_hdr, colWidths=[12.5*cm, 4.5*cm])
        t_hdr.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0), colors.HexColor("#1A237E")),
            ("PADDING",   (0,0),(-1,-1), 8),
            ("VALIGN",    (0,0),(-1,-1), "MIDDLE"),
        ]))
        story.append(t_hdr)

        # Info del host: OS, puertos, servicios, timestamps
        if hm:
            host_info = []
            if hm.get("os"):
                host_info.append(("OS detected", hm["os"]))
            if hm.get("os_cpe"):
                host_info.append(("OS CPE", hm["os_cpe"]))
            if hm.get("ports"):
                host_info.append(("Open ports", hm["ports"]))
            if hm.get("services"):
                host_info.append(("Services", hm["services"]))
            if hm.get("start"):
                ts = fmt_fecha(hm["start"])
                if hm.get("end"):
                    ts += f"  →  {fmt_fecha(hm['end'])}"
                    d = duracion(hm["start"], hm["end"])
                    if d:
                        ts += f"  ({d})"
                host_info.append(("Scan window", ts))
            if hm.get("closed_cves"):
                host_info.append(("Closed CVEs", hm["closed_cves"]))

            t_info = tabla_kv(host_info, E, col_key=4*cm, col_val=13*cm)
            if t_info:
                story.append(Spacer(1, 0.2*cm))
                story.append(t_info)

        story.append(Spacer(1, 0.3*cm))

        for vuln in vulns_host:
            etiqueta, color_sev = clasificar_severidad(vuln["severity"])
            badge_color = color_sev.hexval() if hasattr(color_sev, 'hexval') else "#333333"

            # Cabecera de la vulnerabilidad individual
            cab = [[
                Paragraph(f"{vuln_num}. {vuln['nombre']}", E["nombre_vuln"]),
                Paragraph(
                    f'<font color="{badge_color}"><b>{etiqueta}  {vuln["severity"]:.1f}</b></font>',
                    ParagraphStyle("badge", parent=E["cuerpo"], fontSize=10, alignment=2)
                )
            ]]
            t_cab = Table(cab, colWidths=[12.5*cm, 4.5*cm])
            t_cab.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0), colors.HexColor("#ECEFF1")),
                ("LINEBELOW", (0,0),(-1,0), 1.5, color_sev),
                ("PADDING",   (0,0),(-1,-1), 6),
                ("VALIGN",    (0,0),(-1,-1), "MIDDLE"),
            ]))

            # Construir el bloque completo de esta vuln como KeepTogether
            bloque = [t_cab, Spacer(1, 0.2*cm)]

            # ── Tabla de metadatos de la vuln ──
            vuln_meta = [
                ("Port",            vuln["puerto"]),
                ("Threat level",    vuln["threat"]),
                ("CVSS score",      f"{vuln['severity']:.1f}"
                                    + (f" (original: {vuln['orig_severity']:.1f})"
                                       if vuln["orig_severity"] != vuln["severity"] else "")),
                ("CVSS base (NVT)", vuln["nvt_cvss"]),
                ("NVT family",      vuln["nvt_family"]),
                ("NVT OID",         vuln["nvt_oid"]),
                ("Solution type",   vuln["sol_type"]),
                ("QoD",             (f"{vuln['qod_value']}%"
                                     + (f"  ({vuln['qod_type']})" if vuln["qod_type"] else ""))
                                    if vuln["qod_value"] else ""),
            ]
            t_meta = tabla_kv(vuln_meta, E, col_key=4.5*cm, col_val=12.5*cm)
            if t_meta:
                bloque.append(t_meta)
                bloque.append(Spacer(1, 0.25*cm))

            # ── Secciones de texto ──
            secciones_texto = [
                ("Summary",            vuln["summary"]),
                ("Insight",            vuln["insight"]),
                ("Impact",             vuln["impact"]),
                ("Affected systems",   vuln["affected"]),
                ("Detection method",   vuln["vuldetect"]),
                ("Raw output",         vuln["desc"]),
                ("Recommended solution", vuln["solucion"]),
            ]
            for titulo_sec, contenido in secciones_texto:
                if contenido and contenido.strip():
                    bloque.append(Paragraph(titulo_sec + ":", E["etiqueta"]))
                    bloque.append(Paragraph(contenido, E["cuerpo"]))
                    bloque.append(Spacer(1, 0.15*cm))

            # ── Detection activa ──
            if vuln["detection"]:
                bloque.append(Paragraph("Detection details:", E["etiqueta"]))
                det_rows = [(k, v) for k, v in vuln["detection"].items()]
                t_det = tabla_kv(det_rows, E, col_key=4*cm, col_val=13*cm)
                if t_det:
                    bloque.append(t_det)
                    bloque.append(Spacer(1, 0.15*cm))

            # ── Referencias ──
            cves = vuln["refs"]["cve"]
            urls = vuln["refs"]["url"]
            certs_bund = vuln["refs"]["cert-bund"]
            certs_dfn  = vuln["refs"]["dfn-cert"]
            otros      = vuln["refs"]["other"]

            if any([cves, urls, certs_bund, certs_dfn, otros]):
                bloque.append(Paragraph("References:", E["etiqueta"]))
                if cves:
                    bloque.append(Paragraph(
                        "<b>CVEs:</b>  " + "  ·  ".join(cves),
                        E["ref_cve"]
                    ))
                if urls:
                    for u in urls:
                        bloque.append(Paragraph(f"URL:  {u}", E["ref_url"]))
                if certs_bund:
                    bloque.append(Paragraph(
                        "<b>CERT-Bund:</b>  " + "  ·  ".join(certs_bund[:10])
                        + (f"  (+ {len(certs_bund)-10} more)" if len(certs_bund) > 10 else ""),
                        E["ref_cert"]
                    ))
                if certs_dfn:
                    bloque.append(Paragraph(
                        "<b>DFN-CERT:</b>  " + "  ·  ".join(certs_dfn[:10])
                        + (f"  (+ {len(certs_dfn)-10} more)" if len(certs_dfn) > 10 else ""),
                        E["ref_cert"]
                    ))
                if otros:
                    bloque.append(Paragraph("Other:  " + "  ·  ".join(otros), E["cuerpo"]))

            if vuln.get("comment"):
                bloque.append(Spacer(1, 0.1*cm))
                bloque.append(Paragraph("Comment:", E["etiqueta"]))
                bloque.append(Paragraph(vuln["comment"], E["cuerpo"]))

            bloque.append(Spacer(1, 0.5*cm))

            # KeepTogether solo para el header + metadatos (evita cortes feos)
            # El resto fluye libre para no crear páginas en blanco
            story.append(KeepTogether(bloque[:4]))
            story.extend(bloque[4:])

            vuln_num += 1

        story.append(Spacer(1, 0.6*cm))

    # ── Pie de página ──────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CFD8DC")))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        f"Report generated on {fecha_gen} — Based on OpenVAS/Greenbone XML export — openvas_report_v2.py",
        E["pie"]
    ))

    doc.build(story)
    print(f"[OK] PDF generado: {ruta_salida}")


# ─────────────────────────────────────────────
# 6. PUNTO DE ENTRADA
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Parsea un XML de OpenVAS y genera un PDF completo (v2)."
    )
    parser.add_argument("xml",  help="Ruta del archivo XML exportado desde OpenVAS")
    parser.add_argument("--output", "-o", default=None,
                        help="Nombre del PDF de salida (default: reporte_openvas_v2_<timestamp>.pdf)")
    args = parser.parse_args()

    if args.output is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M")
        args.output = f"reporte_openvas_v2_{ts}.pdf"
    elif os.path.isdir(args.output):
        ts = datetime.now().strftime("%Y%m%d_%H%M")
        args.output = os.path.join(args.output, f"reporte_openvas_v2_{ts}.pdf")

    print(f"[INFO] Procesando: {args.xml}")
    global_meta, hosts_meta, vulns = parsear_xml(args.xml)

    if not vulns:
        print("[AVISO] No se encontraron resultados con host y severidad.")
        sys.exit(0)

    print(f"[INFO] Vulnerabilidades a incluir: {len(vulns)}")
    generar_pdf(global_meta, hosts_meta, vulns, args.output)


if __name__ == "__main__":
    main()
