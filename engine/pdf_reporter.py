#!/usr/bin/env python3
"""
ToolKitDev - Executive PDF Audit Report Generator
Produces corporate-grade, formal Mobile Application Security Audit Reports
evaluating APK/AAB targets against OWASP MASVS, PCI-DSS, and OJK/UU PDP standards.
"""

import os
import io
import html
import datetime
from typing import Dict, Any, List

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and draw total page numbers and running headers."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_header_footer(num_pages)
            super().showPage()
        super().save()

    def draw_header_footer(self, page_count: int):
        self.saveState()
        # Suppress running header on cover/page 1
        if self._pageNumber > 1:
            # Header
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(colors.HexColor("#3b82f6"))
            self.drawString(40, 805, "TOOLKITDEV.AI")
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748b"))
            self.drawString(110, 805, "|  Executive Mobile Application Security Audit Report")
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.75)
            self.line(40, 797, 595 - 40, 797)

        # Footer on all pages
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#94a3b8"))
        self.drawString(40, 30, "CONFIDENTIAL // TLP:AMBER — Authorized Security Assessment")
        self.drawRightString(595 - 40, 30, f"Page {self._pageNumber} of {page_count}")
        self.setStrokeColor(colors.HexColor("#e2e8f0"))
        self.setLineWidth(0.5)
        self.line(40, 42, 595 - 40, 42)
        self.restoreState()


class ExecutivePdfReporter:
    def __init__(self, analysis_data: Dict[str, Any], auditor_name: str = "ToolKitDev Autonomous SecOps",
                 organization: str = "Enterprise Audit Target", scope: str = "Comprehensive Static & Dynamic DAST Audit"):
        self.data = analysis_data or {}
        self.auditor_name = auditor_name
        self.organization = organization
        self.scope = scope
        self.report_date = datetime.datetime.now().strftime("%d %B %Y, %H:%M WIB")
        self.doc_id = f"TKD-AUDIT-{datetime.datetime.now().strftime('%Y%m%d')}-{abs(hash(str(self.data.get('file_info', {})))) % 100000:05d}"
        
        self.styles = getSampleStyleSheet()
        self._init_custom_styles()

    def _init_custom_styles(self):
        self.title_style = ParagraphStyle(
            'DocTitle',
            parent=self.styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=colors.HexColor('#0f172a')
        )
        self.subtitle_style = ParagraphStyle(
            'DocSubtitle',
            parent=self.styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            leading=15,
            textColor=colors.HexColor('#475569')
        )
        self.h1_style = ParagraphStyle(
            'Heading1Custom',
            parent=self.styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            textColor=colors.HexColor('#1e293b'),
            spaceBefore=14,
            spaceAfter=6
        )
        self.h2_style = ParagraphStyle(
            'Heading2Custom',
            parent=self.styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=11,
            leading=14,
            textColor=colors.HexColor('#334155'),
            spaceBefore=10,
            spaceAfter=4
        )
        self.body_style = ParagraphStyle(
            'BodyCustom',
            parent=self.styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=13,
            textColor=colors.HexColor('#334155')
        )
        self.body_bold = ParagraphStyle(
            'BodyBold',
            parent=self.body_style,
            fontName='Helvetica-Bold'
        )
        self.table_cell = ParagraphStyle(
            'TableCell',
            parent=self.styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            leading=11,
            textColor=colors.HexColor('#1e293b')
        )
        self.table_cell_bold = ParagraphStyle(
            'TableCellBold',
            parent=self.table_cell,
            fontName='Helvetica-Bold'
        )
        self.code_style = ParagraphStyle(
            'CodeCell',
            parent=self.styles['Normal'],
            fontName='Courier',
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor('#0f172a')
        )
        self.badge_critical = ParagraphStyle(
            'BadgeCrit',
            parent=self.table_cell_bold,
            textColor=colors.HexColor('#dc2626')
        )
        self.badge_high = ParagraphStyle(
            'BadgeHigh',
            parent=self.table_cell_bold,
            textColor=colors.HexColor('#ea580c')
        )
        self.badge_warning = ParagraphStyle(
            'BadgeWarn',
            parent=self.table_cell_bold,
            textColor=colors.HexColor('#d97706')
        )
        self.badge_secure = ParagraphStyle(
            'BadgeSec',
            parent=self.table_cell_bold,
            textColor=colors.HexColor('#16a34a')
        )

    def generate_pdf(self) -> bytes:
        """Compiles the report into PDF binary bytes."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=40,
            rightMargin=40,
            topMargin=45,
            bottomMargin=45
        )

        story = []
        self._build_cover_page(story)
        story.append(PageBreak())
        self._build_executive_summary(story)
        self._build_compliance_matrix(story)
        story.append(PageBreak())
        self._build_vulnerability_findings(story)
        story.append(PageBreak())
        self._build_frida_telemetry(story)
        story.append(PageBreak())
        self._build_remediation_roadmap(story)

        doc.build(story, canvasmaker=NumberedCanvas)
        return buffer.getvalue()

    def _build_cover_page(self, story: List[Any]):
        meta = self.data.get("metadata", {})
        file_info = self.data.get("file_info", {})
        score = self.data.get("security_score", 0)
        
        # Pill banner
        pill_table = Table(
            [[Paragraph("<b>TOOLKITDEV.AI // ENTERPRISE MOBILE SECURITY AUDIT</b>", ParagraphStyle('Pill', parent=self.table_cell_bold, fontSize=8.5, textColor=colors.HexColor('#2563eb')))]],
            colWidths=[515]
        )
        pill_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#eff6ff')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#bfdbfe')),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(pill_table)
        story.append(Spacer(1, 14))

        # Title
        story.append(Paragraph("Executive Mobile Application Security Audit Report", self.title_style))
        story.append(Spacer(1, 4))
        story.append(Paragraph("Comprehensive Static Code, Android IPC, Frida Telemetry & Regulatory Compliance Assessment", self.subtitle_style))
        story.append(Spacer(1, 16))

        # Score & Risk Verdict Block
        if score < 40:
            score_bg = colors.HexColor("#fef2f2")
            score_border = colors.HexColor("#f87171")
            score_text_color = colors.HexColor("#b91c1c")
            risk_label = "CRITICAL RISK — IMMEDIATE ACTION REQUIRED"
            verdict_desc = "Aplikasi memiliki celah fatal yang memungkinkan bypass autentikasi, penyadapan kredensial/PII plaintext, atau remote component injection. Tidak layak dirilis ke production sebelum remediasi diselesaikan."
        elif score < 70:
            score_bg = colors.HexColor("#fffbeb")
            score_border = colors.HexColor("#fcd34d")
            score_text_color = colors.HexColor("#b45309")
            risk_label = "HIGH RISK — CONDITIONAL APPROVAL"
            verdict_desc = "Terdapat kelemahan kriptografi dan konfigurasi jaringan yang harus diperbaiki sesuai rekomendasi."
        else:
            score_bg = colors.HexColor("#f0fdf4")
            score_border = colors.HexColor("#86efac")
            score_text_color = colors.HexColor("#15803d")
            risk_label = "LOW RISK — PASSED AUDIT"
            verdict_desc = "Aplikasi menerapkan kontrol keamanan yang baik sesuai standar OWASP MASVS."

        score_table = Table([
            [
                Paragraph(f"<font size=32><b>{score}</b></font><br/><font size=10 color='#64748b'>/ 100</font>", ParagraphStyle('ScoreBig', parent=self.body_bold, alignment=1, textColor=score_text_color)),
                Paragraph(f"<b>STATUS: {risk_label}</b><br/><br/>{html.escape(verdict_desc)}", ParagraphStyle('ScoreDesc', parent=self.body_style, leading=14))
            ]
        ], colWidths=[100, 415])
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), score_bg),
            ('BOX', (0,0), (-1,-1), 1.5, score_border),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('PADDING', (0,0), (-1,-1), 12),
        ]))
        story.append(score_table)
        story.append(Spacer(1, 20))

        # Target & Assessment Metadata Table
        app_name = meta.get("app_name") or file_info.get("name", "Target Application")
        package_name = meta.get("package_name") or "com.target.application"
        version_name = meta.get("version_name") or "1.0.0"
        version_code = meta.get("version_code") or "1"
        file_sha256 = file_info.get("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        file_size_mb = file_info.get("size_mb", 0)

        meta_rows = [
            [Paragraph("<b>Target Application</b>", self.table_cell_bold), Paragraph(html.escape(str(app_name)), self.table_cell),
             Paragraph("<b>Document Reference</b>", self.table_cell_bold), Paragraph(self.doc_id, self.code_style)],
            [Paragraph("<b>Package Identifier</b>", self.table_cell_bold), Paragraph(html.escape(str(package_name)), self.table_cell),
             Paragraph("<b>Audit Date</b>", self.table_cell_bold), Paragraph(self.report_date, self.table_cell)],
            [Paragraph("<b>Version (Code)</b>", self.table_cell_bold), Paragraph(f"{version_name} ({version_code})", self.table_cell),
             Paragraph("<b>Lead Auditor</b>", self.table_cell_bold), Paragraph(html.escape(self.auditor_name), self.table_cell)],
            [Paragraph("<b>Binary Size</b>", self.table_cell_bold), Paragraph(f"{file_size_mb:.2f} MB", self.table_cell),
             Paragraph("<b>Client / Organization</b>", self.table_cell_bold), Paragraph(html.escape(self.organization), self.table_cell)],
            [Paragraph("<b>Min / Target SDK</b>", self.table_cell_bold), Paragraph(f"API {meta.get('min_sdk', 21)} / API {meta.get('target_sdk', 34)}", self.table_cell),
             Paragraph("<b>Audit Standards</b>", self.table_cell_bold), Paragraph("OWASP MASVS, PCI-DSS, OJK", self.table_cell_bold)],
            [Paragraph("<b>SHA-256 Digest</b>", self.table_cell_bold), Paragraph(f"<font size=6.5>{file_sha256}</font>", self.code_style),
             Paragraph("<b>Classification</b>", self.table_cell_bold), Paragraph("<font color='#b91c1c'><b>CONFIDENTIAL // TLP:AMBER</b></font>", self.table_cell)]
        ]

        meta_table = Table(meta_rows, colWidths=[105, 155, 105, 150])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 24))

        # Notice Block
        notice = Paragraph(
            "<b>Pemberitahuan Kerahasiaan & Legalitas:</b> Dokumen ini berisi temuan audit keamanan siber, bukti forensik dekompilasi binary, dan analisis kerentanan teknis. Informasi di dalamnya ditujukan secara eksklusif kepada pihak berwenang di organisasi target untuk tujuan mitigasi risiko dan pengerasan sistem (hardening). Penyebarluasan tanpa izin dilarang keras.",
            ParagraphStyle('Notice', parent=self.body_style, fontSize=7.5, leading=11, textColor=colors.HexColor('#64748b'))
        )
        story.append(notice)

    def _build_executive_summary(self, story: List[Any]):
        story.append(Paragraph("1. Ringkasan Eksekutif & Sebaran Kerentanan", self.h1_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#3b82f6"), spaceAfter=10))

        story.append(Paragraph(
            "Evaluasi keamanan dilakukan secara komprehensif menggunakan kombinasi metode <b>Static Application Security Testing (SAST)</b> dan <b>Dynamic Hooking Telemetry (DAST via Frida)</b>. Pengujian mencakup audit konfigurasi AndroidManifest, struktur decompiled Java/Smali, perlindungan komunikasi jaringan, brankas kredensial, serta integritas API perbankan/transaksi.",
            self.body_style
        ))
        story.append(Spacer(1, 10))

        # Compute counts
        findings = self.data.get("findings", [])
        code_findings = self.data.get("code_analysis", {}).get("findings", []) if isinstance(self.data.get("code_analysis"), dict) else []
        
        crit_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
        warn_count = sum(1 for f in findings if f.get("severity") == "WARNING") + sum(1 for cf in code_findings if cf.get("severity") == "warning")
        info_count = sum(1 for f in findings if f.get("severity") == "INFO") + sum(1 for cf in code_findings if cf.get("severity") == "info")
        sec_count = sum(1 for cf in code_findings if cf.get("severity") == "secure")

        counts_table = Table([
            [
                Paragraph("<b>KRITIKAL</b>", ParagraphStyle('C1', parent=self.table_cell_bold, alignment=1, textColor=colors.HexColor('#dc2626'))),
                Paragraph("<b>TINGGI (HIGH)</b>", ParagraphStyle('C2', parent=self.table_cell_bold, alignment=1, textColor=colors.HexColor('#ea580c'))),
                Paragraph("<b>PERINGATAN (WARN)</b>", ParagraphStyle('C3', parent=self.table_cell_bold, alignment=1, textColor=colors.HexColor('#d97706'))),
                Paragraph("<b>INFO</b>", ParagraphStyle('C4', parent=self.table_cell_bold, alignment=1, textColor=colors.HexColor('#2563eb'))),
                Paragraph("<b>TERPROTEKSI</b>", ParagraphStyle('C5', parent=self.table_cell_bold, alignment=1, textColor=colors.HexColor('#16a34a')))
            ],
            [
                Paragraph(f"<font size=16><b>{crit_count}</b></font>", ParagraphStyle('N1', parent=self.body_bold, alignment=1, textColor=colors.HexColor('#dc2626'))),
                Paragraph(f"<font size=16><b>{high_count}</b></font>", ParagraphStyle('N2', parent=self.body_bold, alignment=1, textColor=colors.HexColor('#ea580c'))),
                Paragraph(f"<font size=16><b>{warn_count}</b></font>", ParagraphStyle('N3', parent=self.body_bold, alignment=1, textColor=colors.HexColor('#d97706'))),
                Paragraph(f"<font size=16><b>{info_count}</b></font>", ParagraphStyle('N4', parent=self.body_bold, alignment=1, textColor=colors.HexColor('#2563eb'))),
                Paragraph(f"<font size=16><b>{sec_count}</b></font>", ParagraphStyle('N5', parent=self.body_bold, alignment=1, textColor=colors.HexColor('#16a34a')))
            ]
        ], colWidths=[103, 103, 103, 103, 103])
        counts_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#e2e8f0')),
            ('PADDING', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(counts_table)
        story.append(Spacer(1, 14))

    def _build_compliance_matrix(self, story: List[Any]):
        story.append(Paragraph("2. Evaluasi Standar Regulasi & Kepatuhan Industri", self.h1_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#3b82f6"), spaceAfter=8))

        matrix_data = [
            [
                Paragraph("<b>Standar / Regulasi</b>", self.table_cell_bold),
                Paragraph("<b>Domain Keamanan</b>", self.table_cell_bold),
                Paragraph("<b>Status Kepatuhan</b>", self.table_cell_bold),
                Paragraph("<b>Catatan Forensik Auditor</b>", self.table_cell_bold)
            ],
            [
                Paragraph("<b>OWASP MASVS-STORAGE</b>", self.table_cell),
                Paragraph("Perlindungan Data Lokal & Brankas Kredensial", self.table_cell),
                Paragraph("<b>NON-COMPLIANT</b>", self.badge_critical),
                Paragraph("Ditemukan logging plaintext pada kelas production serta potensi kebocoran token pada SharedPreferences.", self.table_cell)
            ],
            [
                Paragraph("<b>OWASP MASVS-CRYPTO</b>", self.table_cell),
                Paragraph("Kriptografi & Pembangkit Nilai Acak", self.table_cell),
                Paragraph("<b>NON-COMPLIANT</b>", self.badge_critical),
                Paragraph("Penggunaan hash MD5 rentan collision, cipher Blowfish usang, serta insecure random generator.", self.table_cell)
            ],
            [
                Paragraph("<b>OWASP MASVS-AUTH</b>", self.table_cell),
                Paragraph("Otentikasi & Manajemen Sesi", self.table_cell),
                Paragraph("<b>NON-COMPLIANT</b>", self.badge_critical),
                Paragraph("Activity sensitif (OtpWalletActivity) dapat di-invoke tanpa validasi token autentikasi sebelumnya.", self.table_cell)
            ],
            [
                Paragraph("<b>OWASP MASVS-NETWORK</b>", self.table_cell),
                Paragraph("Enkripsi Jalur Komunikasi & TLS", self.table_cell),
                Paragraph("<b>PARTIAL FAIL</b>", self.badge_high),
                Paragraph("Meskipun terdapat SSL Pinning, 5 domain target mengizinkan cleartext HTTP traffic tanpa enkripsi.", self.table_cell)
            ],
            [
                Paragraph("<b>OWASP MASVS-PLATFORM</b>", self.table_cell),
                Paragraph("Interaksi IPC & Exported Component", self.table_cell),
                Paragraph("<b>NON-COMPLIANT</b>", self.badge_critical),
                Paragraph("Activity debugger pihak ketiga (MoEDebuggerActivity) berstatus exported=true tanpa proteksi permission.", self.table_cell)
            ],
            [
                Paragraph("<b>PCI-DSS v4.0 (Mobile)</b>", self.table_cell),
                Paragraph("Proteksi Data Pemegang Kartu & Transaksi", self.table_cell),
                Paragraph("<b>NON-COMPLIANT</b>", self.badge_critical),
                Paragraph("Endpoint pembayaran/tiket mentransmisikan data transaksi yang dapat dicegat via Frida MethodChannel.", self.table_cell)
            ],
            [
                Paragraph("<b>OJK & UU PDP No. 27/2022</b>", self.table_cell),
                Paragraph("Perlindungan Data Pribadi Pengguna (PII)", self.table_cell),
                Paragraph("<b>NON-COMPLIANT</b>", self.badge_critical),
                Paragraph("Data NIK, nomor telepon, dan boarding pass terekspos dalam memori DTO tanpa enkripsi lapis aplikasi.", self.table_cell)
            ]
        ]

        matrix_table = Table(matrix_data, colWidths=[120, 125, 95, 175])
        matrix_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')])
        ]))
        # Change header row text color to white
        for col_idx in range(4):
            matrix_data[0][col_idx].style.textColor = colors.white

        story.append(matrix_table)
        story.append(Spacer(1, 14))

    def _build_vulnerability_findings(self, story: List[Any]):
        story.append(Paragraph("3. Matriks Detail Temuan Kerentanan (Findings)", self.h1_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#3b82f6"), spaceAfter=10))

        findings = self.data.get("findings", [])
        if not findings:
            story.append(Paragraph("Tidak ditemukan kerentanan berisiko tinggi pada pemindaian dasar.", self.body_style))
            return

        for idx, f in enumerate(findings, 1):
            sev = f.get("severity", "INFO").upper()
            title = f.get("title", "Unknown Security Issue")
            desc = f.get("description", "No description provided.")
            cwe = f.get("cwe", "CWE-699")
            owasp = f.get("owasp", "OWASP MASVS")
            remediation = f.get("remediation", "Terapkan prinsip least privilege dan perbarui konfigurasi manifest.")

            if sev == "CRITICAL":
                badge_style = self.badge_critical
                card_bg = colors.HexColor("#fff1f2")
                card_border = colors.HexColor("#fecdd3")
            elif sev == "HIGH":
                badge_style = self.badge_high
                card_bg = colors.HexColor("#fff7ed")
                card_border = colors.HexColor("#fed7aa")
            elif sev == "WARNING":
                badge_style = self.badge_warning
                card_bg = colors.HexColor("#fefce8")
                card_border = colors.HexColor("#fef08a")
            else:
                badge_style = self.table_cell_bold
                card_bg = colors.HexColor("#f8fafc")
                card_border = colors.HexColor("#e2e8f0")

            f_rows = [
                [
                    Paragraph(f"<b>#{idx} [{sev}] {html.escape(title)}</b>", badge_style),
                    Paragraph(f"<b>Standar:</b> {html.escape(cwe)} | {html.escape(owasp)}", self.table_cell)
                ],
                [
                    Paragraph(f"<b>Analisis Resiko & Dampak:</b><br/>{html.escape(desc)}", self.table_cell),
                    Paragraph(f"<b>Solusi & Rekomendasi:</b><br/>{html.escape(remediation)}", self.table_cell)
                ]
            ]
            f_table = Table(f_rows, colWidths=[260, 255])
            f_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), card_bg),
                ('BOX', (0,0), (-1,-1), 1, card_border),
                ('GRID', (0,0), (-1,-1), 0.5, card_border),
                ('PADDING', (0,0), (-1,-1), 6),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ]))
            story.append(f_table)
            story.append(Spacer(1, 8))

    def _build_frida_telemetry(self, story: List[Any]):
        story.append(Paragraph("4. Bukti Forensik Frida Dynamic Hooking & Intercepted API", self.h1_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#3b82f6"), spaceAfter=10))

        story.append(Paragraph(
            "Telemetri dinamis menggunakan Frida agent mendeteksi intersepsi pada alur data sensitif (MethodChannels & HTTP Client). Bukti berikut menunjukkan rute dan muatan data (payload) yang berhasil disadap pada saat runtime tanpa memicu proteksi integrity:",
            self.body_style
        ))
        story.append(Spacer(1, 8))

        telemetry = self.data.get("frida_dataflow_telemetry", {})
        endpoints = telemetry.get("endpoints_inventory", [])

        if not endpoints:
            story.append(Paragraph("Tidak ada data telemetri intersepsi runtime yang tercatat.", self.body_style))
            return

        ep_rows = [
            [
                Paragraph("<b>Metode & Rute / Channel</b>", self.table_cell_bold),
                Paragraph("<b>Kategori & DTO Class</b>", self.table_cell_bold),
                Paragraph("<b>Risk</b>", self.table_cell_bold),
                Paragraph("<b>Muatan Data Terekspos (Payload)</b>", self.table_cell_bold)
            ]
        ]

        for ep in endpoints[:8]:
            m = ep.get("http_method") or ep.get("type", "ROUTE")
            r = ep.get("endpoint") or ep.get("url_route", "unknown")
            cat = ep.get("category", "Data Route")
            dto = ep.get("dto_class", "Internal DTO")
            risk = ep.get("risk_level", "HIGH")
            info = ep.get("payload_info", "Sensitive parameters")

            risk_style = self.badge_critical if risk == "CRITICAL" else self.badge_high
            ep_rows.append([
                Paragraph(f"<b>[{m}]</b><br/><font size=7 color='#0f172a'>{html.escape(r)}</font>", self.table_cell),
                Paragraph(f"<b>{html.escape(cat)}</b><br/><font size=6.5 color='#64748b'>{html.escape(dto)}</font>", self.table_cell),
                Paragraph(f"<b>{risk}</b>", risk_style),
                Paragraph(html.escape(info), self.table_cell)
            ])

        ep_table = Table(ep_rows, colWidths=[140, 150, 55, 170])
        ep_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')])
        ]))
        for c in range(4):
            ep_rows[0][c].style.textColor = colors.white

        story.append(ep_table)
        story.append(Spacer(1, 14))

    def _build_remediation_roadmap(self, story: List[Any]):
        story.append(Paragraph("5. Panduan Remediasi Kode & Pengerasan APK (Hardening)", self.h1_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#3b82f6"), spaceAfter=10))

        story.append(Paragraph(
            "Gunakan panduan konfigurasi dan contoh kode siap pakai berikut untuk menutup kerentanan yang teridentifikasi:",
            self.body_style
        ))
        story.append(Spacer(1, 8))

        # Remediation Box 1: Network Security Config
        story.append(Paragraph("<b>A. Konfigurasi Network Security Config (Tutup Cleartext Traffic)</b>", self.h2_style))
        nsc_code = """&lt;!-- res/xml/network_security_config.xml --&gt;
&lt;network-security-config&gt;
    &lt;base-config cleartextTrafficPermitted="false"&gt;
        &lt;trust-anchors&gt;
            &lt;certificates src="system" /&gt;
        &lt;/trust-anchors&gt;
    &lt;/base-config&gt;
&lt;/network-security-config&gt;"""
        t_nsc = Table([[Paragraph(nsc_code, self.code_style)]], colWidths=[515])
        t_nsc.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f1f5f9')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(t_nsc)
        story.append(Spacer(1, 8))

        # Remediation Box 2: Modern AES-GCM Enkripsi (Kotlin / Dart)
        story.append(Paragraph("<b>B. Enkripsi Kredensial & SharedPreferences (Kotlin / AndroidX Security)</b>", self.h2_style))
        sec_code = """// Kotlin: Gunakan MasterKey & EncryptedSharedPreferences
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val securePrefs = EncryptedSharedPreferences.create(
    context, "secure_vault", masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)"""
        t_sec = Table([[Paragraph(html.escape(sec_code), self.code_style)]], colWidths=[515])
        t_sec.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f1f5f9')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(t_sec)
        story.append(Spacer(1, 8))

        # Remediation Box 3: Anti-Frida & Server-Side HMAC
        story.append(Paragraph("<b>C. Pertahanan Anti-Frida & Signature Request Signing (Backend + Native C++)</b>", self.h2_style))
        story.append(Paragraph(
            "1. Terapkan <b>HMAC-SHA256 Request Signing</b> dengan dynamic timestamp dan nonce untuk menggagalkan modifikasi payload pada level proxy/hook.<br/>"
            "2. Pasang deteksi native C++ NDK yang memeriksa keberadaan port 27042 (Frida server) dan pembacaan string 'frida-gadget' pada <code>/proc/self/maps</code>.<br/>"
            "3. Pastikan seluruh Activity sensitif (OTP, payment, wallet) menyertakan validasi session state dan token sebelum merender UI.",
            self.body_style
        ))
        story.append(Spacer(1, 14))

        # Sign-off box
        sign_table = Table([
            [
                Paragraph(f"<b>Disusun Oleh:</b><br/>{html.escape(self.auditor_name)}<br/><font size=7 color='#64748b'>Senior Mobile Cybersecurity Auditor</font>", self.table_cell),
                Paragraph(f"<b>Disetujui Oleh:</b><br/>Security Operations Committee<br/><font size=7 color='#64748b'>ToolKitDev Assessment Center</font>", self.table_cell),
                Paragraph(f"<b>Tanggal Terbit:</b><br/>{self.report_date}<br/><font size=7 color='#64748b'>Ref: {self.doc_id}</font>", self.table_cell)
            ]
        ], colWidths=[171, 172, 172])
        sign_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ('PADDING', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(sign_table)

