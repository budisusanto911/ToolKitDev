# 🚀 ToolKitDev — Context-Aware Autonomous Mobile DevSecOps Platform

> **Pembeda Utama**: AI yang memahami konteks proyek secara holistik — menghubungkan *Full Codebase*, *Git Ancestry/PRs*, *Dokumen Arsitektur (ADR)*, *Desain Figma*, *PRD*, serta biner aplikasi mobile (**Android APK/AAB & iOS IPA**) dalam satu ruang kerja intelijen terpadu.

Dilengkapi dengan antarmuka modern terinspirasi oleh **Codexer.ai v2.0** dan didukung oleh suite mesin audit otonom:
* **Repository Correlation Graph**: Visualisasi interaktif relasi repositori, dependensi, topik, dan celah keamanan dengan physics force layout.
* **Tri-Metric Scoring Engine**: *Security Score*, *Maintenance Score*, dan *Innovation Score*.
* **Multi-Platform Mobile Teardown**: Inspeksi biner Android (APK/AAB) dan iOS (IPA).
* **APK Version Diff & Regression Audit**: Membandingkan rilis lama vs baru untuk mendeteksi penambahan izin berbahaya dan kebocoran komponen.
* **Software Composition Analysis (SCA)**: Inventaris library pihak ketiga dan pencocokan advisory CVE aktif.
* **1-Click AI Fix Pack Generator**: Otomatis meracik bundel ZIP berisi kode perbaikan siap pasang.
* **Headless CI/CD Scanner CLI**: Runner command-line untuk integrasi pipeline GitHub Actions & GitLab CI.
* **Integrasi Multi-MCP**: Konektor terstandarisasi untuk GitHub, Docs/ADR, Google Docs, dan Figma.

---

## 🎯 Matriks Kapabilitas Fitur

| Fitur | Kategori | Deskripsi | Modul Utama |
| :--- | :---: | :--- | :--- |
| **Mobile SAST & Teardown** | Android / iOS | Audit dekompilasi manifest, ATS, entitlements, DEX size, dan secret scanner | [`apk_analyzer.py`](engine/apk_analyzer.py), [`ipa_analyzer.py`](engine/ipa_analyzer.py) |
| **APK Version Diff** | Delta Audit | Membandingkan 2 rilis APK, menghitung Delta Score, serta mendeteksi regresi keamanan | [`apk_comparator.py`](engine/apk_comparator.py) |
| **SDK & Dependency SCA** | Supply Chain | Memindai 20+ signature SDK mobile dan mencocokkan CVE aktif (NVD / GitHub Advisory) | [`sca_scanner.py`](engine/sca_scanner.py), [`sdk_signatures.json`](engine/sdk_signatures.json) |
| **1-Click AI Fix Pack** | Auto-Remediation | Meracik file ZIP siap pasang (`network_security_config.xml`, `proguard-rules.pro`, helper crypto AES-GCM) | [`fix_pack_generator.py`](engine/fix_pack_generator.py) |
| **iOS (.ipa) Inspector** | Multiplatform | Evaluasi App Transport Security (ATS), MobileProvision, flag Mach-O (PIE, Stack Canaries, ARC) | [`ipa_analyzer.py`](engine/ipa_analyzer.py) |
| **Headless CI/CD Runner** | DevOps Automation | CLI penentu quality gate (exit code 1 jika gagal) untuk pipeline CI/CD | [`cli.py`](cli.py), [`.github/workflows/toolkitdev-audit.yml`](.github/workflows/toolkitdev-audit.yml) |
| **Executive PDF Export** | Compliance | Menghasilkan dokumen laporan resmi berstandar OWASP MASVS, PCI-DSS, & OJK | [`pdf_reporter.py`](engine/pdf_reporter.py) |
| **AI Forensic Chatbot** | Generative AI | Drawer chat interaktif dengan streaming kata-per-kata (SSE) & verifikasi sumber forensik | [`context_qa.py`](engine/context_qa.py), [`ai_forensic_agent.py`](engine/ai_forensic_agent.py) |
| **Dynamic Frida Runner** | Runtime DAST | Template live instrumentation (SSL Pinning bypass, Root evasion, memory key logger) | [`frida_runner.py`](engine/frida_runner.py) |
| **STRIDE Threat Modeling** | Enterprise SecOps | Pemetaan ancaman arsitektural STRIDE, MITRE ATT&CK for Mobile, inherent vs residual risk | [`threat_modeling.py`](engine/threat_modeling.py) |
| **Incident Webhook & SARIF Hub** | Integrasi SIEM | Formatter notifikasi Slack Block Kit, Discord, Jira, serta ekspor standar OASIS SARIF v2.1.0 | [`webhook_notifier.py`](engine/webhook_notifier.py) |

---

## 🛠️ Panduan Penggunaan CLI (`cli.py`)

ToolKitDev menyediakan CLI mandiri untuk audit headless di server maupun CI/CD pipeline:

### 1. Pindai APK, AAB, atau iOS IPA
```bash
python3 cli.py scan uploads/base.apk --fail-on CRITICAL --min-score 50 --fix-pack fixpack.zip --export-pdf audit-report.pdf
```
* **`--fail-on [CRITICAL|HIGH|MEDIUM]`**: Mengembalikan exit code 1 jika ditemukan celah pada tingkat tersebut.
* **`--min-score <0-100>`**: Menggagalkan build jika security score berada di bawah ambang batas.
* **`--fix-pack <path.zip>`**: Otomatis menyimpan berkas patch siap pakai.
* **`--export-pdf <path.pdf>`**: Otomatis menyimpan dokumen PDF resmi.

### 2. Audit Regresi Versi (APK Diff)
```bash
python3 cli.py diff samples/sample-debug.apk uploads/base.apk --fail-on-regression
```
* Mengembalikan exit code 1 jika rilis target mengalami penurunan skor (*score degradation*) atau memperkenalkan regresi celah baru.

### 3. Pindai Dependensi & CVE (SCA)
```bash
python3 cli.py sca uploads/base.apk --fail-on-cve
```
* Mengaudit inventaris library pihak ketiga dan memetakan kerentanan CVE aktif.

---

## 🚀 Menjalankan Server & Antarmuka Web

### 1. Jalankan Server Lokal
```bash
python3 server.py
```
Akses dashboard pada: **`http://localhost:8080`**.

### 2. Jalankan Test Suite Komprehensif (12/12 Engine)
```bash
python3 test_suite.py
```
Memvalidasi seluruh 12 mesin audit (APK Analyzer, Correlation Graph, MCP Hub, Context Q&A, Frontend Assets, APK Diff, Dependency SCA, AI Fix Pack, iOS IPA, Dynamic Frida & CLI, STRIDE Threat Modeling, dan Webhook & SARIF Exporter).

---

## 📂 Struktur Direktori Proyek

```text
ToolKitDev/
├── .github/workflows/
│   └── toolkitdev-audit.yml   # Template GitHub Actions CI/CD Quality Gate
├── cli.py                     # Headless Mobile DevSecOps CLI Runner
├── server.py                  # HTTP Server, SSE Streamer & API Gateway
├── test_suite.py              # Test Suite Validasi 10 Engine
├── engine/
│   ├── apk_analyzer.py        # Dekonstruksi APK/AAB & SAST scanner
│   ├── apk_comparator.py      # Delta audit & APK version regression comparator
│   ├── sca_scanner.py         # Third-party SDK & dependency CVE scanner
│   ├── sdk_signatures.json    # Database signature SDK & advisory CVE
│   ├── fix_pack_generator.py  # 1-Click AI Fix Pack Generator (.zip)
│   ├── ipa_analyzer.py        # iOS IPA teardown & Mach-O binary inspector
│   ├── frida_runner.py        # Dynamic Frida runner & live hook console
│   ├── pdf_reporter.py        # Generator laporan resmi PDF berstandar OJK/OWASP
│   ├── correlation_graph.py   # Visualisasi force graph & Codexer scoring
│   ├── mcp_hub.py             # Manajer konektor Model Context Protocol (MCP)
│   ├── auth_manager.py        # Manajer autentikasi pengguna & session token
│   └── context_qa.py          # Grounded AI Q&A engine
├── public/
│   ├── index.html             # Antarmuka dashboard modern multi-tab
│   ├── style.css              # Dark theme styling & mobile inspector UI
│   └── app.js                 # Logika streaming chat, force graph & event handlers
├── samples/
│   ├── sample-debug.apk       # Sampel biner Android untuk pengujian instan
│   └── sample-ios.ipa         # Sampel biner iOS untuk pengujian instan
└── uploads/                   # Tempat penampungan biner upload pengguna
```

---

## 🌐 Pull Request & Kontribusi

* **Pull Request Aktif**: [PR #1 — feat: Autonomous Mobile DevSecOps Expansion Suite (Phase 2, 3, & 4)](https://github.com/budisusanto911/ToolKitDev/pull/1)
* Seluruh branch fitur telah di-push dan siap di-merge ke branch `main`.
