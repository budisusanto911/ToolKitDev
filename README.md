# 🚀 ToolKitDev — Context-Aware AI Developer Platform

> **Pembeda Utama**: AI yang memahami konteks proyek secara holistik (Full Codebase, Git lineage/PRs, Dokumen Arsitektur & ADR, Desain Figma, PRD Google Docs, dan Binary APK), bukan sekadar membaca potongan kode terisolasi.

Dilengkapi dengan antarmuka modern terinspirasi oleh **Codexer.ai v2.0**:
- **Repository Correlation Graph** (Visualisasi interaktif relasi repositori, dependensi, topik, dan celah keamanan)
- **Tri-Metric Scoring Engine** (Security Score, Maintenance Score, Innovation Score)
- **Modul Bedah APK (Mobile Artifact Inspector)** dengan upload mandiri
- **Integrasi Multi-MCP** (GitHub, Docs/ADR, Google Docs, Figma)
- **Pelacak Fitur Terdahulu & Grounded Context Q&A**

---

## 📸 Referensi Desain & Tampilan Dashboard
Platform ini mengimplementasikan visualisasi layout:
- **Sidebar**: Dashboard, Repositories, APK Inspector, MCP & Context, Security & Compliance, Settings.
- **Metric Cards**: Security Score (`0/100`), Maintenance Score (`20/100`), Innovation Score (`100/100`).
- **Interactive Force Graph**:
  - 🔵 **Correlations** (solid blue line)
  - 🔴 **Vulnerabilities** (dashed red line)
  - 🟡 **Dependencies** (solid yellow line)
  - 🟣 **Topics & Tags** (solid purple line)
- **Mobile APK Teardown**: Drag & drop `.apk` langsung ke dropzone untuk audit keamanan seketika!

---

## 🛠️ Cara Menjalankan

### 1. Jalankan Server Lokal
```bash
python3 server.py
```
Server akan aktif di: **`http://localhost:8080`** (atau port yang dispesifikasikan via `PORT=8765 python3 server.py`).

Buka browser kamu dan navigasi ke `http://localhost:8080`.

### 2. Jalankan Automated Test Suite
```bash
python3 test_suite.py
```
Memverifikasi 5 engine suite (APK analyzer, Correlation graph, MCP Hub, Grounded Q&A, dan frontend static assets).

---

## 📱 Fitur Bedah APK (Mobile Security & QA)

Kamu bisa memeriksa keamanan dan kesehatan aplikasi mobile **hanya dengan mengunggah file APK**:
1. **Manifest Security Audit**:
   - `android:debuggable` detection (Mencegah runtime debugging & memory dumping)
   - `android:allowBackup` audit (Mencegah ekstraksi data via ADB)
   - `android:usesCleartextTraffic` check (Mencegah transmisi HTTP unencrypted)
   - **Exported Component Hunter**: Mendeteksi Activity, Service, atau Receiver dengan `android:exported="true"` tanpa permission guard.
2. **Audit Permissions**:
   - Klasifikasi Dangerous Permissions (Kamera, Lokasi background, SMS, Storage) vs Normal.
3. **Secret & Credential Hunter**:
   - Memindai DEX bytecode dan file XML untuk mencari hardcoded Google/Firebase keys, AWS keys, JWT tokens, dan internal endpoints.
4. **Binary & Asset Size Breakdown**:
   - Distribusi persentase DEX code, Native `.so` libraries (per arsitektur CPU), Resources, dan Assets.
5. **Dynamic Mobile Security Score (0-100)**:
   - Skor keamanan dihitung otomatis berdasarkan bobot keparahan celah yang ditemukan.

---

## 🔌 Integrasi Multi-MCP (Model Context Protocol)

- **GitHub MCP**: Menarik struktur codebase, pull requests, issue threads, dan commit diffs.
- **Architecture Docs MCP**: Mengindeks ADR (Architecture Decision Records) dan OpenAPI/Swagger specs.
- **Google Docs MCP**: Membaca spesifikasi bisnis dan acceptance criteria dari PRD.
- **Figma MCP**: Memeriksa hierarki token warna, styling, dan frame desain untuk validasi implementasi UI.

---

## 📂 Struktur Direktori Proyek

```
ToolKitDev/
├── engine/
│   ├── apk_analyzer.py        # Engine dekonstruksi APK, manifest & secret scanner
│   ├── correlation_graph.py   # Generator graph korelasi & scoring tri-matrik
│   ├── mcp_hub.py             # Manajer konektor GitHub, Docs, Figma, GDocs MCP
│   └── context_qa.py          # Grounded Q&A engine & pelacak riwayat fitur
├── public/
│   ├── index.html             # Antarmuka dashboard modern ala Codexer.ai
│   ├── style.css              # Dark theme styling (violet/purple gradient accents)
│   └── app.js                 # Interactive physics force graph & client logic
├── samples/
│   └── sample-debug.apk       # Sample Android binary untuk instant 1-click test
├── uploads/                   # Tempat penampungan upload APK pengguna
├── server.py                  # HTTP server & REST API router
├── test_suite.py              # Test suite validasi engine
└── README.md                  # Dokumentasi proyek
```

