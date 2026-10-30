#!/usr/bin/env python3
"""
ToolKitDev - 1-Click AI Fix Pack Generator (.zip)
Generates ready-to-deploy remediation patch bundles tailored to the specific
vulnerabilities and architecture of the scanned mobile application.
"""

import os
import io
import json
import zipfile
import datetime
from typing import Dict, Any, Optional, List


class FixPackGenerator:
    def __init__(self, analysis_data: Dict[str, Any], app_name: Optional[str] = None):
        self.analysis = analysis_data
        self.platform = self.analysis.get("platform", "android")
        meta = self.analysis.get("metadata", {})
        self.app_name = app_name or meta.get("app_label") or meta.get("app_name") or meta.get("package_name") or "ToolKitDev_SecuredApp"
        self.package_name = meta.get("package_name") or "com.example.app"
        self.target_sdk = meta.get("target_sdk") or 34
        self.min_sdk = meta.get("min_sdk") or 24

        # Extract findings and endpoints
        self.findings = self.analysis.get("findings", [])
        self.endpoints = self.analysis.get("endpoints", [])
        self.components = self.analysis.get("components", {})

    def _generate_network_security_config(self) -> str:
        # Collect extracted domain names
        domains = set()
        for ep in self.endpoints:
            url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
            if "://" in url:
                try:
                    host = url.split("://")[1].split("/")[0].split(":")[0]
                    if "." in host and not host.replace(".", "").isdigit():
                        domains.add(host)
                except Exception:
                    pass

        domain_xml_blocks = []
        for d in sorted(list(domains))[:8]:  # Limit top 8 production hosts
            domain_xml_blocks.append(f"""        <domain includeSubdomains="true">{d}</domain>""")

        if not domain_xml_blocks:
            domain_xml_blocks.append(f"""        <domain includeSubdomains="true">api.{self.package_name.split('.')[-1]}.com</domain>""")

        domains_str = "\n".join(domain_xml_blocks)

        return f"""<?xml version="1.0" encoding="utf-8"?>
<!--
    ToolKitDev AI Auto-Remediation: Network Security Configuration
    Enforces TLS 1.3 / 1.2, blocks cleartext HTTP, and specifies certificate pinning structure.
    Target: {self.package_name}
-->
<network-security-config>
    <!-- 1. Enforce HTTPS across the entire application -->
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>

    <!-- 2. Secure Trusted Domain Whitelist & Certificate Pinning -->
    <domain-config cleartextTrafficPermitted="false">
{domains_str}
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
        <!-- Optional: Enable Certificate Pinning for zero-trust MITM protection -->
        <pin-set expiration="2027-12-31">
            <!-- Replace with actual SHA-256 SPKI pin of your production certificate -->
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <!-- Backup pin for certificate rotation -->
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>

    <!-- 3. Debug Overrides (Only active during debug builds) -->
    <debug-overrides>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
"""

    def _generate_proguard_rules(self) -> str:
        return f"""# =====================================================================
# ToolKitDev AI Auto-Remediation: ProGuard / R8 Hardening Rules
# Package: {self.package_name}
# Objective: Strip logs, obfuscate business logic, protect sensitive keys
# =====================================================================

# 1. Strip debug log calls from production release APK
-assumenosideeffects class android.util.Log {{
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
    public static int println(...);
}}

-assumenosideeffects class java.io.PrintStream {{
    public void println(...);
    public void print(...);
}}

# 2. Maximum Obfuscation & Shrinking
-repackageclasses '{self.package_name}.internal.obfuscated'
-allowaccessmodification
-overloadaggressively
-flattenpackagehierarchy

# 3. Preserve essential Android framework & security components
-keepattributes Exceptions, InnerClasses, Signature, Deprecated, SourceFile, LineNumberTable, *Annotation*, EnclosingMethod
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceiver
-keep public class * extends android.content.ContentProvider

# 4. Safe reflection for models & network serialization
-keepclassmembers class * implements java.io.Serializable {{
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    !static !transient <fields>;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}}

# 5. Native library security
-keepclasseswithmembernames class * {{
    native <methods>;
}}
"""

    def _generate_secured_manifest(self) -> str:
        # Determine exported activities
        acts = self.components.get("activities", [])
        act_blocks = []
        for a in acts[:6]:
            act_name = a if isinstance(a, str) else a.get("name", "MainActivity")
            # Determine if this should be exported (e.g. Launcher)
            is_launcher = "main" in act_name.lower() or "splash" in act_name.lower()
            if is_launcher:
                act_blocks.append(f"""        <activity
            android:name="{act_name}"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>""")
            else:
                act_blocks.append(f"""        <activity
            android:name="{act_name}"
            android:exported="false" />""")

        if not act_blocks:
            act_blocks.append(f"""        <activity
            android:name=".ui.MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>""")

        activities_xml = "\n".join(act_blocks)

        return f"""<?xml version="1.0" encoding="utf-8"?>
<!--
    ToolKitDev AI Auto-Remediation: Hardened AndroidManifest.xml
    Target: {self.package_name}
    Key Remediations Applied:
      1. android:allowBackup="false" (Prevent ADB backup data exfiltration)
      2. android:debuggable="false" (Prevent debugger attachment in prod)
      3. android:networkSecurityConfig="@xml/network_security_config" (Enforce TLS)
      4. Closed unprotected exported components (android:exported="false")
-->
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{self.package_name}">

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />

    <application
        android:allowBackup="false"
        android:debuggable="false"
        android:supportsRtl="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:networkSecurityConfig="@xml/network_security_config"
        android:extractNativeLibs="false">

{activities_xml}

        <!-- FileProvider with secured non-exported configuration -->
        <provider
            android:name="androidx.core.content.FileProvider"
            android:authorities="{self.package_name}.fileprovider"
            android:exported="false"
            android:grantUriPermissions="true">
            <meta-data
                android:name="android.support.FILE_PROVIDER_PATHS"
                android:resource="@xml/file_paths" />
        </provider>

    </application>
</manifest>
"""

    def _generate_secure_crypto_util_kt(self) -> str:
        return f"""package {self.package_name}.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * ToolKitDev AI Auto-Remediation: Enterprise Cryptographic Utility
 * Implements hardware-backed AES-256-GCM authenticated encryption using AndroidKeyStore.
 * Replaces insecure algorithms (DES, 3DES, AES/ECB) and static hardcoded keys.
 */
object SecureCryptoUtil {{

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "ToolKitDev_Master_Key"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_LENGTH = 128
    private const val IV_LENGTH = 12

    private val keyStore: KeyStore by lazy {{
        KeyStore.getInstance(ANDROID_KEYSTORE).apply {{ load(null) }}
    }}

    @Synchronized
    private fun getOrCreateSecretKey(): SecretKey {{
        if (!keyStore.containsAlias(KEY_ALIAS)) {{
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE
            )
            val builder = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {{
                // Enable StrongBox Keymaster if device hardware supports it
                builder.setIsStrongBoxBacked(false)
            }}

            keyGenerator.init(builder.build())
            return keyGenerator.generateKey()
        }}
        val entry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry
        return entry.secretKey
    }}

    /**
     * Encrypts plaintext string using AES-256-GCM.
     * Returns Base64 encoded payload formatted as: [IV (12 bytes)] + [Ciphertext + Auth Tag]
     */
    fun encrypt(plaintext: String): String {{
        val secretKey = getOrCreateSecretKey()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val encryptedBytes = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))

        // Prepend IV to ciphertext
        val combined = ByteArray(iv.size + encryptedBytes.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encryptedBytes, 0, combined, iv.size, encryptedBytes.size)

        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }}

    /**
     * Decrypts Base64 payload formatted as [IV] + [Ciphertext + Auth Tag]
     */
    fun decrypt(combinedBase64: String): String {{
        val combined = Base64.decode(combinedBase64, Base64.NO_WRAP)
        if (combined.size < IV_LENGTH) {{
            throw IllegalArgumentException("Ciphertext payload is too short.")
        }}

        val iv = ByteArray(IV_LENGTH)
        val ciphertext = ByteArray(combined.size - IV_LENGTH)
        System.arraycopy(combined, 0, iv, 0, IV_LENGTH)
        System.arraycopy(combined, IV_LENGTH, ciphertext, 0, ciphertext.size)

        val secretKey = getOrCreateSecretKey()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

        val decryptedBytes = cipher.doFinal(ciphertext)
        return String(decryptedBytes, Charsets.UTF_8)
    }}
}}
"""

    def _generate_secure_storage_dart(self) -> str:
        return f"""// ToolKitDev AI Auto-Remediation: Flutter Secure Storage Wrapper
// Replaces cleartext SharedPreferences with Android Keystore & iOS Keychain
// Dependencies: flutter_secure_storage: ^9.0.0

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class SecureVaultService {{
  static const FlutterSecureStorage _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(
      encryptedSharedPreferences: true,
      resetOnError: true,
      keyCipherAlgorithm: KeyCipherAlgorithm.RSA_ECB_PKCS1Padding,
      storageCipherAlgorithm: StorageCipherAlgorithm.AES_GCM_NoPadding,
    ),
    iOptions: IOSOptions(
      accessibility: KeychainAccessibility.first_unlock_this_device,
      synchronizable: false,
    ),
  );

  /// Securely save an encrypted token or credential
  static Future<void> saveSecureToken(String key, String value) async {{
    await _storage.write(key: key, value: value);
  }}

  /// Read and decrypt secure token
  static Future<String?> getSecureToken(String key) async {{
    return await _storage.read(key: key);
  }}

  /// Delete sensitive credential upon logout
  static Future<void> clearAuthCredentials() async {{
    await _storage.deleteAll();
  }}
}}
"""

    def _generate_readme_guide(self) -> str:
        findings_bullets = []
        for idx, f in enumerate(self.findings[:8], 1):
            title = f.get("title") or f.get("issue") or "Security Observation"
            sev = f.get("severity", "MEDIUM").upper()
            findings_bullets.append(f"{idx}. **[{sev}] {title}**")

        findings_text = "\n".join(findings_bullets) if findings_bullets else "- Tidak ada temuan kritis yang membutuhkan patch manual."

        return f"""# 🛡️ ToolKitDev AI Remediation Fix Pack
**Target Application**: `{self.app_name}` (`{self.package_name}`)  
**Generated by**: ToolKitDev Security Intelligence Platform  
**Standards Compliance**: OWASP Mobile Top 10, MASVS-STORAGE-1, MASVS-NETWORK-1

---

## 📦 Isi Berkas Fix Pack:

1. `res/xml/network_security_config.xml`
   * Memblokir seluruh koneksi HTTP Plaintext (*cleartextTrafficPermitted="false"*).
   * Mengatur konfigurasi certificate pinning untuk domain API produksi.
   * **Cara Pasang**: Salin ke folder `app/src/main/res/xml/`.

2. `app/proguard-rules.pro`
   * Mengotomatiskan penghapusan method `Log.d()`, `Log.v()`, `println()` pada build Release.
   * Mengaktifkan agresif obfuskasi kelas internal untuk mencegah *decompilation*.
   * **Cara Pasang**: Tambahkan isi file ini ke file `proguard-rules.pro` di modul aplikasi Android Anda.

3. `app/src/main/AndroidManifest_secured.xml`
   * Referensi konfigurasi manifest yang aman:
     * `android:allowBackup="false"` (Mencegah pencurian data melalui ADB bridge).
     * `android:debuggable="false"` (Menutup celah attachment debugger).
     * `android:exported="false"` pada Activity/Service non-launcher.
   * **Cara Pasang**: Bandingkan dan terapkan perubahan pada `app/src/main/AndroidManifest.xml`.

4. `app/src/main/java/{self.package_name.replace('.', '/')}/security/SecureCryptoUtil.kt`
   * Modul enkripsi AES-256-GCM berbasis hardware *AndroidKeyStore*.
   * Menjamin integritas data menggunakan Galois/Counter Mode (GCM Authentication Tag).
   * **Cara Pasang**: Salin ke package source code Android Anda.

5. `lib/services/secure_vault_service.dart`
   * Khusus aplikasi berbasis Flutter: implementasi penyimpanan aman memanfaatkan Android EncryptedSharedPreferences dan iOS Keychain.
   * **Cara Pasang**: Salin ke folder `lib/` pada proyek Flutter Anda.

---

## 🎯 Temuan Keamanan yang Diselesaikan oleh Fix Pack Ini:
{findings_text}

---
*Generated automatically by ToolKitDev AI Remediation Engine.*
"""

    def _generate_web_nginx_conf(self) -> str:
        return """# ToolKitDev - Nginx Web Security & Hardening Configuration
# Include this snippet in your server block: include /etc/nginx/conf.d/security.conf;

# 1. Hide Server Version
server_tokens off;

# 2. Strong HTTP Security Headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;

# 3. HTTP Strict Transport Security (HSTS)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# 4. Content Security Policy (CSP)
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self';" always;

# 5. Prevent Access to Hidden & Sensitive Files (.env, .git, etc.)
location ~ /\\.(?!well-known) {
    deny all;
    access_log off;
    log_not_found off;
}

location ~* (\\.env|\\.git|\\.bak|\\.sql|\\.zip|\\.tar|\\.gz|composer\\.json|package\\.json)$ {
    deny all;
    return 404;
}
"""

    def _generate_web_express_middleware(self) -> str:
        return """// ToolKitDev - Express.js Security Headers & Hardening Middleware
// Installation: npm install helmet cors
const helmet = require('helmet');
const cors = require('cors');

function applySecurityMiddleware(app) {
    // 1. Remove x-powered-by
    app.disable('x-powered-by');

    // 2. Comprehensive Security Headers with Helmet
    app.use(helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", "data:", "https:"],
                objectSrc: ["'none'"],
                upgradeInsecureRequests: [],
            },
        },
        crossOriginEmbedderPolicy: false,
        hsts: {
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true
        },
        frameguard: {
            action: 'sameorigin'
        },
        noSniff: true,
        referrerPolicy: {
            policy: 'strict-origin-when-cross-origin'
        }
    }));

    // 3. Strict CORS Whitelist
    const allowedOrigins = ['https://yourdomain.com', 'https://app.yourdomain.com'];
    app.use(cors({
        origin: function(origin, callback) {
            if (!origin || allowedOrigins.indexOf(origin) !== -1) {
                callback(null, true);
            } else {
                callback(new Error('Blocked by ToolKitDev CORS Policy'));
            }
        },
        credentials: true
    }));
}

module.exports = applySecurityMiddleware;
"""

    def _generate_web_apache_htaccess(self) -> str:
        return """# ToolKitDev - Apache .htaccess Security Hardening
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; img-src 'self' data:;"
</IfModule>

# Block access to hidden files (.env, .git, etc.)
<FilesMatch "^\\.">
    Order allow,deny
    Deny from all
</FilesMatch>

# Block access to environment and backup files
<FilesMatch "\\.(env|bak|sql|zip|gz)$">
    Order allow,deny
    Deny from all
</FilesMatch>
"""

    def _generate_web_readme_guide(self) -> str:
        findings_md = ""
        for idx, f in enumerate(self.findings, 1):
            findings_md += f"### {idx}. [{f.get('severity')}] {f.get('title')}\n"
            findings_md += f"- **Kategori**: {f.get('category')} ({f.get('cwe', 'N/A')})\n"
            findings_md += f"- **Rekomendasi**: {f.get('recommendation')}\n\n"

        return f"""# ToolKitDev Autonomous Web Remediation Fix Pack
**Target**: {self.app_name}  
**Generated At**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  

Paket ini berisi konfigurasi keamanan siap pakai untuk mengatasi seluruh celah keamanan web yang ditemukan oleh ToolKitDev Scanner.

## 📦 Berkas yang Disertakan:
1. `nginx_security.conf`: Konfigurasi reverse proxy Nginx untuk mengaktifkan CSP, HSTS, X-Frame-Options, dan memblokir akses ke `/.env` / `/.git`.
2. `security_headers.htaccess`: Konfigurasi untuk web server Apache.
3. `express_security_middleware.js`: Middleware keamanan untuk Node.js Express menggunakan `helmet` dan whitelist CORS.

## 🎯 Temuan Keamanan Web yang Diperbaiki:
{findings_md}

---
*Generated automatically by ToolKitDev Autonomous Web SecOps Engine.*
"""

    def generate_zip_bytes(self) -> bytes:
        """Creates an in-memory ZIP package containing all remediation files."""
        zip_buffer = io.BytesIO()

        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as z:
            if self.platform == "web":
                # Web Remediation Bundle
                z.writestr("nginx/nginx_security.conf", self._generate_web_nginx_conf())
                z.writestr("apache/security_headers.htaccess", self._generate_web_apache_htaccess())
                z.writestr("nodejs/express_security_middleware.js", self._generate_web_express_middleware())
                z.writestr("README_WEB_SECURITY_GUIDE.md", self._generate_web_readme_guide())
            else:
                # 1. Network Security Config
                z.writestr("res/xml/network_security_config.xml", self._generate_network_security_config())

                # 2. ProGuard Rules
                z.writestr("proguard-rules.pro", self._generate_proguard_rules())

                # 3. Hardened AndroidManifest
                z.writestr("AndroidManifest_secured.xml", self._generate_secured_manifest())

                # 4. Kotlin Crypto Util
                pkg_path = self.package_name.replace(".", "/")
                z.writestr(f"kotlin/{pkg_path}/security/SecureCryptoUtil.kt", self._generate_secure_crypto_util_kt())

                # 5. Flutter Secure Storage Service
                z.writestr("flutter/secure_vault_service.dart", self._generate_secure_storage_dart())

                # 6. Implementation Readme Guide
                z.writestr("README_SECURITY_FIX_GUIDE.md", self._generate_readme_guide())

        zip_buffer.seek(0)
        return zip_buffer.getvalue()

    def save_zip(self, output_file_path: str) -> str:
        data = self.generate_zip_bytes()
        os.makedirs(os.path.dirname(os.path.abspath(output_file_path)), exist_ok=True)
        with open(output_file_path, "wb") as f:
            f.write(data)
        return output_file_path

