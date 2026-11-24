#!/usr/bin/env python3
"""
ToolKitDev - Automated APK Security Patcher & Re-Signer Engine
Closes detected Android APK vulnerabilities automatically by:
1. Decoding APK via apktool (fast resource-only mode or full smali mode when needed)
2. Applying targeted security patches to:
   - AndroidManifest.xml (debuggable, allowBackup, usesCleartextTraffic,
     exported debug/sensitive/unprotected components, excess dangerous permissions)
   - res/xml/network_security_config.xml (cleartext domains, user CA certs)
   - Smali bytecode & resources/assets (weak crypto ciphers, hardcoded secrets, staging/actuator URLs)
3. Rebuilding APK via apktool, aligning via zipalign, and signing with an Enterprise Release
   keystore (v1+v2+v3) via apksigner
4. Re-scanning the patched APK via ApkAnalyzer to verify closed vulnerabilities & updated score
"""

import os
import re
import shutil
import tempfile
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, Any, List, Optional, Set, Tuple

from engine.apk_analyzer import ApkAnalyzer, DANGEROUS_PERMISSIONS, SECRET_PATTERNS

ANDROID_NS = "http://schemas.android.com/apk/res/android"
ANDROID_ATTR = f"{{{ANDROID_NS}}}"

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYSTORE_DIR = os.path.join(BASE_DIR, "build", "keystore")
FRAMEWORK_DIR = os.path.join(BASE_DIR, "build", "apktool-framework")
KEYSTORE_PATH = os.path.join(KEYSTORE_DIR, "toolkitdev-release.jks")
KEYSTORE_ALIAS = "toolkitdev-release"
KEYSTORE_PASS = "toolkitdev123"

# Map of supported automated fixes and whether they require full smali decoding
FIX_CATALOG: Dict[str, Dict[str, Any]] = {
    "debuggable": {
        "label": "Disable android:debuggable",
        "needs_smali": False,
        "category": "Manifest",
    },
    "allow_backup": {
        "label": "Disable android:allowBackup",
        "needs_smali": False,
        "category": "Manifest",
    },
    "uses_cleartext_traffic": {
        "label": "Disable android:usesCleartextTraffic",
        "needs_smali": False,
        "category": "Manifest",
    },
    "cleartext_domains": {
        "label": "Enforce HTTPS in Network Security Config",
        "needs_smali": False,
        "category": "Network Security",
    },
    "trusts_user_certs": {
        "label": "Remove User CA Trust Anchors",
        "needs_smali": False,
        "category": "Network Security",
    },
    "debug_activities": {
        "label": "Close Exported Debug Activities",
        "needs_smali": False,
        "category": "Manifest",
    },
    "sensitive_activities": {
        "label": "Close Exported Sensitive Activities",
        "needs_smali": False,
        "category": "Manifest",
    },
    "exported_components": {
        "label": "Close Unprotected Exported Components",
        "needs_smali": False,
        "category": "Manifest",
    },
    "dangerous_permissions": {
        "label": "Prune Excess Dangerous Permissions",
        "needs_smali": False,
        "category": "Permissions",
    },
    "debug_signed": {
        "label": "Re-Sign APK with Release Certificate",
        "needs_smali": False,
        "category": "Signature",
    },
    "weak_crypto": {
        "label": "Upgrade Weak Ciphers (Blowfish/ECB/DES -> AES/GCM)",
        "needs_smali": True,
        "category": "Bytecode",
    },
    "hardcoded_secrets": {
        "label": "Redact Hardcoded Secrets & API Keys",
        "needs_smali": True,
        "category": "Bytecode & Resources",
    },
    "staging_endpoints": {
        "label": "Neutralize Hardcoded Staging / Actuator Endpoints",
        "needs_smali": True,
        "category": "Bytecode & Resources",
    },
    "missing_anti_tamper": {
        "label": "Inject RuntimeGuard (Anti-Root, Anti-Frida, Anti-Emulator, Anti-Debugger)",
        "needs_smali": True,
        "category": "Anti-Tamper / Runtime Guard",
    },
    "obfuscate_structure": {
        "label": "Flatten & Obfuscate APK Resource Paths (aapt2 + Strip Metadata)",
        "needs_smali": False,
        "category": "Anti-Reverse-Engineering",
    },
}

# Permissions prioritized for pruning when dangerous permission count exceeds 5
PRUNE_PRIORITY_PERMISSIONS = [
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.CALL_PHONE",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.GET_ACCOUNTS",
    "android.permission.BODY_SENSORS",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.POST_NOTIFICATIONS",
]

DEBUG_ACTIVITY_RE = re.compile(
    r"(MoEDebuggerActivity|Flipper|Chucker|LeakCanary|DebugActivity|TestActivity|DevActivity)",
    re.IGNORECASE,
)
SENSITIVE_ACTIVITY_RE = re.compile(
    r".*(?:Payment|Checkout|Ovo|Dana|Gopay|Shopee|Binding|Wallet|Pin|Otp|Auth|Transaction|Transfer|ShoppingAssistant).*Activity",
    re.IGNORECASE,
)

RUNTIME_GUARD_SMALI = r""".class public Lcom/toolkitdev/security/RuntimeGuard;
.super Ljava/lang/Object;
.source "RuntimeGuard.java"


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method private static fileExists(Ljava/lang/String;)Z
    .locals 1
    .param p0, "path"    # Ljava/lang/String;

    new-instance v0, Ljava/io/File;

    invoke-direct {v0, p0}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    move-result v0

    return v0
.end method

.method public static isDeviceRooted()Z
    .locals 5

    const/4 v0, 0x1

    const-string v1, "/system/bin/su"

    invoke-static {v1}, Lcom/toolkitdev/security/RuntimeGuard;->fileExists(Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_0

    return v0

    :cond_0
    const-string v1, "/system/xbin/su"

    invoke-static {v1}, Lcom/toolkitdev/security/RuntimeGuard;->fileExists(Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_1

    return v0

    :cond_1
    const-string v1, "/sbin/su"

    invoke-static {v1}, Lcom/toolkitdev/security/RuntimeGuard;->fileExists(Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_2

    return v0

    :cond_2
    const-string v1, "/data/local/xbin/su"

    invoke-static {v1}, Lcom/toolkitdev/security/RuntimeGuard;->fileExists(Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_3

    return v0

    :cond_3
    const-string v1, "/system/app/Superuser.apk"

    invoke-static {v1}, Lcom/toolkitdev/security/RuntimeGuard;->fileExists(Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_4

    return v0

    :cond_4
    const-string v1, "/sbin/.magisk"

    invoke-static {v1}, Lcom/toolkitdev/security/RuntimeGuard;->fileExists(Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_5

    return v0

    :cond_5
    const-string v1, "/data/adb/magisk"

    invoke-static {v1}, Lcom/toolkitdev/security/RuntimeGuard;->fileExists(Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_6

    return v0

    :cond_6
    const-string v1, "/data/adb/ksu"

    invoke-static {v1}, Lcom/toolkitdev/security/RuntimeGuard;->fileExists(Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_7

    return v0

    :cond_7
    const-string v1, "/data/adb/apatch"

    invoke-static {v1}, Lcom/toolkitdev/security/RuntimeGuard;->fileExists(Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_8

    return v0

    :cond_8
    sget-object v1, Landroid/os/Build;->TAGS:Ljava/lang/String;

    if-eqz v1, :cond_9

    const-string v2, "test-keys"

    invoke-virtual {v1, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-eqz v2, :cond_9

    return v0

    :cond_9
    # Anti-Hide-Root: Inspect /proc/self/mounts for Magisk, KernelSU, APatch, debug_ramdisk
    :try_start_0
    new-instance v1, Ljava/io/BufferedReader;

    new-instance v2, Ljava/io/FileReader;

    const-string v3, "/proc/self/mounts"

    invoke-direct {v2, v3}, Ljava/io/FileReader;-><init>(Ljava/lang/String;)V

    invoke-direct {v1, v2}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V

    :cond_a
    invoke-virtual {v1}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_c

    invoke-virtual {v2}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    move-result-object v2

    const-string v3, "magisk"

    invoke-virtual {v2, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v3

    if-nez v3, :cond_b

    const-string v3, "ksu"

    invoke-virtual {v2, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v3

    if-nez v3, :cond_b

    const-string v3, "apatch"

    invoke-virtual {v2, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v3

    if-nez v3, :cond_b

    const-string v3, "debug_ramdisk"

    invoke-virtual {v2, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v3

    if-nez v3, :cond_b

    const-string v3, "core/mirror"

    invoke-virtual {v2, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v3

    if-eqz v3, :cond_a

    :cond_b
    invoke-virtual {v1}, Ljava/io/BufferedReader;->close()V

    return v0

    :cond_c
    invoke-virtual {v1}, Ljava/io/BufferedReader;->close()V
    :try_end_0
    .catch Ljava/lang/Throwable; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    const/4 v4, 0x0

    return v4
.end method

.method public static isHookFrameworkDetected()Z
    .locals 5

    const/4 v0, 0x1

    # 1. Inspect /proc/self/maps for Frida, Zygisk, LSPosed, EdXposed, Riru, Substrate
    :try_start_0
    new-instance v1, Ljava/io/BufferedReader;

    new-instance v2, Ljava/io/FileReader;

    const-string v3, "/proc/self/maps"

    invoke-direct {v2, v3}, Ljava/io/FileReader;-><init>(Ljava/lang/String;)V

    invoke-direct {v1, v2}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V

    :cond_0
    invoke-virtual {v1}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_2

    invoke-virtual {v2}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    move-result-object v2

    const-string v3, "frida-agent"

    invoke-virtual {v2, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v3

    if-nez v3, :cond_1

    const-string v3, "frida-server"

    invoke-virtual {v2, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v3

    if-nez v3, :cond_1

    const-string v3, "gumjs"

    invoke-virtual {v2, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v3

    if-nez v3, :cond_1

    const-string v3, "libfrida"

    invoke-virtual {v2, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v3

    if-nez v3, :cond_1

    const-string v3, "libzygisk"

    invoke-virtual {v2, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v3

    if-nez v3, :cond_1

    const-string v3, "lsposed"

    invoke-virtual {v2, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v3

    if-nez v3, :cond_1

    const-string v3, "edxposed"

    invoke-virtual {v2, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v3

    if-nez v3, :cond_1

    const-string v3, "riru"

    invoke-virtual {v2, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v3

    if-nez v3, :cond_1

    const-string v3, "substrate"

    invoke-virtual {v2, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v3

    if-nez v3, :cond_1

    const-string v3, "libgadget"

    invoke-virtual {v2, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v3

    if-eqz v3, :cond_0

    :cond_1
    invoke-virtual {v1}, Ljava/io/BufferedReader;->close()V

    return v0

    :cond_2
    invoke-virtual {v1}, Ljava/io/BufferedReader;->close()V
    :try_end_0
    .catch Ljava/lang/Throwable; {:try_start_0 .. :try_end_0} :catch_0

    # 2. Inspect /proc/net/tcp for Frida default port 27042 (0x69A2)
    :catch_0
    :try_start_1
    new-instance v1, Ljava/io/BufferedReader;

    new-instance v2, Ljava/io/FileReader;

    const-string v3, "/proc/net/tcp"

    invoke-direct {v2, v3}, Ljava/io/FileReader;-><init>(Ljava/lang/String;)V

    invoke-direct {v1, v2}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V

    :cond_3
    invoke-virtual {v1}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_5

    const-string v3, ":69A2"

    invoke-virtual {v2, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v3

    if-nez v3, :cond_4

    const-string v3, "27042"

    invoke-virtual {v2, v3}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v3

    if-eqz v3, :cond_3

    :cond_4
    invoke-virtual {v1}, Ljava/io/BufferedReader;->close()V

    return v0

    :cond_5
    invoke-virtual {v1}, Ljava/io/BufferedReader;->close()V
    :try_end_1
    .catch Ljava/lang/Throwable; {:try_start_1 .. :try_end_1} :catch_1

    # 3. Runtime check for XposedBridge / LSPosed class loader presence
    :catch_1
    :try_start_2
    const-string v1, "de.robv.android.xposed.XposedBridge"

    invoke-static {v1}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    return v0
    :try_end_2
    .catch Ljava/lang/Throwable; {:try_start_2 .. :try_end_2} :catch_2

    :catch_2
    const/4 v4, 0x0

    return v4
.end method

.method public static isEmulatorDetected()Z
    .locals 3

    const/4 v0, 0x1

    const-string v1, "/dev/qemu_pipe"

    invoke-static {v1}, Lcom/toolkitdev/security/RuntimeGuard;->fileExists(Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_0

    return v0

    :cond_0
    const-string v1, "/dev/socket/qemud"

    invoke-static {v1}, Lcom/toolkitdev/security/RuntimeGuard;->fileExists(Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_1

    return v0

    :cond_1
    sget-object v1, Landroid/os/Build;->FINGERPRINT:Ljava/lang/String;

    if-eqz v1, :cond_3

    invoke-virtual {v1}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    move-result-object v1

    const-string v2, "goldfish"

    invoke-virtual {v1, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_2

    const-string v2, "ranchu"

    invoke-virtual {v1, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_2

    const-string v2, "qemu"

    invoke-virtual {v1, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_2

    const-string v2, "sdk_gphone"

    invoke-virtual {v1, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-eqz v2, :cond_3

    :cond_2
    return v0

    :cond_3
    sget-object v1, Landroid/os/Build;->HARDWARE:Ljava/lang/String;

    if-eqz v1, :cond_5

    invoke-virtual {v1}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    move-result-object v1

    const-string v2, "goldfish"

    invoke-virtual {v1, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_4

    const-string v2, "ranchu"

    invoke-virtual {v1, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_4

    const-string v2, "vbox86p"

    invoke-virtual {v1, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_4

    const-string v2, "nox"

    invoke-virtual {v1, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-eqz v2, :cond_5

    :cond_4
    return v0

    :cond_5
    sget-object v1, Landroid/os/Build;->MODEL:Ljava/lang/String;

    if-eqz v1, :cond_7

    invoke-virtual {v1}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    move-result-object v1

    const-string v2, "sdk_gphone"

    invoke-virtual {v1, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_6

    const-string v2, "genymotion"

    invoke-virtual {v1, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_6

    const-string v2, "bluestacks"

    invoke-virtual {v1, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_6

    const-string v2, "ldplayer"

    invoke-virtual {v1, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-eqz v2, :cond_7

    :cond_6
    return v0

    :cond_7
    const/4 v2, 0x0

    return v2
.end method

.method public static isTracerOrDebuggerAttached()Z
    .locals 5

    const/4 v0, 0x1

    invoke-static {}, Landroid/os/Debug;->isDebuggerConnected()Z

    move-result v1

    if-nez v1, :cond_0

    invoke-static {}, Landroid/os/Debug;->waitingForDebugger()Z

    move-result v1

    if-eqz v1, :cond_1

    :cond_0
    return v0

    :cond_1
    # Kernel procfs TracerPid check (catches ptrace / Frida / GDB attach even when Java Debug API is bypassed)
    :try_start_0
    new-instance v1, Ljava/io/BufferedReader;

    new-instance v2, Ljava/io/FileReader;

    const-string v3, "/proc/self/status"

    invoke-direct {v2, v3}, Ljava/io/FileReader;-><init>(Ljava/lang/String;)V

    invoke-direct {v1, v2}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V

    :cond_2
    invoke-virtual {v1}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_3

    const-string v3, "TracerPid:"

    invoke-virtual {v2, v3}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result v3

    if-eqz v3, :cond_2

    const/16 v3, 0xa

    invoke-virtual {v2, v3}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object v2

    const-string v3, "0"

    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_3

    invoke-virtual {v1}, Ljava/io/BufferedReader;->close()V

    return v0

    :cond_3
    invoke-virtual {v1}, Ljava/io/BufferedReader;->close()V
    :try_end_0
    .catch Ljava/lang/Throwable; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    const/4 v4, 0x0

    return v4
.end method

.method private static hasPackage(Landroid/content/Context;Ljava/lang/String;)Z
    .locals 3
    .param p0, "ctx"    # Landroid/content/Context;
    .param p1, "pkg"    # Ljava/lang/String;

    const/4 v0, 0x0

    if-nez p0, :cond_0

    return v0

    :cond_0
    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v1

    invoke-virtual {v1, p1, v0}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    const/4 v2, 0x1

    return v2
    :try_end_0
    .catch Ljava/lang/Throwable; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    return v0
.end method

.method private static getProp(Ljava/lang/String;)Ljava/lang/String;
    .locals 5
    .param p0, "key"    # Ljava/lang/String;

    :try_start_0
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    move-result-object v0

    const/4 v1, 0x2

    new-array v1, v1, [Ljava/lang/String;

    const/4 v2, 0x0

    const-string v3, "getprop"

    aput-object v3, v1, v2

    const/4 v2, 0x1

    aput-object p0, v1, v2

    invoke-virtual {v0, v1}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;

    move-result-object v0

    new-instance v1, Ljava/io/BufferedReader;

    new-instance v2, Ljava/io/InputStreamReader;

    invoke-virtual {v0}, Ljava/lang/Process;->getInputStream()Ljava/io/InputStream;

    move-result-object v3

    invoke-direct {v2, v3}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V

    invoke-direct {v1, v2}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V

    invoke-virtual {v1}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1}, Ljava/io/BufferedReader;->close()V

    if-eqz v2, :cond_0

    invoke-virtual {v2}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object v2

    return-object v2
    :try_end_0
    .catch Ljava/lang/Throwable; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    :cond_0
    const-string v4, ""

    return-object v4
.end method

.method public static isMagiskOrRootAppInstalled(Landroid/content/Context;)Z
    .locals 2
    .param p0, "ctx"    # Landroid/content/Context;

    const/4 v0, 0x1

    const-string v1, "com.topjohnwu.magisk"

    invoke-static {p0, v1}, Lcom/toolkitdev/security/RuntimeGuard;->hasPackage(Landroid/content/Context;Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_0

    return v0

    :cond_0
    const-string v1, "io.github.vvb2060.magisk"

    invoke-static {p0, v1}, Lcom/toolkitdev/security/RuntimeGuard;->hasPackage(Landroid/content/Context;Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_1

    return v0

    :cond_1
    const-string v1, "me.weishu.kernelsu"

    invoke-static {p0, v1}, Lcom/toolkitdev/security/RuntimeGuard;->hasPackage(Landroid/content/Context;Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_2

    return v0

    :cond_2
    const-string v1, "me.bmax.apatch"

    invoke-static {p0, v1}, Lcom/toolkitdev/security/RuntimeGuard;->hasPackage(Landroid/content/Context;Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_3

    return v0

    :cond_3
    const-string v1, "org.lsposed.manager"

    invoke-static {p0, v1}, Lcom/toolkitdev/security/RuntimeGuard;->hasPackage(Landroid/content/Context;Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_4

    return v0

    :cond_4
    const-string v1, "eu.chainfire.supersu"

    invoke-static {p0, v1}, Lcom/toolkitdev/security/RuntimeGuard;->hasPackage(Landroid/content/Context;Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_5

    return v0

    :cond_5
    # Check bootloader unlocked / verified boot state (orange / flash.locked=0)
    const-string v1, "ro.boot.verifiedbootstate"

    invoke-static {v1}, Lcom/toolkitdev/security/RuntimeGuard;->getProp(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    const-string p0, "orange"

    invoke-virtual {p0, v1}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_6

    return v0

    :cond_6
    const-string v1, "ro.boot.flash.locked"

    invoke-static {v1}, Lcom/toolkitdev/security/RuntimeGuard;->getProp(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    const-string p0, "0"

    invoke-virtual {p0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_7

    return v0

    :cond_7
    const-string v1, "ro.boot.vbmeta.device_state"

    invoke-static {v1}, Lcom/toolkitdev/security/RuntimeGuard;->getProp(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    const-string p0, "unlocked"

    invoke-virtual {p0, v1}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_8

    return v0

    :cond_8
    # Check "which su" execution
    :try_start_0
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    move-result-object v1

    const-string p0, "which su"

    invoke-virtual {v1, p0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;

    move-result-object v1

    new-instance p0, Ljava/io/BufferedReader;

    new-instance v0, Ljava/io/InputStreamReader;

    invoke-virtual {v1}, Ljava/lang/Process;->getInputStream()Ljava/io/InputStream;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V

    invoke-direct {p0, v0}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V

    invoke-virtual {p0}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p0}, Ljava/io/BufferedReader;->close()V

    if-eqz v1, :cond_9

    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v1

    if-lez v1, :cond_9

    const/4 v0, 0x1

    return v0
    :try_end_0
    .catch Ljava/lang/Throwable; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    :cond_9
    const/4 v0, 0x0

    return v0
.end method

.method public static detectThreat(Landroid/content/Context;)Ljava/lang/String;
    .locals 1
    .param p0, "ctx"    # Landroid/content/Context;

    invoke-static {}, Lcom/toolkitdev/security/RuntimeGuard;->isDeviceRooted()Z

    move-result v0

    if-nez v0, :cond_0

    invoke-static {p0}, Lcom/toolkitdev/security/RuntimeGuard;->isMagiskOrRootAppInstalled(Landroid/content/Context;)Z

    move-result v0

    if-eqz v0, :cond_1

    :cond_0
    const-string v0, "Perangkat Root / Magisk / KernelSU / Bootloader Unlocked terdeteksi"

    return-object v0

    :cond_1
    invoke-static {}, Lcom/toolkitdev/security/RuntimeGuard;->isHookFrameworkDetected()Z

    move-result v0

    if-eqz v0, :cond_2

    const-string v0, "Framework Hooking (Frida / LSPosed / Zygisk / Xposed) terdeteksi"

    return-object v0

    :cond_2
    invoke-static {}, Lcom/toolkitdev/security/RuntimeGuard;->isEmulatorDetected()Z

    move-result v0

    if-eqz v0, :cond_3

    const-string v0, "Lingkungan Emulator / Virtual Device terdeteksi"

    return-object v0

    :cond_3
    invoke-static {}, Lcom/toolkitdev/security/RuntimeGuard;->isTracerOrDebuggerAttached()Z

    move-result v0

    if-eqz v0, :cond_4

    const-string v0, "Debugger / Tracer aktif terdeteksi pada perangkat"

    return-object v0

    :cond_4
    const/4 v0, 0x0

    return-object v0
.end method

.method public static terminateApp()V
    .locals 1

    invoke-static {}, Landroid/os/Process;->myPid()I

    move-result v0

    invoke-static {v0}, Landroid/os/Process;->killProcess(I)V

    const/4 v0, 0x0

    invoke-static {v0}, Ljava/lang/System;->exit(I)V

    return-void
.end method

.method public static enforceSecurity(Landroid/content/Context;)V
    .locals 4
    .param p0, "ctx"    # Landroid/content/Context;

    invoke-static {p0}, Lcom/toolkitdev/security/RuntimeGuard;->detectThreat(Landroid/content/Context;)Ljava/lang/String;

    move-result-object v0

    if-nez v0, :cond_0

    return-void

    :cond_0
    const-string v1, "ToolKitDevGuard"

    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    if-eqz p0, :cond_2

    :try_start_0
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Perangkat Anda terdeteksi memiliki masalah keamanan:\n\n\u2022 "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, "\n\nDemi melindungi data dan transaksi Anda, aplikasi tidak dapat dijalankan pada perangkat ini."

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    instance-of v2, p0, Landroid/app/Activity;

    if-eqz v2, :cond_1

    new-instance v2, Landroid/app/AlertDialog$Builder;

    const v3, 0x10302d1

    invoke-direct {v2, p0, v3}, Landroid/app/AlertDialog$Builder;-><init>(Landroid/content/Context;I)V

    const-string v3, "\u26a0\ufe0f Peringatan Keamanan Perangkat"

    invoke-virtual {v2, v3}, Landroid/app/AlertDialog$Builder;->setTitle(Ljava/lang/CharSequence;)Landroid/app/AlertDialog$Builder;

    invoke-virtual {v2, v1}, Landroid/app/AlertDialog$Builder;->setMessage(Ljava/lang/CharSequence;)Landroid/app/AlertDialog$Builder;

    const/4 v3, 0x0

    invoke-virtual {v2, v3}, Landroid/app/AlertDialog$Builder;->setCancelable(Z)Landroid/app/AlertDialog$Builder;

    const-string v3, "Keluar Aplikasi"

    new-instance v1, Lcom/toolkitdev/security/RuntimeGuard$ExitListener;

    invoke-direct {v1}, Lcom/toolkitdev/security/RuntimeGuard$ExitListener;-><init>()V

    invoke-virtual {v2, v3, v1}, Landroid/app/AlertDialog$Builder;->setPositiveButton(Ljava/lang/CharSequence;Landroid/content/DialogInterface$OnClickListener;)Landroid/app/AlertDialog$Builder;

    invoke-virtual {v2}, Landroid/app/AlertDialog$Builder;->show()Landroid/app/AlertDialog;

    return-void

    :cond_1
    const/4 v2, 0x1

    invoke-static {p0, v1, v2}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object v2

    invoke-virtual {v2}, Landroid/widget/Toast;->show()V
    :try_end_0
    .catch Ljava/lang/Throwable; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    :cond_2
    invoke-static {}, Lcom/toolkitdev/security/RuntimeGuard;->terminateApp()V

    return-void
.end method
.method public static install(Landroid/content/Context;)V
    .locals 2
    .param p0, "ctx"    # Landroid/content/Context;

    if-nez p0, :cond_0

    return-void

    :cond_0
    :try_start_0
    instance-of v0, p0, Landroid/app/Application;

    if-eqz v0, :cond_1

    move-object v0, p0

    check-cast v0, Landroid/app/Application;

    new-instance v1, Lcom/toolkitdev/security/RuntimeGuard$GuardCallbacks;

    invoke-direct {v1}, Lcom/toolkitdev/security/RuntimeGuard$GuardCallbacks;-><init>()V

    invoke-virtual {v0, v1}, Landroid/app/Application;->registerActivityLifecycleCallbacks(Landroid/app/Application$ActivityLifecycleCallbacks;)V

    return-void

    :cond_1
    invoke-static {p0}, Lcom/toolkitdev/security/RuntimeGuard;->enforceSecurity(Landroid/content/Context;)V
    :try_end_0
    .catch Ljava/lang/Throwable; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    return-void
.end method
"""

RUNTIME_GUARD_CALLBACKS_SMALI = r""".class public Lcom/toolkitdev/security/RuntimeGuard$GuardCallbacks;
.super Ljava/lang/Object;
.source "RuntimeGuard.java"

# interfaces
.implements Landroid/app/Application$ActivityLifecycleCallbacks;


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onActivityCreated(Landroid/app/Activity;Landroid/os/Bundle;)V
    .locals 0

    return-void
.end method

.method public onActivityStarted(Landroid/app/Activity;)V
    .locals 0

    return-void
.end method

.method public onActivityResumed(Landroid/app/Activity;)V
    .locals 0
    .param p1, "activity"    # Landroid/app/Activity;

    invoke-static {p1}, Lcom/toolkitdev/security/RuntimeGuard;->enforceSecurity(Landroid/content/Context;)V

    return-void
.end method

.method public onActivityPaused(Landroid/app/Activity;)V
    .locals 0

    return-void
.end method

.method public onActivityStopped(Landroid/app/Activity;)V
    .locals 0

    return-void
.end method

.method public onActivitySaveInstanceState(Landroid/app/Activity;Landroid/os/Bundle;)V
    .locals 0

    return-void
.end method

.method public onActivityDestroyed(Landroid/app/Activity;)V
    .locals 0

    return-void
.end method
"""

RUNTIME_GUARD_EXIT_LISTENER_SMALI = r""".class public Lcom/toolkitdev/security/RuntimeGuard$ExitListener;
.super Ljava/lang/Object;
.source "RuntimeGuard.java"

# interfaces
.implements Landroid/content/DialogInterface$OnClickListener;


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onClick(Landroid/content/DialogInterface;I)V
    .locals 0
    .param p1, "dialog"    # Landroid/content/DialogInterface;
    .param p2, "which"    # I

    invoke-static {}, Lcom/toolkitdev/security/RuntimeGuard;->terminateApp()V

    return-void
.end method
"""


def infer_fix_id_from_title(title: str) -> Optional[str]:
    """Map a finding title string (from cached JSON or live scan) to its canonical fix_id."""
    t = (title or "").lower()
    if "debuggable" in t:
        return "debuggable"
    if "debug certificate" in t or "debug signed" in t:
        return "debug_signed"
    if "cleartext http traffic allowed globally" in t or "usescleartexttraffic" in t:
        return "uses_cleartext_traffic"
    if "cleartext traffic allowed for" in t or "staging/target domains" in t:
        return "cleartext_domains"
    if "user-installed ca" in t or "user root ca" in t:
        return "trusts_user_certs"
    if "debug activity" in t or "moedebugger" in t:
        return "debug_activities"
    if "sensitive activities" in t or "unauthenticated access to sensitive" in t:
        return "sensitive_activities"
    if "weak cryptography" in t or "insecure cipher" in t or "blowfish" in t or "ecb" in t:
        return "weak_crypto"
    if "hardcoded secrets" in t or "tokens detected" in t:
        return "hardcoded_secrets"
    if "spring boot actuator" in t or "staging endpoints" in t:
        return "staging_endpoints"
    if "backup enabled" in t or "allowbackup" in t:
        return "allow_backup"
    if "exported components without permissions" in t:
        return "exported_components"
    if "dangerous permissions" in t:
        return "dangerous_permissions"
    if "anti-tamper" in t or "root, frida" in t or "missing root" in t:
        return "missing_anti_tamper"
    return None


class ApkPatcher:
    def __init__(self, apk_path: str, output_dir: Optional[str] = None):
        self.apk_path = os.path.abspath(apk_path)
        if not os.path.isfile(self.apk_path):
            raise FileNotFoundError(f"APK file not found: {self.apk_path}")
        if self.apk_path.lower().endswith(".aab"):
            raise ValueError(
                "Automated binary patching currently supports .apk files. "
                "For .aab bundles, convert to APK via bundletool or download the AI Fix Pack."
            )
        if self.apk_path.lower().endswith(".ipa"):
            raise ValueError("Automated binary patching currently supports Android .apk files only.")
        self.output_dir = output_dir or os.path.dirname(self.apk_path)
        os.makedirs(self.output_dir, exist_ok=True)
        self.logs: List[str] = []

    def _log(self, level: str, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.logs.append(f"[{ts}] [{level}] {msg}")

    def _ensure_release_keystore(self) -> str:
        """Create a persistent RSA-2048 release keystore if one does not exist."""
        os.makedirs(KEYSTORE_DIR, exist_ok=True)
        if os.path.isfile(KEYSTORE_PATH):
            return KEYSTORE_PATH
        self._log("INFO", "Generating ToolKitDev Enterprise Release Keystore (RSA 2048)...")
        cmd = [
            "keytool",
            "-genkeypair",
            "-v",
            "-keystore", KEYSTORE_PATH,
            "-alias", KEYSTORE_ALIAS,
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "10000",
            "-storepass", KEYSTORE_PASS,
            "-keypass", KEYSTORE_PASS,
            "-dname", "CN=ToolKitDev Enterprise Release, OU=AppSec Remediation, O=ToolKitDev, L=Jakarta, S=DKI, C=ID",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            raise RuntimeError(f"keytool failed: {proc.stderr or proc.stdout}")
        return KEYSTORE_PATH

    def _register_xml_namespaces(self, xml_path: str):
        """Parse and register all xmlns:* prefixes from an XML file to preserve them on write."""
        ET.register_namespace("android", ANDROID_NS)
        try:
            with open(xml_path, "r", encoding="utf-8", errors="ignore") as f:
                header = f.read(8192)
            for prefix, uri in re.findall(r'xmlns:([a-zA-Z0-9_\-]+)="([^"]+)"', header):
                ET.register_namespace(prefix, uri)
        except Exception:
            pass

    def _is_launcher_component(self, elem: ET.Element) -> bool:
        """Return True if an <activity> or <activity-alias> has MAIN/LAUNCHER intent-filter."""
        for ifilter in elem.findall("intent-filter"):
            has_main = any(
                a.get(f"{ANDROID_ATTR}name") == "android.intent.action.MAIN"
                for a in ifilter.findall("action")
            )
            has_launcher = any(
                c.get(f"{ANDROID_ATTR}name") == "android.intent.category.LAUNCHER"
                for c in ifilter.findall("category")
            )
            if has_main and has_launcher:
                return True
        return False

    def _patch_manifest(
        self,
        manifest_path: str,
        requested_fixes: Set[str],
        before_analysis: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Apply manifest-level fixes to decoded AndroidManifest.xml."""
        applied: List[Dict[str, Any]] = []
        if not os.path.isfile(manifest_path):
            self._log("WARN", "AndroidManifest.xml not found in decoded directory.")
            return applied

        self._register_xml_namespaces(manifest_path)
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        app_elem = root.find("application")
        modified = False

        # 1. android:debuggable="false"
        if "debuggable" in requested_fixes and app_elem is not None:
            app_elem.set(f"{ANDROID_ATTR}debuggable", "false")
            modified = True
            applied.append({
                "fix_id": "debuggable",
                "status": "patched",
                "file": "AndroidManifest.xml",
                "detail": 'Set android:debuggable="false" on <application>',
            })
            self._log("PATCH", 'AndroidManifest.xml -> android:debuggable="false"')

        # 2. android:allowBackup="false"
        if "allow_backup" in requested_fixes and app_elem is not None:
            app_elem.set(f"{ANDROID_ATTR}allowBackup", "false")
            modified = True
            applied.append({
                "fix_id": "allow_backup",
                "status": "patched",
                "file": "AndroidManifest.xml",
                "detail": 'Set android:allowBackup="false" on <application>',
            })
            self._log("PATCH", 'AndroidManifest.xml -> android:allowBackup="false"')

        # 3. android:usesCleartextTraffic="false"
        if "uses_cleartext_traffic" in requested_fixes and app_elem is not None:
            app_elem.set(f"{ANDROID_ATTR}usesCleartextTraffic", "false")
            modified = True
            applied.append({
                "fix_id": "uses_cleartext_traffic",
                "status": "patched",
                "file": "AndroidManifest.xml",
                "detail": 'Set android:usesCleartextTraffic="false" on <application>',
            })
            self._log("PATCH", 'AndroidManifest.xml -> android:usesCleartextTraffic="false"')

        # 4. Exported Debug Activities
        if "debug_activities" in requested_fixes and app_elem is not None:
            detected_debug = set(
                (before_analysis.get("sensitive_components") or {}).get("debug_activities", [])
            )
            closed_debug: List[str] = []
            for act in app_elem.findall("activity") + app_elem.findall("activity-alias"):
                name = act.get(f"{ANDROID_ATTR}name", "")
                if not name or self._is_launcher_component(act):
                    continue
                if name in detected_debug or DEBUG_ACTIVITY_RE.search(name):
                    act.set(f"{ANDROID_ATTR}exported", "false")
                    for ifilter in list(act.findall("intent-filter")):
                        act.remove(ifilter)
                    closed_debug.append(name)
                    modified = True
            applied.append({
                "fix_id": "debug_activities",
                "status": "patched" if closed_debug else "no_change",
                "file": "AndroidManifest.xml",
                "detail": f"Closed {len(closed_debug)} debug activity(ies): {', '.join(closed_debug[:5])}"
                if closed_debug
                else "No exported debug activities found to close.",
                "items": closed_debug,
            })
            self._log("PATCH", f"Closed {len(closed_debug)} exported debug activity(ies)")

        # 5. Exported Sensitive Activities
        if "sensitive_activities" in requested_fixes and app_elem is not None:
            detected_sens = set(
                (before_analysis.get("sensitive_components") or {}).get("sensitive_activities", [])
            )
            closed_sens: List[str] = []
            for act in app_elem.findall("activity") + app_elem.findall("activity-alias"):
                name = act.get(f"{ANDROID_ATTR}name", "")
                if not name or self._is_launcher_component(act):
                    continue
                if name in detected_sens or SENSITIVE_ACTIVITY_RE.search(name):
                    if not act.get(f"{ANDROID_ATTR}permission"):
                        act.set(f"{ANDROID_ATTR}exported", "false")
                        for ifilter in list(act.findall("intent-filter")):
                            act.remove(ifilter)
                        closed_sens.append(name)
                        modified = True
            applied.append({
                "fix_id": "sensitive_activities",
                "status": "patched" if closed_sens else "no_change",
                "file": "AndroidManifest.xml",
                "detail": f"Protected {len(closed_sens)} sensitive activity(ies) with android:exported=\"false\": {', '.join(closed_sens[:5])}"
                if closed_sens
                else "No unprotected sensitive activities found.",
                "items": closed_sens,
            })
            self._log("PATCH", f"Closed {len(closed_sens)} sensitive activity(ies)")

        # 6. General Unprotected Exported Components (SDK-safe: never break Firebase/Google/AndroidX/Launcher)
        if "exported_components" in requested_fixes and app_elem is not None:
            safe_sdk_prefixes = (
                "androidx.",
                "android.support.",
                "com.google.",
                "com.firebase.",
                "com.android.",
                "com.facebook.",
                "io.flutter.",
            )
            closed_count = 0
            for tag in ("activity", "service", "receiver"):
                for comp in app_elem.findall(tag):
                    cname = comp.get(f"{ANDROID_ATTR}name", "")
                    if tag == "activity" and self._is_launcher_component(comp):
                        continue
                    if any(cname.startswith(pref) for pref in safe_sdk_prefixes):
                        continue
                    if comp.get(f"{ANDROID_ATTR}permission"):
                        continue
                    exp = comp.get(f"{ANDROID_ATTR}exported")
                    has_if = comp.find("intent-filter") is not None
                    if exp == "true" or (exp is None and has_if):
                        comp.set(f"{ANDROID_ATTR}exported", "false")
                        closed_count += 1
                        modified = True
            applied.append({
                "fix_id": "exported_components",
                "status": "patched" if closed_count else "no_change",
                "file": "AndroidManifest.xml",
                "detail": f'Hardened {closed_count} app exported component(s) to android:exported="false" (preserved Firebase/Google/AndroidX/Launcher components to prevent FC)',
            })
            self._log("PATCH", f"Hardened {closed_count} app exported component(s) (SDK-safe)")

        # 7. Prune Excess Dangerous Permissions (down to <= 5)
        if "dangerous_permissions" in requested_fixes:
            perm_elems = list(root.findall("uses-permission"))
            dangerous_elems = [
                el for el in perm_elems
                if el.get(f"{ANDROID_ATTR}name", "") in DANGEROUS_PERMISSIONS
            ]
            removed_perms: List[str] = []
            if len(dangerous_elems) > 5:
                to_remove_count = len(dangerous_elems) - 5
                # Sort by prune priority
                priority_map = {p: idx for idx, p in enumerate(PRUNE_PRIORITY_PERMISSIONS)}
                dangerous_elems.sort(
                    key=lambda el: priority_map.get(el.get(f"{ANDROID_ATTR}name", ""), 999)
                )
                for el in dangerous_elems[:to_remove_count]:
                    pname = el.get(f"{ANDROID_ATTR}name", "")
                    root.remove(el)
                    removed_perms.append(pname)
                    modified = True
            applied.append({
                "fix_id": "dangerous_permissions",
                "status": "patched" if removed_perms else "no_change",
                "file": "AndroidManifest.xml",
                "detail": f"Pruned {len(removed_perms)} excess dangerous permission(s) to meet <=5 threshold: {', '.join(removed_perms[:6])}"
                if removed_perms
                else "Dangerous permission count is already within safe threshold (<=5).",
                "items": removed_perms,
            })
            self._log("PATCH", f"Pruned {len(removed_perms)} excess dangerous permission(s)")

        if modified:
            tree.write(manifest_path, encoding="utf-8", xml_declaration=True)

        return applied

    def _patch_network_security_config(
        self,
        decode_dir: str,
        requested_fixes: Set[str],
    ) -> List[Dict[str, Any]]:
        """Patch res/xml/*network_security*.xml to enforce HTTPS and remove user CA trust."""
        applied: List[Dict[str, Any]] = []
        xml_dir = os.path.join(decode_dir, "res", "xml")
        target_files: List[str] = []

        if os.path.isdir(xml_dir):
            for fname in os.listdir(xml_dir):
                if not fname.endswith(".xml"):
                    continue
                fpath = os.path.join(xml_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
                        content = fp.read()
                    if "network-security-config" in content or "domain-config" in content:
                        target_files.append(fpath)
                except Exception:
                    pass

        if not target_files:
            # Create a hardened network_security_config.xml if none existed
            os.makedirs(xml_dir, exist_ok=True)
            default_cfg = os.path.join(xml_dir, "network_security_config.xml")
            with open(default_cfg, "w", encoding="utf-8") as fp:
                fp.write(
                    '<?xml version="1.0" encoding="utf-8"?>\n'
                    '<network-security-config>\n'
                    '    <base-config cleartextTrafficPermitted="false">\n'
                    '        <trust-anchors>\n'
                    '            <certificates src="system" />\n'
                    '        </trust-anchors>\n'
                    '    </base-config>\n'
                    '</network-security-config>\n'
                )
            target_files.append(default_cfg)
            self._log("PATCH", "Created hardened res/xml/network_security_config.xml")

        for fpath in target_files:
            rel_path = os.path.relpath(fpath, decode_dir)
            try:
                tree = ET.parse(fpath)
                root = tree.getroot()
                changed = False

                if "cleartext_domains" in requested_fixes:
                    domains_hardened: List[str] = []
                    # Remove <domain-config cleartextTrafficPermitted="true"> blocks (staging/cleartext overrides)
                    for parent in list(root.iter()):
                        for child in list(parent):
                            ctag = child.tag.split("}")[-1]
                            if ctag == "domain-config" and child.get("cleartextTrafficPermitted", "").lower() == "true":
                                for d in child.findall("domain"):
                                    if d.text:
                                        domains_hardened.append(d.text.strip())
                                parent.remove(child)
                                changed = True
                    # Enforce cleartextTrafficPermitted="false" on any remaining base-config or domain-config
                    for cfg in root.iter():
                        tag = cfg.tag.split("}")[-1]
                        if tag in ("base-config", "domain-config"):
                            if cfg.get("cleartextTrafficPermitted", "").lower() == "true":
                                cfg.set("cleartextTrafficPermitted", "false")
                                changed = True
                    # Ensure base-config exists with cleartextTrafficPermitted="false"
                    base_cfg = root.find("base-config")
                    if base_cfg is None:
                        base_cfg = ET.SubElement(root, "base-config", {"cleartextTrafficPermitted": "false"})
                        ta = ET.SubElement(base_cfg, "trust-anchors")
                        ET.SubElement(ta, "certificates", {"src": "system"})
                        changed = True
                    else:
                        base_cfg.set("cleartextTrafficPermitted", "false")
                        changed = True

                    applied.append({
                        "fix_id": "cleartext_domains",
                        "status": "patched",
                        "file": rel_path,
                        "detail": f'Removed cleartext <domain-config> overrides for {len(domains_hardened)} domain(s) ({", ".join(domains_hardened[:5])}) and enforced <base-config cleartextTrafficPermitted="false">.'
                        if domains_hardened
                        else 'Enforced <base-config cleartextTrafficPermitted="false">.',
                        "items": domains_hardened,
                    })
                    self._log("PATCH", f'{rel_path} -> removed cleartext overrides ({len(domains_hardened)} domains) & enforced HTTPS-only base-config')

                if "trusts_user_certs" in requested_fixes:
                    removed_user_certs = 0
                    # Remove any <certificates src="user"/> elements
                    for parent in root.iter():
                        for child in list(parent):
                            ctag = child.tag.split("}")[-1]
                            if ctag == "certificates" and child.get("src", "").lower() == "user":
                                parent.remove(child)
                                removed_user_certs += 1
                                changed = True
                    # Also remove <debug-overrides> if it only existed to trust user certs
                    for dbg in list(root.findall("debug-overrides")):
                        root.remove(dbg)
                        changed = True
                    applied.append({
                        "fix_id": "trusts_user_certs",
                        "status": "patched" if removed_user_certs else "no_change",
                        "file": rel_path,
                        "detail": f'Removed {removed_user_certs} <certificates src="user"/> trust anchor(s).',
                    })
                    self._log("PATCH", f"{rel_path} -> removed {removed_user_certs} user CA trust anchor(s)")

                if changed:
                    tree.write(fpath, encoding="utf-8", xml_declaration=True)
            except Exception as e:
                self._log("WARN", f"Failed XML parse on {rel_path}, applying regex fallback: {e}")
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
                    txt = fp.read()
                if "cleartext_domains" in requested_fixes:
                    txt = re.sub(
                        r'cleartextTrafficPermitted\s*=\s*"true"',
                        'cleartextTrafficPermitted="false"',
                        txt,
                        flags=re.IGNORECASE,
                    )
                if "trusts_user_certs" in requested_fixes:
                    txt = re.sub(
                        r'<certificates[^>]*src\s*=\s*"user"[^>]*/?>',
                        "",
                        txt,
                        flags=re.IGNORECASE,
                    )
                with open(fpath, "w", encoding="utf-8") as fp:
                    fp.write(txt)

        return applied

    def _patch_smali_and_resources(
        self,
        decode_dir: str,
        requested_fixes: Set[str],
    ) -> List[Dict[str, Any]]:
        """Patch smali bytecode & resources/assets for weak crypto, hardcoded secrets, and staging endpoints."""
        applied: List[Dict[str, Any]] = []

        # 1. Weak Cryptography (Blowfish / ECB / DES / RC4 -> AES/GCM/NoPadding)
        if "weak_crypto" in requested_fixes:
            patched_files: List[str] = []
            replacements_count = 0

            crypto_subs = [
                (re.compile(r'"(?:AES|DES|DESede|Blowfish)/ECB/[^"]*"', re.IGNORECASE), '"AES/GCM/NoPadding"'),
                (re.compile(r'"(?:DES|DESede|RC4|ARCFOUR)(?:/[^"]*)?"', re.IGNORECASE), '"AES/GCM/NoPadding"'),
                (re.compile(r'"Blowfish(?:/[^"]*)?"', re.IGNORECASE), '"AES"'),
            ]

            for entry in sorted(os.listdir(decode_dir)):
                if not entry.startswith("smali"):
                    continue
                smali_root = os.path.join(decode_dir, entry)
                if not os.path.isdir(smali_root):
                    continue
                for dirpath, _, filenames in os.walk(smali_root):
                    for fn in filenames:
                        if not fn.endswith(".smali"):
                            continue
                        fpath = os.path.join(dirpath, fn)
                        try:
                            with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
                                content = fp.read()
                            # Fast pre-check before running regexes
                            if not any(tok in content for tok in ("Blowfish", "blowfish", "/ECB", "/ecb", '"DES', '"RC4', '"ARCFOUR')):
                                continue
                            new_content = content
                            file_hits = 0
                            for rx, repl in crypto_subs:
                                new_content, n = rx.subn(repl, new_content)
                                file_hits += n
                            if file_hits > 0:
                                with open(fpath, "w", encoding="utf-8") as fp:
                                    fp.write(new_content)
                                replacements_count += file_hits
                                patched_files.append(os.path.relpath(fpath, decode_dir))
                        except Exception:
                            pass

            applied.append({
                "fix_id": "weak_crypto",
                "status": "patched" if replacements_count > 0 else "no_change",
                "file": f"{len(patched_files)} smali file(s)",
                "detail": f"Replaced {replacements_count} insecure cipher literal(s) (Blowfish/ECB/DES/RC4 -> AES/GCM) across {len(patched_files)} smali file(s). Note: verify backend cipher compatibility in QA.",
                "items": patched_files[:10],
            })
            self._log("PATCH", f"Upgraded {replacements_count} weak crypto literal(s) in {len(patched_files)} smali file(s)")

        # 2. Hardcoded Secrets / Tokens Redaction
        if "hardcoded_secrets" in requested_fixes:
            redacted_count = 0
            redacted_files: List[str] = []
            text_exts = (".smali", ".xml", ".json", ".properties", ".txt", ".js", ".cfg", ".conf", ".yaml", ".yml")

            scan_dirs = [
                os.path.join(decode_dir, d)
                for d in os.listdir(decode_dir)
                if d.startswith("smali") or d in ("res", "assets")
            ]

            for sdir in scan_dirs:
                if not os.path.isdir(sdir):
                    continue
                for dirpath, _, filenames in os.walk(sdir):
                    for fn in filenames:
                        if not fn.lower().endswith(text_exts):
                            continue
                        fpath = os.path.join(dirpath, fn)
                        try:
                            with open(fpath, "rb") as fp:
                                raw = fp.read()
                            # Quick pre-filter
                            if not any(marker in raw for marker in (b"AIza", b"AKIA", b"ghp_", b"gho_", b"ghu_", b"ghs_", b"xox", b"PRIVATE KEY", b"eyJ")):
                                continue
                            new_raw = raw
                            file_hits = 0
                            for _, pat in SECRET_PATTERNS:
                                new_raw, n = pat.subn(b"REDACTED_BY_TOOLKITDEV", new_raw)
                                file_hits += n
                            if file_hits > 0:
                                with open(fpath, "wb") as fp:
                                    fp.write(new_raw)
                                redacted_count += file_hits
                                redacted_files.append(os.path.relpath(fpath, decode_dir))
                        except Exception:
                            pass

            applied.append({
                "fix_id": "hardcoded_secrets",
                "status": "patched" if redacted_count > 0 else "no_change",
                "file": f"{len(redacted_files)} file(s)",
                "detail": f"Redacted {redacted_count} hardcoded secret/token occurrence(s) across {len(redacted_files)} file(s). Remember to rotate exposed keys & inject via secure backend/CI.",
                "items": redacted_files[:10],
            })
            self._log("PATCH", f"Redacted {redacted_count} hardcoded secret(s) in {len(redacted_files)} file(s)")

        # 3. Staging / Actuator Endpoints Neutralization
        if "staging_endpoints" in requested_fixes:
            neutralized_count = 0
            neutralized_files: List[str] = []
            actuator_rx = re.compile(rb"https?://[a-zA-Z0-9_\-\.]+(?::[0-9]+)?/actuator(?:/[a-zA-Z0-9_\-]+)?", re.IGNORECASE)
            staging_rx = re.compile(rb"https?://(?:[a-zA-Z0-9_\-]+\.)*(?:staging|stg|uat|dev|sandbox|internal)\.[a-zA-Z0-9_\-\.]+", re.IGNORECASE)

            scan_dirs = [
                os.path.join(decode_dir, d)
                for d in os.listdir(decode_dir)
                if d.startswith("smali") or d in ("res", "assets")
            ]
            for sdir in scan_dirs:
                if not os.path.isdir(sdir):
                    continue
                for dirpath, _, filenames in os.walk(sdir):
                    for fn in filenames:
                        if not fn.endswith((".smali", ".xml", ".json", ".properties")):
                            continue
                        fpath = os.path.join(dirpath, fn)
                        try:
                            with open(fpath, "rb") as fp:
                                raw = fp.read()
                            if b"http" not in raw:
                                continue
                            new_raw, n1 = actuator_rx.subn(b"https://blocked-actuator.invalid", raw)
                            new_raw, n2 = staging_rx.subn(b"https://blocked-staging.invalid", new_raw)
                            if (n1 + n2) > 0:
                                with open(fpath, "wb") as fp:
                                    fp.write(new_raw)
                                neutralized_count += n1 + n2
                                neutralized_files.append(os.path.relpath(fpath, decode_dir))
                        except Exception:
                            pass

            applied.append({
                "fix_id": "staging_endpoints",
                "status": "patched" if neutralized_count > 0 else "no_change",
                "file": f"{len(neutralized_files)} file(s)",
                "detail": f"Neutralized {neutralized_count} staging/actuator URL(s) across {len(neutralized_files)} file(s).",
                "items": neutralized_files[:10],
            })
            self._log("PATCH", f"Neutralized {neutralized_count} staging/actuator endpoint(s)")

        return applied

    def _inject_runtime_guard(self, decode_dir: str, manifest_path: str) -> List[Dict[str, Any]]:
        """
        Inject com.toolkitdev.security.RuntimeGuard Smali class (Anti-Root, Anti-Frida,
        Anti-Emulator, Anti-Debugger) into a dedicated DEX-safe smali directory and hook
        enforceSecurity() into the app's Application.onCreate() or Launcher Activity.onCreate().
        """
        applied: List[Dict[str, Any]] = []

        # 1. Pick target smali directory (avoid 64K method overflow on multi-dex APKs)
        existing_smali = [
            d for d in os.listdir(decode_dir)
            if d == "smali" or re.match(r"^smali_classes\d+$", d)
        ]
        max_idx = 1
        for d in existing_smali:
            m = re.match(r"^smali_classes(\d+)$", d)
            if m:
                max_idx = max(max_idx, int(m.group(1)))

        if len(existing_smali) > 1:
            target_smali_root = f"smali_classes{max_idx + 1}"
        else:
            target_smali_root = "smali"

        guard_rel = os.path.join(target_smali_root, "com", "toolkitdev", "security", "RuntimeGuard.smali")
        guard_abs = os.path.join(decode_dir, guard_rel)
        listener_rel = os.path.join(target_smali_root, "com", "toolkitdev", "security", "RuntimeGuard$ExitListener.smali")
        listener_abs = os.path.join(decode_dir, listener_rel)
        callbacks_rel = os.path.join(target_smali_root, "com", "toolkitdev", "security", "RuntimeGuard$GuardCallbacks.smali")
        callbacks_abs = os.path.join(decode_dir, callbacks_rel)
        os.makedirs(os.path.dirname(guard_abs), exist_ok=True)
        with open(guard_abs, "w", encoding="utf-8") as fp:
            fp.write(RUNTIME_GUARD_SMALI)
        with open(listener_abs, "w", encoding="utf-8") as fp:
            fp.write(RUNTIME_GUARD_EXIT_LISTENER_SMALI)
        with open(callbacks_abs, "w", encoding="utf-8") as fp:
            fp.write(RUNTIME_GUARD_CALLBACKS_SMALI)
        self._log("PATCH", f"Injected {guard_rel} + GuardCallbacks + AlertDialog ExitListener")

        # 2. Add <queries> for Magisk/KernelSU/APatch/LSPosed/SuperSU in AndroidManifest.xml (Android 11+ visibility)
        #    and hook RuntimeGuard.install(this) into Application.onCreate() (preferred so every Activity.onResumed shows popup)
        hooked_target = None
        if os.path.isfile(manifest_path):
            try:
                self._register_xml_namespaces(manifest_path)
                tree = ET.parse(manifest_path)
                root = tree.getroot()
                pkg = root.get("package", "")
                app_elem = root.find("application")

                # Add <queries> packages for root/magisk visibility on Android 11-15
                queries_elem = root.find("queries")
                if queries_elem is None:
                    queries_elem = ET.SubElement(root, "queries")
                existing_qpkgs = {
                    p.get(f"{ANDROID_ATTR}name", "")
                    for p in queries_elem.findall("package")
                }
                root_pkgs = [
                    "com.topjohnwu.magisk",
                    "io.github.vvb2060.magisk",
                    "me.weishu.kernelsu",
                    "me.bmax.apatch",
                    "org.lsposed.manager",
                    "eu.chainfire.supersu",
                ]
                q_added = False
                for rpkg in root_pkgs:
                    if rpkg not in existing_qpkgs:
                        ET.SubElement(queries_elem, "package", {f"{ANDROID_ATTR}name": rpkg})
                        q_added = True
                if q_added:
                    tree.write(manifest_path, encoding="utf-8", xml_declaration=True)
                    self._log("PATCH", "Added <queries> for Magisk/KernelSU/APatch/LSPosed in AndroidManifest.xml")

                candidates: List[str] = []
                if app_elem is not None:
                    # Prefer Application.onCreate() -> registerActivityLifecycleCallbacks so EVERY Activity shows popup on resume!
                    app_name = app_elem.get(f"{ANDROID_ATTR}name", "")
                    if app_name:
                        candidates.append(app_name)
                    for act in app_elem.findall("activity"):
                        if self._is_launcher_component(act):
                            aname = act.get(f"{ANDROID_ATTR}name", "")
                            if aname:
                                candidates.append(aname)
                    for alias in app_elem.findall("activity-alias"):
                        if self._is_launcher_component(alias):
                            tname = alias.get(f"{ANDROID_ATTR}targetActivity", "")
                            if tname:
                                candidates.append(tname)

                # Resolve candidate class names to smali paths
                # Use invoke-static/range {p0 .. p0} (3rc format, 16-bit reg index) so it works
                # even when onCreate() has >= 16 locals (where p0 maps to v16+, e.g. v30).
                hook_line = "    invoke-static/range {p0 .. p0}, Lcom/toolkitdev/security/RuntimeGuard;->install(Landroid/content/Context;)V\n"
                for cname in candidates:
                    if cname.startswith(".") and pkg:
                        fqcn = pkg + cname
                    elif "." not in cname and pkg:
                        fqcn = f"{pkg}.{cname}"
                    else:
                        fqcn = cname
                    rel_smali = fqcn.replace(".", os.sep) + ".smali"

                    for sdir in sorted(existing_smali):
                        candidate_path = os.path.join(decode_dir, sdir, rel_smali)
                        if not os.path.isfile(candidate_path):
                            continue
                        with open(candidate_path, "r", encoding="utf-8", errors="ignore") as fp:
                            content = fp.read()
                        if "Lcom/toolkitdev/security/RuntimeGuard;->install(" in content:
                            hooked_target = f"{fqcn}.onCreate() [already hooked]"
                            break

                        # Inject right after invoke-super / invoke-super/range ...->onCreate(...)V
                        super_re = re.compile(
                            r"(\.method\s+[^\n]*\bonCreate\([^\n]*\)V(?:(?!\.end method)[\s\S])*?invoke-super(?:/range)?\s+\{[^\}]*\},\s*[^\n]*->onCreate\([^\n]*\)V\s*\n)"
                        )
                        new_content, n = super_re.subn(
                            r"\1\n" + hook_line,
                            content,
                            count=1,
                        )
                        if n == 0:
                            oncreate_re = re.compile(
                                r"(\.method\s+[^\n]*\bonCreate\([^\n]*\)V\s*\n(?:\s*\.[^\n]*\n)*?\s*\.(?:locals|registers)\s+\d+\s*\n)"
                            )
                            new_content, n = oncreate_re.subn(
                                r"\1\n" + hook_line,
                                content,
                                count=1,
                            )
                        if n > 0:
                            with open(candidate_path, "w", encoding="utf-8") as fp:
                                fp.write(new_content)
                            hooked_target = f"{fqcn}.onCreate() ({os.path.relpath(candidate_path, decode_dir)})"
                            self._log("PATCH", f"Hooked RuntimeGuard.install(Context) lifecycle guard into {hooked_target}")
                            break
                    if hooked_target:
                        break
            except Exception as e:
                self._log("WARN", f"Could not auto-hook Activity/Application onCreate: {e}")

        detail = (
            f"Injected RuntimeGuard.smali (Root/su/Magisk, Frida 27042/maps, Emulator, Anti-Debugger) into {guard_rel}"
            + (f" and hooked into {hooked_target}." if hooked_target else ".")
        )
        applied.append({
            "fix_id": "missing_anti_tamper",
            "status": "patched",
            "file": guard_rel,
            "detail": detail,
        })
        return applied

    def patch(self, fix_ids: List[str]) -> Dict[str, Any]:
        """
        Execute automated APK patching for the requested fix_ids (or ["all"]).
        Returns before/after scores, patch logs, patched APK path, and full re-scanned analysis.
        """
        self._log("INFO", f"Starting Automated APK Patcher on {os.path.basename(self.apk_path)}")

        # 1. Pre-patch analysis
        before_analysis = ApkAnalyzer(self.apk_path).analyze()
        before_score = before_analysis.get("security_score", 0)
        before_findings = before_analysis.get("findings", [])

        # Resolve requested fixes
        # Note: In "all" mode, apply runtime-safe patches that will NOT cause Force Close (FC)
        # (skip blind DEX Blowfish->AES & Firebase API key redaction unless explicitly requested).
        unsafe_for_batch = {"weak_crypto", "hardcoded_secrets"}
        requested: Set[str] = set()
        skipped_unsafe: List[str] = []
        if not fix_ids or "all" in fix_ids:
            for f in before_findings:
                fid = f.get("fix_id") or infer_fix_id_from_title(f.get("title", ""))
                if fid and fid in FIX_CATALOG:
                    if fid in unsafe_for_batch:
                        skipped_unsafe.append(fid)
                    else:
                        requested.add(fid)
            # Proactively include runtime-safe manifest/network hardening AND RuntimeGuard popup
            # so resource-obfuscated network_security_config.xml, exported_components, and
            # Magisk/Root/Frida/Emulator Popup Guard are always active.
            requested.update({
                "debuggable",
                "allow_backup",
                "uses_cleartext_traffic",
                "cleartext_domains",
                "trusts_user_certs",
                "exported_components",
                "missing_anti_tamper",
            })
            if skipped_unsafe:
                self._log(
                    "INFO",
                    f"Runtime-Safe Mode: skipped {', '.join(skipped_unsafe)} during batch 'all' to prevent Firebase/Crypto Force Close (can still be patched individually or via Fix Pack source code).",
                )
        else:
            for fid in fix_ids:
                resolved = fid if fid in FIX_CATALOG else infer_fix_id_from_title(fid)
                if resolved and resolved in FIX_CATALOG:
                    requested.add(resolved)

        if not requested:
            return {
                "success": False,
                "error": "Tidak ada celah yang dapat di-patch secara otomatis pada pilihan ini.",
                "before_score": before_score,
                "logs": self.logs,
            }

        self._log("INFO", f"Target fixes selected ({len(requested)}): {', '.join(sorted(requested))}")

        # Determine if we need full smali decode or fast resource-only decode
        needs_smali = any(FIX_CATALOG[fid]["needs_smali"] for fid in requested)
        only_resign = requested == {"debug_signed"}

        base_name = os.path.splitext(os.path.basename(self.apk_path))[0]
        # Avoid stacking _patched_patched
        clean_base = re.sub(r"_patched$", "", base_name)
        patched_filename = f"{clean_base}_patched.apk"
        patched_path = os.path.join(self.output_dir, patched_filename)

        work_dir = tempfile.mkdtemp(prefix="toolkitdev_patch_")
        decode_dir = os.path.join(work_dir, "decoded")
        rebuilt_apk = os.path.join(work_dir, "rebuilt.apk")
        aligned_apk = os.path.join(work_dir, "aligned.apk")

        patches_applied: List[Dict[str, Any]] = []

        try:
            if only_resign:
                shutil.copy2(self.apk_path, rebuilt_apk)
                self._log("INFO", "Signature-only remediation selected; skipping apktool decode/rebuild.")
            else:
                # 2. Decode with apktool
                os.makedirs(FRAMEWORK_DIR, exist_ok=True)
                decode_cmd = ["apktool", "d", "-f", "-p", FRAMEWORK_DIR, "-o", decode_dir]
                if not needs_smali:
                    decode_cmd.append("-s")  # Fast mode: skip DEX disassembly
                    self._log("INFO", "Decoding APK via apktool (fast resource/manifest mode -s)...")
                else:
                    self._log("INFO", "Decoding APK via apktool (full smali + resource mode)...")
                decode_cmd.append(self.apk_path)

                proc = subprocess.run(decode_cmd, capture_output=True, text=True, timeout=300)
                if proc.returncode != 0:
                    raise RuntimeError(f"apktool decode failed: {(proc.stderr or proc.stdout)[-800:]}")
                self._log("OK", "APK decoded successfully.")

                # 3. Apply Manifest patches
                manifest_fixes = requested & {
                    "debuggable",
                    "allow_backup",
                    "uses_cleartext_traffic",
                    "debug_activities",
                    "sensitive_activities",
                    "exported_components",
                    "dangerous_permissions",
                }
                if manifest_fixes:
                    manifest_path = os.path.join(decode_dir, "AndroidManifest.xml")
                    patches_applied.extend(self._patch_manifest(manifest_path, manifest_fixes, before_analysis))

                # 4. Apply Network Security Config patches
                netsec_fixes = requested & {"cleartext_domains", "trusts_user_certs"}
                if netsec_fixes:
                    patches_applied.extend(self._patch_network_security_config(decode_dir, netsec_fixes))

                # 5. Apply Smali / Resource patches
                smali_fixes = requested & {"weak_crypto", "hardcoded_secrets", "staging_endpoints"}
                if smali_fixes:
                    patches_applied.extend(self._patch_smali_and_resources(decode_dir, smali_fixes))

                # 5b. Inject RuntimeGuard (Anti-Root, Anti-Frida, Anti-Emulator, Anti-Debugger)
                if "missing_anti_tamper" in requested:
                    manifest_path = os.path.join(decode_dir, "AndroidManifest.xml")
                    patches_applied.extend(self._inject_runtime_guard(decode_dir, manifest_path))

                # 6. Rebuild APK via apktool
                self._log("INFO", "Rebuilding patched APK via apktool b...")
                build_cmd = ["apktool", "b", "-p", FRAMEWORK_DIR, decode_dir, "-o", rebuilt_apk]
                proc = subprocess.run(build_cmd, capture_output=True, text=True, timeout=300)
                if proc.returncode != 0:
                    raise RuntimeError(f"apktool build failed: {(proc.stderr or proc.stdout)[-800:]}")
                self._log("OK", "Patched APK rebuilt successfully.")

                # 6b. Strip build/tooling metadata leakage & flatten/obfuscate res/ folder structure via aapt2
                self._log("INFO", "Obfuscating APK resource paths (aapt2 --enable-resource-path-shortening) & stripping build metadata...")
                optimized_apk = os.path.join(work_dir, "optimized.apk")
                opt_cmd = [
                    "aapt2",
                    "optimize",
                    "--enable-resource-path-shortening",
                    "-o",
                    optimized_apk,
                    rebuilt_apk,
                ]
                opt_proc = subprocess.run(opt_cmd, capture_output=True, text=True, timeout=180)
                if opt_proc.returncode == 0 and os.path.isfile(optimized_apk):
                    # Strip non-essential build metadata files while preserving META-INF/services/ and all runtime files
                    stripped_apk = os.path.join(work_dir, "stripped.apk")
                    stripped_count = 0
                    try:
                        import zipfile as _zf
                        with _zf.ZipFile(optimized_apk, "r") as zin, _zf.ZipFile(stripped_apk, "w") as zout:
                            for item in zin.infolist():
                                name = item.filename
                                is_leak_meta = (
                                    (name.startswith("META-INF/") and name.endswith(".version"))
                                    or name.startswith("META-INF/com/android/build/")
                                    or name in ("kotlin-tooling-metadata.json", "DebugProbesKt.bin")
                                )
                                if is_leak_meta:
                                    stripped_count += 1
                                    continue
                                data = zin.read(name)
                                zout.writestr(item, data, compress_type=item.compress_type)
                        rebuilt_apk = stripped_apk
                    except Exception:
                        rebuilt_apk = optimized_apk

                    patches_applied.append({
                        "fix_id": "obfuscate_structure",
                        "status": "patched",
                        "file": "res/* & META-INF/*",
                        "detail": f"Flattened & obfuscated all res/ folder paths via aapt2 (--enable-resource-path-shortening) and stripped {stripped_count} build metadata file(s).",
                    })
                    self._log("OK", f"Resource paths flattened/obfuscated & {stripped_count} metadata file(s) stripped.")
                else:
                    self._log("WARN", f"aapt2 optimize skipped: {(opt_proc.stderr or opt_proc.stdout)[-200:]}")

            # 7. Zipalign
            self._log("INFO", "Running zipalign (4-byte page alignment)...")
            align_cmd = ["zipalign", "-f", "-p", "4", rebuilt_apk, aligned_apk]
            proc = subprocess.run(align_cmd, capture_output=True, text=True, timeout=120)
            if proc.returncode != 0:
                # Fallback if -p not supported or fails
                align_cmd_fb = ["zipalign", "-f", "4", rebuilt_apk, aligned_apk]
                proc2 = subprocess.run(align_cmd_fb, capture_output=True, text=True, timeout=120)
                if proc2.returncode != 0:
                    raise RuntimeError(f"zipalign failed: {(proc2.stderr or proc2.stdout)[-500:]}")
            self._log("OK", "APK zipaligned.")

            # 8. Sign with Release Keystore (v1 + v2 + v3)
            keystore = self._ensure_release_keystore()
            self._log("INFO", "Signing APK with Enterprise Release Keystore (v1/v2/v3)...")
            sign_cmd = [
                "apksigner",
                "sign",
                "--ks", keystore,
                "--ks-key-alias", KEYSTORE_ALIAS,
                "--ks-pass", f"pass:{KEYSTORE_PASS}",
                "--key-pass", f"pass:{KEYSTORE_PASS}",
                "--v1-signing-enabled", "true",
                "--v2-signing-enabled", "true",
                "--v3-signing-enabled", "true",
                "--out", patched_path,
                aligned_apk,
            ]
            proc = subprocess.run(sign_cmd, capture_output=True, text=True, timeout=180)
            if proc.returncode != 0:
                raise RuntimeError(f"apksigner failed: {(proc.stderr or proc.stdout)[-500:]}")

            if "debug_signed" in requested:
                patches_applied.append({
                    "fix_id": "debug_signed",
                    "status": "patched",
                    "file": "META-INF / APK Signature Block",
                    "detail": "Re-signed APK with RSA-2048 ToolKitDev Enterprise Release Keystore (v1/v2/v3).",
                })

            # Verify signature
            verify_proc = subprocess.run(["apksigner", "verify", patched_path], capture_output=True, text=True, timeout=60)
            signature_verified = verify_proc.returncode == 0
            self._log("OK", f"APK signed & verified (apksigner verify = {signature_verified}).")

            # 9. Re-scan patched APK to prove vulnerabilities are closed
            self._log("INFO", f"Re-scanning {patched_filename} with ApkAnalyzer to verify closure...")
            after_analysis = ApkAnalyzer(patched_path).analyze()
            after_score = after_analysis.get("security_score", 0)
            after_findings = after_analysis.get("findings", [])

            before_titles = {f.get("title") for f in before_findings}
            after_titles = {f.get("title") for f in after_findings}
            closed_findings = [f.get("title") for f in before_findings if f.get("title") not in after_titles]

            self._log(
                "OK",
                f"Verification complete! Score: {before_score} -> {after_score} (+{after_score - before_score} pts). "
                f"Findings: {len(before_findings)} -> {len(after_findings)}.",
            )

            return {
                "success": True,
                "source_file": os.path.basename(self.apk_path),
                "patched_file": patched_filename,
                "patched_path": patched_path,
                "download_url": f"/api/apk/download-patched?file={patched_filename}",
                "signature_verified": signature_verified,
                "before_score": before_score,
                "after_score": after_score,
                "score_delta": after_score - before_score,
                "before_findings_count": len(before_findings),
                "after_findings_count": len(after_findings),
                "closed_findings": closed_findings,
                "patches_applied": patches_applied,
                "logs": self.logs,
                "new_analysis": after_analysis,
            }
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)
