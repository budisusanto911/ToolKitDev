#!/usr/bin/env python3
"""
Builds ToolKitDev RuntimeGuard v2 prebuilt artifacts:
1. Native multi-ABI shared libraries (libtkdguard.so) for arm64-v8a, armeabi-v7a, x86, x86_64
   using Android NDK clang with 16KB page-size alignment (Android 15 compatible).
2. Verified Smali bytecode for com.toolkitdev.security.RuntimeGuard (+ inner classes)
   compiled via javac -> d8 -> apktool baksmali.
"""

import os
import glob
import shutil
import zipfile
import tempfile
import subprocess

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
NATIVE_SRC = os.path.join(SCRIPT_DIR, "native", "tkdguard.c")
JAVA_SRC = os.path.join(SCRIPT_DIR, "java", "com", "toolkitdev", "security", "RuntimeGuard.java")
PREBUILT_DIR = os.path.join(SCRIPT_DIR, "prebuilt")
PREBUILT_LIB_DIR = os.path.join(PREBUILT_DIR, "lib")
PREBUILT_SMALI_DIR = os.path.join(PREBUILT_DIR, "smali")

def resolve_sdk_root() -> str:
    candidates = [
        os.environ.get("ANDROID_HOME") or "",
        os.environ.get("ANDROID_SDK_ROOT") or "",
        os.path.expanduser("~/Android/Sdk"),
        os.path.expanduser("~/Android/SDK"),
        "/usr/lib/android-sdk",
    ]
    for c in candidates:
        if c and os.path.isdir(os.path.join(c, "ndk")):
            return c
    for c in candidates:
        if c and os.path.isdir(c):
            return c
    return os.path.expanduser("~/Android/Sdk")


SDK_ROOT = resolve_sdk_root()

ABI_TARGETS = {
    "arm64-v8a":   ("aarch64-linux-android21-clang",     True),
    "armeabi-v7a": ("armv7a-linux-androideabi21-clang",  False),
    "x86":         ("i686-linux-android21-clang",        False),
    "x86_64":      ("x86_64-linux-android21-clang",      True),
}


def find_ndk_bin() -> str:
    ndk_root = os.path.join(SDK_ROOT, "ndk")
    if os.path.isdir(ndk_root):
        versions = sorted(os.listdir(ndk_root), reverse=True)
        for v in versions:
            candidate = os.path.join(ndk_root, v, "toolchains", "llvm", "prebuilt", "linux-x86_64", "bin")
            if os.path.isdir(candidate):
                return candidate
    raise RuntimeError(f"Android NDK LLVM toolchain not found under {ndk_root}")


def find_android_jar() -> str:
    platforms = sorted(glob.glob(os.path.join(SDK_ROOT, "platforms", "android-*", "android.jar")), reverse=True)
    if not platforms:
        raise RuntimeError(f"android.jar not found under {SDK_ROOT}/platforms")
    return platforms[0]


def find_d8() -> str:
    d8s = sorted(glob.glob(os.path.join(SDK_ROOT, "build-tools", "*", "d8")), reverse=True)
    if not d8s:
        raise RuntimeError(f"d8 not found under {SDK_ROOT}/build-tools")
    return d8s[0]


def build_native():
    ndk_bin = find_ndk_bin()
    llvm_strip = os.path.join(ndk_bin, "llvm-strip")
    print(f"[*] Using NDK toolchain: {ndk_bin}")

    for abi, (compiler_name, is_64bit) in ABI_TARGETS.items():
        cc = os.path.join(ndk_bin, compiler_name)
        if not os.path.isfile(cc):
            raise RuntimeError(f"Compiler not found: {cc}")
        out_dir = os.path.join(PREBUILT_LIB_DIR, abi)
        os.makedirs(out_dir, exist_ok=True)
        out_so = os.path.join(out_dir, "libtkdguard.so")

        cmd = [
            cc,
            "-shared",
            "-fPIC",
            "-O2",
            "-Wall",
            "-Wextra",
            "-fvisibility=hidden",
            "-ffunction-sections",
            "-fdata-sections",
            "-Wl,--gc-sections",
            "-Wl,-z,relro,-z,now",
            "-Wl,-z,noexecstack",
        ]
        if is_64bit:
            # 16KB ELF segment alignment for Android 15+ 16KB page-size devices
            cmd.append("-Wl,-z,max-page-size=16384")
        cmd += [NATIVE_SRC, "-llog", "-o", out_so]

        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"Failed compiling {abi}:\n{proc.stderr}\n{proc.stdout}")

        if os.path.isfile(llvm_strip):
            subprocess.run([llvm_strip, "--strip-unneeded", out_so], check=True)

        size_kb = os.path.getsize(out_so) / 1024.0
        print(f"  [OK] Built {abi}/libtkdguard.so ({size_kb:.1f} KB)")


def build_smali():
    android_jar = find_android_jar()
    d8_bin = find_d8()
    print(f"[*] Using android.jar: {android_jar}")
    print(f"[*] Using d8: {d8_bin}")

    work = tempfile.mkdtemp(prefix="tkdguard_build_")
    try:
        classes_dir = os.path.join(work, "classes")
        dex_dir = os.path.join(work, "dex")
        os.makedirs(classes_dir, exist_ok=True)
        os.makedirs(dex_dir, exist_ok=True)

        # 1. Compile Java source targeting Java 8 bytecode for universal Android compatibility
        javac_cmd = [
            "javac",
            "-source", "8",
            "-target", "8",
            "-Xlint:-options",
            "-cp", android_jar,
            "-d", classes_dir,
            JAVA_SRC,
        ]
        proc = subprocess.run(javac_cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"javac failed:\n{proc.stderr}\n{proc.stdout}")

        class_files = []
        for root, _, files in os.walk(classes_dir):
            for f in files:
                if f.endswith(".class"):
                    class_files.append(os.path.join(root, f))
        print(f"  [OK] javac produced {len(class_files)} class file(s)")

        # 2. Convert .class -> classes.dex via d8 (--min-api 21)
        d8_cmd = [
            d8_bin,
            "--min-api", "21",
            "--lib", android_jar,
            "--output", dex_dir,
        ] + class_files
        proc = subprocess.run(d8_cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"d8 failed:\n{proc.stderr}\n{proc.stdout}")

        dex_path = os.path.join(dex_dir, "classes.dex")
        if not os.path.isfile(dex_path):
            raise RuntimeError("d8 did not produce classes.dex")

        # 3. Disassemble classes.dex -> verified smali using apktool's embedded baksmali
        # Build a minimal stub apk containing classes.dex and decode smali with apktool
        stub_apk = os.path.join(work, "stub.apk")
        with zipfile.ZipFile(stub_apk, "w", zipfile.ZIP_STORED) as z:
            z.write(dex_path, "classes.dex")

        decoded = os.path.join(work, "decoded")
        proc = subprocess.run(
            ["apktool", "d", "-f", "-r", "-o", decoded, stub_apk],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"apktool baksmali decode failed:\n{proc.stderr}\n{proc.stdout}")

        src_smali = os.path.join(decoded, "smali", "com", "toolkitdev", "security")
        if not os.path.isdir(src_smali):
            raise RuntimeError(f"Expected smali dir missing: {src_smali}")

        if os.path.isdir(PREBUILT_SMALI_DIR):
            shutil.rmtree(PREBUILT_SMALI_DIR)
        dst_smali = os.path.join(PREBUILT_SMALI_DIR, "com", "toolkitdev", "security")
        shutil.copytree(src_smali, dst_smali)

        smali_files = sorted(os.listdir(dst_smali))
        print(f"  [OK] Generated {len(smali_files)} verified Smali file(s): {', '.join(smali_files)}")
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    build_native()
    build_smali()
    print("[DONE] RuntimeGuard v2 prebuilt native + smali artifacts ready.")
