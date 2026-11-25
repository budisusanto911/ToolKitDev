package com.toolkitdev.security;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Application;
import android.content.ContentResolver;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.os.Debug;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.provider.Settings;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * ToolKitDev RuntimeGuard v2.1 — Multi-Layer Anti-Root, Anti-Frida, Anti-Zygisk & Anti-Hide RASP
 *
 * Policy:
 * - Developer Options / USB Debugging alone are ALLOWED so normal users & QA are not blocked.
 * - Strictly BLOCKS Root (Magisk, KernelSU, KSU-Next, SukiSU, APatch, SuperSU),
 *   Root Hiding & Attestation Spoofers (Shamiko, Zygisk, Zygisk-Next, ReZygisk, Hide My Applist,
 *   TrickyStore, PlayIntegrityFix), Frida (active D-Bus port probe + maps + threads + fds),
 *   LSPosed / Xposed / Inline Memory Hooking (/proc/self/smaps dirty .text),
 *   Bootloader Unlocked (Hardware TEE Key Attestation + vbmeta.digest cross-check),
 *   SELinux Permissive, Active Debugger/Tracer (TracerPid), and Emulators.
 */
public class RuntimeGuard {

    private static final String TAG = "ToolKitDevGuard";

    /* Bitmask flags synchronized with native tkdguard.c */
    private static final int FLAG_ROOT_BINARY     = 1 << 0;
    private static final int FLAG_ROOT_MOUNT      = 1 << 1;
    private static final int FLAG_HIDDEN_ROOT_APP = 1 << 2;
    private static final int FLAG_BOOTLOADER_PROP = 1 << 3;
    private static final int FLAG_HOOK_FRAMEWORK  = 1 << 4;
    private static final int FLAG_DEBUGGER_TRACER = 1 << 5;
    private static final int FLAG_EMULATOR        = 1 << 6;
    private static final int FLAG_SELINUX_TAMPER  = 1 << 7;
    private static final int FLAG_MEMORY_HOOK     = 1 << 8;
    private static final int FLAG_FRIDA_ACTIVE    = 1 << 9;

    private static volatile boolean sNativeLoaded = false;
    private static volatile boolean sInstalled = false;
    private static volatile boolean sAttestationChecked = false;
    private static volatile String sCachedAttestationThreat = null;
    private static volatile boolean sKillScheduled = false;
    private static volatile int sDialogShownActivityHash = 0;

    static {
        try {
            System.loadLibrary("tkdguard");
            sNativeLoaded = true;
        } catch (Throwable t) {
            sNativeLoaded = false;
            Log.e(TAG, "Native guard load failed: " + t.getMessage());
        }
    }

    private static native int nativeScan();
    private static native String nativeScanDetails();
    private static native String nativeGetProp(String key);
    private static native void nativeHardTerminate();

    private static boolean fileExists(String path) {
        try {
            return new File(path).exists();
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean hasPackage(Context ctx, String pkg) {
        if (ctx == null || pkg == null) return false;
        try {
            ctx.getPackageManager().getPackageInfo(pkg, 0);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static String getProp(String key) {
        if (sNativeLoaded) {
            try {
                String v = nativeGetProp(key);
                if (v != null && v.length() > 0) return v.trim();
            } catch (Throwable ignored) {}
        }
        BufferedReader br = null;
        try {
            java.lang.Process p = Runtime.getRuntime().exec(new String[]{"getprop", key});
            br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line = br.readLine();
            if (line != null) return line.trim();
        } catch (Throwable ignored) {
        } finally {
            if (br != null) {
                try { br.close(); } catch (Throwable ignored) {}
            }
        }
        return "";
    }

    private static String toHexLower(byte[] bytes) {
        if (bytes == null) return "";
        char[] hex = "0123456789abcdef".toCharArray();
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            out[i * 2] = hex[v >>> 4];
            out[i * 2 + 1] = hex[v & 0x0F];
        }
        return new String(out);
    }

    private static boolean isAllZero(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return true;
        for (byte b : bytes) {
            if (b != 0) return false;
        }
        return true;
    }

    /* ---------------- Layer 1: Java Root / Binary / Mount Fallback ---------------- */

    public static boolean isDeviceRooted() {
        String[] paths = new String[]{
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/vendor/bin/su",
            "/data/local/xbin/su",
            "/system/app/Superuser.apk",
            "/sbin/.magisk",
            "/debug_ramdisk/.magisk",
            "/data/adb/magisk",
            "/data/adb/ksu",
            "/data/adb/apatch"
        };
        for (String p : paths) {
            if (fileExists(p)) return true;
        }

        if (Build.TAGS != null && Build.TAGS.contains("test-keys")) {
            return true;
        }

        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/proc/self/mounts"));
            String line;
            while ((line = br.readLine()) != null) {
                String lower = line.toLowerCase();
                if (lower.contains("magisk") || lower.contains("kernelsu")
                        || lower.contains("apatch") || lower.contains("debug_ramdisk")
                        || lower.contains("core/mirror") || lower.contains("/data/adb/modules")
                        || lower.contains("shamiko") || lower.contains("susfs")) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        } finally {
            if (br != null) {
                try { br.close(); } catch (Throwable ignored) {}
            }
        }
        return false;
    }

    public static boolean isMagiskOrRootAppInstalled(Context ctx) {
        String[] pkgs = new String[]{
            "com.topjohnwu.magisk",
            "io.github.vvb2060.magisk",
            "io.github.huskydg.magisk",
            "com.topjohnwu.magisk.alpha",
            "me.weishu.kernelsu",
            "com.rifsxd.ksunext",
            "com.sukisu.ultra",
            "io.github.a13e300.ksuwebui",
            "me.bmax.apatch",
            "org.lsposed.manager",
            "io.github.lsposed.manager",
            "org.meowcat.edxposed.manager",
            "de.robv.android.xposed.installer",
            "com.solohsu.android.edxp.manager",
            "net.accelf.devoptshide",
            "com.accelforce.devoptshide",
            "com.tsng.hidemyapplist",
            "com.google.android.hmal",
            "icu.nullptr.hidemyapplist",
            "io.github.chankyin.bootloaderspoofer",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.noshufou.android.su",
            "com.thirdparty.superuser",
            "ru.aaaaaccg.installer",
            "com.chelpus.lackypatch",
            "com.dimonvideo.luckypatcher",
            "net.jolivier.cert.Importer"
        };
        for (String pkg : pkgs) {
            if (hasPackage(ctx, pkg)) return true;
        }

        String vb = getProp("ro.boot.verifiedbootstate");
        if ("orange".equalsIgnoreCase(vb) || "yellow".equalsIgnoreCase(vb) || "red".equalsIgnoreCase(vb)) {
            return true;
        }
        if ("0".equals(getProp("ro.boot.flash.locked"))) return true;
        if ("unlocked".equalsIgnoreCase(getProp("ro.boot.vbmeta.device_state"))) return true;
        if ("1".equals(getProp("ro.boot.warranty_bit")) || "1".equals(getProp("ro.warranty_bit"))) return true;

        BufferedReader br = null;
        try {
            java.lang.Process p = Runtime.getRuntime().exec("which su");
            br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line = br.readLine();
            if (line != null && line.trim().length() > 0) return true;
        } catch (Throwable ignored) {
        } finally {
            if (br != null) {
                try { br.close(); } catch (Throwable ignored) {}
            }
        }
        return false;
    }

    /* ---------------- Layer 2: Hardware-Backed Key Attestation (TEE + Anti-TrickyStore) ---------------- */

    private static String checkHardwareKeyAttestation() {
        if (sAttestationChecked) {
            return sCachedAttestationThreat;
        }
        if (Build.VERSION.SDK_INT < 24) {
            sAttestationChecked = true;
            return null;
        }

        String alias = "tkd_att_" + (System.nanoTime() & 0xFFFFL);
        KeyStore ks = null;
        try {
            byte[] nonce = new byte[16];
            new SecureRandom().nextBytes(nonce);

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                    alias, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(nonce)
                    .build();
            kpg.initialize(spec);
            kpg.generateKeyPair();

            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            Certificate[] chain = ks.getCertificateChain(alias);
            if (chain == null || chain.length < 2) {
                Log.w(TAG, "KeyAttestation chain unavailable/short (len=" + (chain == null ? 0 : chain.length) + ")");
                sAttestationChecked = true;
                return null;
            }

            // 1. Verify cryptographic chain integrity & reject AOSP software/fake keyboxes
            for (int i = 0; i < chain.length; i++) {
                if (chain[i] instanceof X509Certificate) {
                    X509Certificate x = (X509Certificate) chain[i];
                    String subj = x.getSubjectX500Principal() != null ? x.getSubjectX500Principal().getName() : "";
                    String iss = x.getIssuerX500Principal() != null ? x.getIssuerX500Principal().getName() : "";
                    String lowSubj = subj.toLowerCase();
                    String lowIss = iss.toLowerCase();
                    if (lowSubj.contains("software attestation") || lowIss.contains("software attestation")
                            || lowSubj.contains("aosp") || lowIss.contains("aosp")
                            || lowSubj.contains("tricky") || lowIss.contains("tricky")) {
                        sCachedAttestationThreat = "Keystore Software Attestation / Fake Keybox terdeteksi (TEE tidak valid)";
                        sAttestationChecked = true;
                        return sCachedAttestationThreat;
                    }
                }
                if (i + 1 < chain.length) {
                    try {
                        chain[i].verify(chain[i + 1].getPublicKey());
                    } catch (Throwable verifyErr) {
                        sCachedAttestationThreat = "Integritas sertifikat Hardware Attestation tidak valid (TrickyStore / Keybox spoofing)";
                        sAttestationChecked = true;
                        return sCachedAttestationThreat;
                    }
                }
            }

            // 2. Parse ASN.1 KeyDescription extension (OID 1.3.6.1.4.1.11129.2.1.17)
            if (chain[0] instanceof X509Certificate) {
                byte[] extBytes = ((X509Certificate) chain[0]).getExtensionValue("1.3.6.1.4.1.11129.2.1.17");
                if (extBytes != null && extBytes.length > 8) {
                    String vbmetaDigest = getProp("ro.boot.vbmeta.digest");
                    String err = parseKeyAttestationExtension(extBytes, nonce, vbmetaDigest, Build.VERSION.SDK_INT);
                    if (err != null) {
                        sCachedAttestationThreat = err;
                        sAttestationChecked = true;
                        return err;
                    }
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "KeyAttestation skipped/failed: " + t.getClass().getSimpleName() + ": " + t.getMessage());
        } finally {
            if (ks != null) {
                try { ks.deleteEntry(alias); } catch (Throwable ignored) {}
            }
        }
        sAttestationChecked = true;
        return null;
    }

    /** Minimal zero-dependency DER TLV parser for Android Key Attestation OID 1.3.6.1.4.1.11129.2.1.17 */
    private static final class DerElement {
        int tagClass;
        boolean constructed;
        int tagNumber;
        int valStart;
        int valLen;
        int nextPos;
    }

    private static DerElement readDer(byte[] data, int pos, int limit) {
        if (pos >= limit) return null;
        int first = data[pos++] & 0xFF;
        DerElement el = new DerElement();
        el.tagClass = (first >> 6) & 0x03;
        el.constructed = (first & 0x20) != 0;
        int tagNum = first & 0x1F;
        if (tagNum == 0x1F) {
            tagNum = 0;
            int guard = 0;
            while (pos < limit && guard++ < 5) {
                int b = data[pos++] & 0xFF;
                tagNum = (tagNum << 7) | (b & 0x7F);
                if ((b & 0x80) == 0) break;
            }
        }
        el.tagNumber = tagNum;
        if (pos >= limit) return null;

        int lenByte = data[pos++] & 0xFF;
        int len;
        if ((lenByte & 0x80) == 0) {
            len = lenByte;
        } else {
            int numBytes = lenByte & 0x7F;
            if (numBytes == 0 || numBytes > 4 || pos + numBytes > limit) return null;
            len = 0;
            for (int i = 0; i < numBytes; i++) {
                len = (len << 8) | (data[pos++] & 0xFF);
            }
        }
        if (len < 0 || pos + len > limit) return null;
        el.valStart = pos;
        el.valLen = len;
        el.nextPos = pos + len;
        return el;
    }

    private static int readDerInt(byte[] data, DerElement el) {
        int val = 0;
        for (int i = 0; i < el.valLen; i++) {
            val = (val << 8) | (data[el.valStart + i] & 0xFF);
        }
        return val;
    }

    static String parseKeyAttestationExtension(byte[] extValue, byte[] expectedNonce, String vbmetaDigestProp, int sdkInt) {
        DerElement outerOctet = readDer(extValue, 0, extValue.length);
        if (outerOctet == null || outerOctet.tagNumber != 4) return null;

        DerElement seq = readDer(extValue, outerOctet.valStart, outerOctet.valStart + outerOctet.valLen);
        if (seq == null || !seq.constructed || seq.tagNumber != 16) return null;

        int cur = seq.valStart;
        int end = seq.valStart + seq.valLen;
        List<DerElement> fields = new ArrayList<DerElement>();
        while (cur < end && fields.size() < 10) {
            DerElement f = readDer(extValue, cur, end);
            if (f == null) break;
            fields.add(f);
            cur = f.nextPos;
        }
        if (fields.size() < 8) return null;

        // Field 1: attestationSecurityLevel (0=Software, 1=TEE, 2=StrongBox)
        int attLevel = readDerInt(extValue, fields.get(1));
        if (attLevel == 0 && sdkInt >= 29) {
            return "Software-Only Key Attestation terdeteksi (TEE dibypass / Fake Keybox)";
        }

        // Field 4: attestationChallenge (OCTET STRING)
        DerElement challengeEl = fields.get(4);
        if (challengeEl.valLen != expectedNonce.length) {
            return "Challenge Hardware Attestation tidak cocok (Spoofing terdeteksi)";
        }
        byte[] gotNonce = Arrays.copyOfRange(extValue, challengeEl.valStart, challengeEl.valStart + challengeEl.valLen);
        if (!Arrays.equals(gotNonce, expectedNonce)) {
            return "Challenge Hardware Attestation dimanipulasi (Spoofing terdeteksi)";
        }

        // Field 7: teeEnforced AuthorizationList (and fallback Field 6: softwareEnforced)
        String teeResult = inspectAuthorizationListForRootOfTrust(extValue, fields.get(7), vbmetaDigestProp);
        if (teeResult != null) return teeResult;

        String swResult = inspectAuthorizationListForRootOfTrust(extValue, fields.get(6), vbmetaDigestProp);
        if (swResult != null) return swResult;

        return null;
    }

    private static String inspectAuthorizationListForRootOfTrust(byte[] data, DerElement authList, String vbmetaDigestProp) {
        if (authList == null || !authList.constructed) return null;
        int cur = authList.valStart;
        int end = authList.valStart + authList.valLen;
        while (cur < end) {
            DerElement entry = readDer(data, cur, end);
            if (entry == null) break;
            cur = entry.nextPos;
            // Context-specific constructed tag [704] = RootOfTrust
            if (entry.tagClass == 2 && entry.tagNumber == 704) {
                DerElement rotSeq = readDer(data, entry.valStart, entry.valStart + entry.valLen);
                if (rotSeq == null || !rotSeq.constructed) return null;
                int rc = rotSeq.valStart;
                int re = rotSeq.valStart + rotSeq.valLen;
                List<DerElement> rotFields = new ArrayList<DerElement>();
                while (rc < re && rotFields.size() < 6) {
                    DerElement rf = readDer(data, rc, re);
                    if (rf == null) break;
                    rotFields.add(rf);
                    rc = rf.nextPos;
                }
                if (rotFields.size() >= 3) {
                    DerElement vbKeyEl = rotFields.get(0);
                    byte[] vbKey = Arrays.copyOfRange(data, vbKeyEl.valStart, vbKeyEl.valStart + vbKeyEl.valLen);
                    DerElement lockedEl = rotFields.get(1);
                    boolean deviceLocked = lockedEl.valLen > 0 && (data[lockedEl.valStart] != 0);
                    int bootState = readDerInt(data, rotFields.get(2));

                    if (!deviceLocked) {
                        return "Bootloader Unlocked terdeteksi langsung dari Hardware TEE Keystore";
                    }
                    if (bootState != 0) {
                        return "Verified Boot tidak terverifikasi pada Hardware TEE (state=" + bootState + ")";
                    }
                    // Anti-TrickyStore check #1: genuine locked TEE never has an empty or all-zero verifiedBootKey
                    if (isAllZero(vbKey)) {
                        return "Hardware Attestation dipalsukan (TrickyStore / verifiedBootKey kosong/nol)";
                    }
                    // Anti-TrickyStore check #2: compare TEE verifiedBootHash against kernel ro.boot.vbmeta.digest
                    if (rotFields.size() >= 4) {
                        DerElement vbHashEl = rotFields.get(3);
                        byte[] vbHash = Arrays.copyOfRange(data, vbHashEl.valStart, vbHashEl.valStart + vbHashEl.valLen);
                        if (vbHash.length > 0 && isAllZero(vbHash)) {
                            return "Hardware Attestation dipalsukan (TrickyStore / verifiedBootHash nol)";
                        }
                        if (vbHash.length == 32 && vbmetaDigestProp != null) {
                            String propHex = vbmetaDigestProp.trim().toLowerCase();
                            if (propHex.length() == 64 && !propHex.equals("0000000000000000000000000000000000000000000000000000000000000000")) {
                                String teeHashHex = toHexLower(vbHash);
                                if (!propHex.equals(teeHashHex)) {
                                    return "Manipulasi Hardware Attestation terdeteksi (TrickyStore / vbmeta.digest tidak cocok dengan TEE)";
                                }
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    /* ---------------- Layer 3: ART / LSPosed / Xposed / Frida Hook Detection ---------------- */

    private static boolean isPureJavaMethodHooked() {
        try {
            Method m1 = Settings.Global.class.getDeclaredMethod(
                    "getInt", ContentResolver.class, String.class, int.class);
            if (Modifier.isNative(m1.getModifiers())) return true;
        } catch (Throwable ignored) {}
        try {
            Method m1b = Settings.Global.class.getDeclaredMethod(
                    "getInt", ContentResolver.class, String.class);
            if (Modifier.isNative(m1b.getModifiers())) return true;
        } catch (Throwable ignored) {}
        try {
            Method m2 = Settings.Global.class.getDeclaredMethod(
                    "getString", ContentResolver.class, String.class);
            if (Modifier.isNative(m2.getModifiers())) return true;
        } catch (Throwable ignored) {}
        try {
            Method m3 = Settings.Secure.class.getDeclaredMethod(
                    "getInt", ContentResolver.class, String.class, int.class);
            if (Modifier.isNative(m3.getModifiers())) return true;
        } catch (Throwable ignored) {}
        try {
            Method m3b = Settings.Secure.class.getDeclaredMethod(
                    "getString", ContentResolver.class, String.class);
            if (Modifier.isNative(m3b.getModifiers())) return true;
        } catch (Throwable ignored) {}
        try {
            Method m4 = File.class.getDeclaredMethod("exists");
            if (Modifier.isNative(m4.getModifiers())) return true;
        } catch (Throwable ignored) {}
        try {
            Method m4b = Runtime.class.getDeclaredMethod("exec", String.class);
            if (Modifier.isNative(m4b.getModifiers())) return true;
        } catch (Throwable ignored) {}
        try {
            Class<?> apm = Class.forName("android.app.ApplicationPackageManager");
            Method m5 = apm.getDeclaredMethod("getPackageInfo", String.class, int.class);
            if (Modifier.isNative(m5.getModifiers())) return true;
        } catch (Throwable ignored) {}
        return false;
    }

    public static boolean isHookFrameworkDetected() {
        if (isPureJavaMethodHooked()) return true;

        try {
            StackTraceElement[] frames = new Throwable().getStackTrace();
            if (frames != null) {
                for (StackTraceElement el : frames) {
                    String cn = el.getClassName();
                    if (cn != null) {
                        String low = cn.toLowerCase();
                        if (low.contains("xposed") || low.contains("lsposed")
                                || low.contains("lsphooker") || low.contains("edhooker")
                                || low.contains("substrate") || low.contains("frida")) {
                            return true;
                        }
                    }
                }
            }
        } catch (Throwable ignored) {}

        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = br.readLine()) != null) {
                String low = line.toLowerCase();
                if (low.contains("frida-agent") || low.contains("frida-server")
                        || low.contains("gumjs") || low.contains("libfrida")
                        || low.contains("libzygisk") || low.contains("lsposed")
                        || low.contains("lsplant") || low.contains("edxposed")
                        || low.contains("riru") || low.contains("substrate")
                        || low.contains("libgadget") || low.contains("shamiko")
                        || low.contains("devoptshide") || low.contains("hidemyapplist")) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        } finally {
            if (br != null) {
                try { br.close(); } catch (Throwable ignored) {}
            }
        }

        BufferedReader br2 = null;
        try {
            br2 = new BufferedReader(new FileReader("/proc/net/tcp"));
            String line;
            while ((line = br2.readLine()) != null) {
                if (line.contains(":69A2") || line.contains("27042")) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        } finally {
            if (br2 != null) {
                try { br2.close(); } catch (Throwable ignored) {}
            }
        }

        String[] hookClasses = new String[]{
            "de.robv.android.xposed.XposedBridge",
            "de.robv.android.xposed.XC_MethodHook",
            "org.lsposed.lspd.core.Main",
            "com.saurik.substrate.MS$2"
        };
        for (String hc : hookClasses) {
            try {
                Class.forName(hc);
                return true;
            } catch (Throwable ignored) {}
        }
        return false;
    }

    public static boolean isEmulatorDetected() {
        if (fileExists("/dev/qemu_pipe") || fileExists("/dev/socket/qemud")) return true;
        if (Build.FINGERPRINT != null) {
            String fp = Build.FINGERPRINT.toLowerCase();
            if (fp.contains("goldfish") || fp.contains("ranchu") || fp.contains("qemu") || fp.contains("sdk_gphone")) {
                return true;
            }
        }
        if (Build.HARDWARE != null) {
            String hw = Build.HARDWARE.toLowerCase();
            if (hw.contains("goldfish") || hw.contains("ranchu") || hw.contains("vbox86p") || hw.contains("nox")) {
                return true;
            }
        }
        if (Build.MODEL != null) {
            String md = Build.MODEL.toLowerCase();
            if (md.contains("sdk_gphone") || md.contains("genymotion") || md.contains("bluestacks") || md.contains("ldplayer")) {
                return true;
            }
        }
        return false;
    }

    public static boolean isTracerOrDebuggerAttached() {
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) return true;
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/proc/self/status"));
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    String pid = line.substring(10).trim();
                    if (!"0".equals(pid)) return true;
                    break;
                }
            }
        } catch (Throwable ignored) {
        } finally {
            if (br != null) {
                try { br.close(); } catch (Throwable ignored) {}
            }
        }
        return false;
    }

    /* ---------------- Unified Multi-Layer Threat Aggregation (Developer Mode ALLOWED) ---------------- */

    public static String detectThreat(Context ctx) {
        List<String> reasons = new ArrayList<String>();

        int nativeFlags = 0;
        String nativeDetails = "";
        if (sNativeLoaded) {
            try {
                nativeFlags = nativeScan();
                if (nativeFlags != 0) {
                    nativeDetails = nativeScanDetails();
                }
            } catch (Throwable t) {
                reasons.add("Integritas modul keamanan native (libtkdguard) terganggu");
            }
        } else {
            reasons.add("Pustaka keamanan native (libtkdguard.so) tidak termuat / dimodifikasi");
        }

        // 1. Hardware Key Attestation (TEE/StrongBox + Anti-TrickyStore vbmeta cross-check)
        String attestationErr = checkHardwareKeyAttestation();
        if (attestationErr != null) {
            reasons.add(attestationErr);
        }

        // 2. Root / Magisk / KernelSU / APatch / Overlay Mount / Hidden Root Package / Bootloader / SELinux
        boolean rootFound = ((nativeFlags & (FLAG_ROOT_BINARY | FLAG_ROOT_MOUNT | FLAG_HIDDEN_ROOT_APP | FLAG_BOOTLOADER_PROP | FLAG_SELINUX_TAMPER)) != 0)
                || isDeviceRooted()
                || isMagiskOrRootAppInstalled(ctx);
        if (rootFound) {
            reasons.add("Perangkat Root / Magisk / KernelSU / APatch / Modul Hide terdeteksi");
        }

        // 3. Active Frida Server / Instrumentation
        if ((nativeFlags & FLAG_FRIDA_ACTIVE) != 0) {
            reasons.add("Frida Server / Dynamic Instrumentation aktif terdeteksi (port 27042)");
        }

        // 4. Zygisk / Shamiko / LSPosed / Xposed / Inline Memory Hooking (/proc/self/smaps dirty .text)
        if (((nativeFlags & FLAG_MEMORY_HOOK) != 0)) {
            reasons.add("Injeksi Memori / Zygisk / Shamiko / LSPlant Inline Hook terdeteksi pada pustaka sistem");
        }
        if (((nativeFlags & FLAG_HOOK_FRAMEWORK) != 0) || isHookFrameworkDetected()) {
            reasons.add("Framework Hooking (Frida / LSPosed / Zygisk / Xposed / Hide Module) terdeteksi");
        }

        // 5. Emulator
        if (((nativeFlags & FLAG_EMULATOR) != 0) || isEmulatorDetected()) {
            reasons.add("Lingkungan Emulator / Virtual Device terdeteksi");
        }

        // 6. Active Debugger / ptrace Tracer (Developer Mode alone is NOT blocked)
        if (((nativeFlags & FLAG_DEBUGGER_TRACER) != 0) || isTracerOrDebuggerAttached()) {
            reasons.add("Debugger / Tracer aktif terdeteksi pada proses aplikasi");
        }

        if (reasons.isEmpty()) {
            return null;
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < reasons.size(); i++) {
            if (i > 0) sb.append("\n\u2022 ");
            sb.append(reasons.get(i));
        }
        if (nativeDetails != null && nativeDetails.length() > 0) {
            Log.e(TAG, "Native diagnostics: " + nativeDetails);
        }
        return sb.toString();
    }

    /* ---------------- Hard Transaction & Process Lockout ---------------- */

    public static void terminateApp() {
        try {
            if (sNativeLoaded) {
                nativeHardTerminate();
            }
        } catch (Throwable ignored) {}
        try {
            Process.killProcess(Process.myPid());
        } catch (Throwable ignored) {}
        try {
            Runtime.getRuntime().halt(1);
        } catch (Throwable ignored) {}
        try {
            System.exit(1);
        } catch (Throwable ignored) {}
    }

    private static void terminateActivityAndApp(Activity activity) {
        if (activity != null) {
            try {
                activity.finishAffinity();
            } catch (Throwable ignored) {
                try { activity.finish(); } catch (Throwable ignored2) {}
            }
        }
        terminateApp();
    }

    private static void lockActivitySurface(final Activity activity, String threatSummary) {
        try {
            FrameLayout root = new FrameLayout(activity);
            root.setBackgroundColor(Color.parseColor("#0B1120"));
            root.setClickable(true);
            root.setFocusable(true);
            root.setLayoutParams(new ViewGroup.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.MATCH_PARENT));

            LinearLayout box = new LinearLayout(activity);
            box.setOrientation(LinearLayout.VERTICAL);
            box.setGravity(Gravity.CENTER);
            box.setPadding(64, 64, 64, 64);

            TextView title = new TextView(activity);
            title.setText("\u26a0\ufe0f AKSES & TRANSAKSI DIBLOKIR");
            title.setTextColor(Color.parseColor("#EF4444"));
            title.setTextSize(18f);
            title.setGravity(Gravity.CENTER);

            TextView body = new TextView(activity);
            body.setText("\nPerangkat terdeteksi tidak aman:\n\n\u2022 " + threatSummary
                    + "\n\nDemi keamanan akun & transaksi, aplikasi ditutup otomatis.");
            body.setTextColor(Color.parseColor("#E2E8F0"));
            body.setTextSize(14f);
            body.setGravity(Gravity.CENTER);

            box.addView(title);
            box.addView(body);
            root.addView(box, new FrameLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.MATCH_PARENT));

            activity.setContentView(root);
            activity.setFinishOnTouchOutside(false);
        } catch (Throwable ignored) {}
    }

    private static void scheduleFailsafeKill(final Activity activity) {
        if (sKillScheduled) return;
        sKillScheduled = true;
        try {
            new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {
                @Override
                public void run() {
                    terminateActivityAndApp(activity);
                }
            }, 6000L);
        } catch (Throwable ignored) {}

        try {
            Thread watchdog = new Thread(new Runnable() {
                @Override
                public void run() {
                    try { Thread.sleep(7000L); } catch (Throwable ignored) {}
                    terminateApp();
                }
            });
            watchdog.setDaemon(true);
            watchdog.start();
        } catch (Throwable ignored) {}
    }

    public static void enforceSecurity(Context ctx) {
        enforceSecurity(ctx, true);
    }

    private static void enforceSecurity(Context ctx, boolean showDialog) {
        String threat = detectThreat(ctx);
        if (threat == null) {
            return;
        }

        Log.e(TAG, "SECURITY BLOCK TRIGGERED: " + threat);

        if (ctx instanceof Activity) {
            final Activity activity = (Activity) ctx;
            lockActivitySurface(activity, threat);
            scheduleFailsafeKill(activity);

            if (!showDialog || activity.isFinishing()) {
                return;
            }
            int actHash = System.identityHashCode(activity);
            if (sDialogShownActivityHash == actHash) {
                return;
            }
            sDialogShownActivityHash = actHash;

            try {
                String msg = "Perangkat Anda terdeteksi memiliki pelanggaran keamanan:\n\n\u2022 "
                        + threat
                        + "\n\nDemi melindungi data dan transaksi Anda, seluruh akses & transaksi diblokir pada perangkat ini.";

                AlertDialog.Builder builder = new AlertDialog.Builder(
                        activity, android.R.style.Theme_DeviceDefault_Dialog_Alert);
                builder.setTitle("\u26a0\ufe0f Peringatan Keamanan Perangkat");
                builder.setMessage(msg);
                builder.setCancelable(false);
                builder.setPositiveButton("Keluar Aplikasi", new ExitListener(activity));
                AlertDialog dialog = builder.create();
                dialog.setCanceledOnTouchOutside(false);
                dialog.setOnCancelListener(new DialogInterface.OnCancelListener() {
                    @Override
                    public void onCancel(DialogInterface d) {
                        terminateActivityAndApp(activity);
                    }
                });
                dialog.setOnDismissListener(new DialogInterface.OnDismissListener() {
                    @Override
                    public void onDismiss(DialogInterface d) {
                        terminateActivityAndApp(activity);
                    }
                });
                dialog.setOnKeyListener(new DialogInterface.OnKeyListener() {
                    @Override
                    public boolean onKey(DialogInterface d, int keyCode, KeyEvent event) {
                        if (keyCode == KeyEvent.KEYCODE_BACK || keyCode == KeyEvent.KEYCODE_SEARCH) {
                            terminateActivityAndApp(activity);
                            return true;
                        }
                        return false;
                    }
                });
                dialog.show();
                return;
            } catch (Throwable t) {
                terminateActivityAndApp(activity);
                return;
            }
        }

        if (ctx != null) {
            try {
                Toast.makeText(ctx, "Keamanan perangkat tidak memenuhi syarat: " + threat, Toast.LENGTH_LONG).show();
            } catch (Throwable ignored) {}
        }
        terminateApp();
    }

    public static void install(Context ctx) {
        if (ctx == null) return;
        try {
            if (ctx instanceof Application) {
                if (!sInstalled) {
                    sInstalled = true;
                    ((Application) ctx).registerActivityLifecycleCallbacks(new GuardCallbacks());
                }
                try {
                    checkHardwareKeyAttestation();
                } catch (Throwable ignored) {}
                return;
            }
            enforceSecurity(ctx);
        } catch (Throwable ignored) {}
    }

    public static final class ExitListener implements DialogInterface.OnClickListener {
        private final Activity mActivity;

        public ExitListener() {
            this.mActivity = null;
        }

        public ExitListener(Activity activity) {
            this.mActivity = activity;
        }

        @Override
        public void onClick(DialogInterface dialog, int which) {
            terminateActivityAndApp(mActivity);
        }
    }

    public static final class GuardCallbacks implements Application.ActivityLifecycleCallbacks {
        @Override
        public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
            enforceSecurity(activity, false);
        }

        @Override
        public void onActivityStarted(Activity activity) {
            enforceSecurity(activity, false);
        }

        @Override
        public void onActivityResumed(Activity activity) {
            enforceSecurity(activity, true);
        }

        @Override
        public void onActivityPaused(Activity activity) {}

        @Override
        public void onActivityStopped(Activity activity) {}

        @Override
        public void onActivitySaveInstanceState(Activity activity, Bundle outState) {}

        @Override
        public void onActivityDestroyed(Activity activity) {}
    }
}
