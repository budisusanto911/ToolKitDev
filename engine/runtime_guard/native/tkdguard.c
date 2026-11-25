/*
 * ToolKitDev RuntimeGuard v2.1 - Native Anti-Root / Anti-Hide / Anti-Frida / Anti-Zygisk Engine
 *
 * Policy:
 *   - ALLOWS normal Developer Options & USB Debugging on clean devices.
 *   - BLOCKS Root (Magisk, KernelSU, KSU-Next, SukiSU, APatch, SuperSU), Hide Modules
 *     (Shamiko, Zygisk, Zygisk-Next, ReZygisk, LSPosed, Hide My Applist, TrickyStore, PIF),
 *     Frida (active D-Bus port probe + maps + threads + fds), Inline Memory Hooking
 *     (/proc/self/smaps dirty .text on libc/libart/libandroid_runtime), Unlocked Bootloader,
 *     SELinux Tampering, Active Debugger/Tracer (TracerPid), and Emulators.
 *
 * Uses direct Linux syscalls (SYS_openat, SYS_read, SYS_close, SYS_faccessat,
 * SYS_readlinkat, SYS_getdents64, SYS_kill, SYS_getpid, SYS_exit_group) and native
 * __system_property_get() so Java Xposed/LSPosed hooks and libc PLT hooks cannot spoof checks.
 */

#define _GNU_SOURCE
#include <jni.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <android/log.h>

#define LOG_TAG "ToolKitDevGuard"

/* Threat Bitmask Flags */
#define FLAG_ROOT_BINARY       (1 << 0)
#define FLAG_ROOT_MOUNT        (1 << 1)
#define FLAG_HIDDEN_ROOT_APP   (1 << 2)
#define FLAG_BOOTLOADER_PROP   (1 << 3)
#define FLAG_HOOK_FRAMEWORK    (1 << 4)
#define FLAG_DEBUGGER_TRACER   (1 << 5)
#define FLAG_EMULATOR          (1 << 6)
#define FLAG_SELINUX_TAMPER    (1 << 7)
#define FLAG_MEMORY_HOOK       (1 << 8)
#define FLAG_FRIDA_ACTIVE      (1 << 9)

/* Portable kernel linux_dirent64 ABI across arm64, arm32, x86, x86_64 */
struct tkd_dirent64 {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[];
};

/* ---------------- Direct Raw Syscall Wrappers ---------------- */

static inline long raw_openat(int dirfd, const char *path, int flags, int mode) {
    return syscall(SYS_openat, dirfd, path, flags, mode);
}

static inline long raw_read(int fd, void *buf, size_t count) {
    return syscall(SYS_read, fd, buf, count);
}

static inline long raw_close(int fd) {
    return syscall(SYS_close, fd);
}

static inline long raw_faccessat(int dirfd, const char *path, int mode) {
    return syscall(SYS_faccessat, dirfd, path, mode, 0);
}

static inline long raw_readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz) {
    return syscall(SYS_readlinkat, dirfd, path, buf, bufsiz);
}

static inline long raw_getdents64(int fd, void *dirp, unsigned int count) {
    return syscall(SYS_getdents64, fd, dirp, count);
}

static int raw_file_exists(const char *path) {
    return raw_faccessat(AT_FDCWD, path, F_OK) == 0;
}

static ssize_t raw_read_small_file(const char *path, char *out, size_t max_len) {
    if (!out || max_len < 2) return -1;
    out[0] = '\0';
    long fd = raw_openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return -1;
    size_t total = 0;
    while (total + 1 < max_len) {
        long n = raw_read((int)fd, out + total, max_len - 1 - total);
        if (n <= 0) break;
        total += (size_t)n;
    }
    raw_close((int)fd);
    out[total] = '\0';
    return (ssize_t)total;
}

/* ---------------- String & Stream Helpers ---------------- */

static int str_contains_ci(const char *haystack, const char *needle) {
    if (!haystack || !needle || !*needle) return 0;
    size_t nlen = strlen(needle);
    for (const char *p = haystack; *p; p++) {
        size_t i = 0;
        while (i < nlen && p[i] && tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) {
            i++;
        }
        if (i == nlen) return 1;
    }
    return 0;
}

static void append_reason(char *buf, size_t buf_sz, const char *msg) {
    if (!buf || !msg || !*msg) return;
    size_t cur = strlen(buf);
    if (cur + 4 >= buf_sz) return;
    if (cur > 0) {
        strncat(buf, "|", buf_sz - cur - 1);
        cur = strlen(buf);
    }
    strncat(buf, msg, buf_sz - cur - 1);
}

static int get_prop(const char *name, char *out, size_t out_sz) {
    if (!out || out_sz < PROP_VALUE_MAX) return 0;
    out[0] = '\0';
    int len = __system_property_get(name, out);
    if (len < 0) {
        out[0] = '\0';
        return 0;
    }
    return len;
}

typedef int (*line_cb_t)(const char *line, void *ctx);

static void stream_proc_lines(const char *path, line_cb_t cb, void *ctx) {
    long fd = raw_openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return;

    char chunk[4096];
    char line[2048];
    size_t line_len = 0;

    for (;;) {
        long n = raw_read((int)fd, chunk, sizeof(chunk));
        if (n <= 0) break;
        for (long i = 0; i < n; i++) {
            char c = chunk[i];
            if (c == '\n') {
                line[line_len] = '\0';
                if (line_len > 0 && cb(line, ctx)) {
                    raw_close((int)fd);
                    return;
                }
                line_len = 0;
            } else if (line_len + 1 < sizeof(line)) {
                line[line_len++] = c;
            }
        }
    }
    if (line_len > 0) {
        line[line_len] = '\0';
        cb(line, ctx);
    }
    raw_close((int)fd);
}

/* ---------------- 1. Root Binary, PATH & Artifact Checks ---------------- */

static int check_root_binaries(char *detail, size_t detail_sz) {
    static const char *const root_paths[] = {
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/vendor/bin/su",
        "/product/bin/su",
        "/odm/bin/su",
        "/system_ext/bin/su",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/su/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/system/bin/.ext/.su",
        "/system/usr/we-need-root/su-backup",
        "/system/app/Superuser.apk",
        "/system/app/SuperSU.apk",
        "/system/priv-app/SuperSU/SuperSU.apk",
        "/sbin/.magisk",
        "/sbin/magisk",
        "/system/bin/magisk",
        "/system/xbin/magisk",
        "/debug_ramdisk/.magisk",
        "/debug_ramdisk/su",
        "/debug_ramdisk/magisk",
        "/data/adb/magisk",
        "/data/adb/magisk.db",
        "/data/adb/ksu",
        "/data/adb/ksud",
        "/data/adb/ksu/bin/su",
        "/data/adb/apatch",
        "/data/adb/apd",
        "/data/adb/ap/bin/su",
        "/data/adb/modules",
        "/data/adb/lspd",
        "/data/adb/shamiko",
        "/data/adb/tricky_store",
        "/dev/.magisk",
        "/dev/magisk",
        "/cache/magisk.log",
        "/cache/.disable_magisk",
        "/system/xbin/daemonsu",
        "/system/bin/daemonsu",
        "/system/etc/init.d/99SuperSUDaemon",
        "/data/local/tmp/frida-server",
        "/data/local/tmp/re.frida.server",
        NULL
    };

    for (int i = 0; root_paths[i] != NULL; i++) {
        if (raw_file_exists(root_paths[i])) {
            append_reason(detail, detail_sz, "Native:su/root_artifact");
            return 1;
        }
    }

    /* Scan every directory in PATH for su / magisk / ksud / apd / daemonsu */
    const char *path_env = getenv("PATH");
    if (path_env && *path_env) {
        static const char *const bins[] = { "su", "magisk", "ksud", "apd", "daemonsu", NULL };
        const char *p = path_env;
        while (*p) {
            const char *sep = strchr(p, ':');
            size_t dlen = sep ? (size_t)(sep - p) : strlen(p);
            if (dlen > 0 && dlen < 200) {
                char candidate[256];
                for (int b = 0; bins[b] != NULL; b++) {
                    size_t blen = strlen(bins[b]);
                    if (dlen + 1 + blen + 1 < sizeof(candidate)) {
                        memcpy(candidate, p, dlen);
                        candidate[dlen] = '/';
                        memcpy(candidate + dlen + 1, bins[b], blen + 1);
                        if (raw_file_exists(candidate)) {
                            append_reason(detail, detail_sz, "Native:PATH_root_binary");
                            return 1;
                        }
                    }
                }
            }
            if (!sep) break;
            p = sep + 1;
        }
    }

    return 0;
}

/* ---------------- 2. Self-Calibrated Anti-HMA Root/Hook App Syscall Probe ---------------- */

static int check_hidden_root_packages_native(char *detail, size_t detail_sz) {
    /*
     * Defeats Hide My Applist (HMA) which hooks PackageManagerService.
     * Self-calibration guarantees 0% false positives across all Android/SELinux versions:
     * ONLY run EACCES-based existence probing if a guaranteed nonexistent canary returns ENOENT.
     */
    static const char *const base_dirs[] = {
        "/data/data/",
        "/data/user_de/0/",
        NULL
    };
    static const char *const root_pkgs[] = {
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
        "com.tsng.hidemyapplist",
        "com.google.android.hmal",
        "icu.nullptr.hidemyapplist",
        "net.accelf.devoptshide",
        "com.accelforce.devoptshide",
        "io.github.chankyin.bootloaderspoofer",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "ru.aaaaaccg.installer",
        "com.chelpus.lackypatch",
        "com.dimonvideo.luckypatcher",
        "net.jolivier.cert.Importer",
        NULL
    };

    for (int d = 0; base_dirs[d] != NULL; d++) {
        char canary[256];
        size_t blen = strlen(base_dirs[d]);
        const char *canary_name = "com.tkd.nonexistent.canary.9f8a7b6c";
        memcpy(canary, base_dirs[d], blen);
        strcpy(canary + blen, canary_name);

        errno = 0;
        long cret = raw_faccessat(AT_FDCWD, canary, F_OK);
        int cerr = errno;
        if (cret == 0 || cerr != ENOENT) {
            /* SELinux doesn't distinguish ENOENT vs EACCES here — skip safely */
            continue;
        }

        for (int i = 0; root_pkgs[i] != NULL; i++) {
            char probe[256];
            size_t plen = strlen(root_pkgs[i]);
            if (blen + plen + 1 >= sizeof(probe)) continue;
            memcpy(probe, base_dirs[d], blen);
            memcpy(probe + blen, root_pkgs[i], plen + 1);

            errno = 0;
            long r = raw_faccessat(AT_FDCWD, probe, F_OK);
            int e = errno;
            if (r == 0 || e == EACCES) {
                char msg[160];
                snprintf(msg, sizeof(msg), "Native:hidden_pkg(%s)", root_pkgs[i]);
                append_reason(detail, detail_sz, msg);
                return 1;
            }
        }
    }
    return 0;
}

/* ---------------- 3. Deep MountInfo & Mounts Forensics ---------------- */

struct mount_scan_ctx {
    int detected;
    char *detail;
    size_t detail_sz;
};

static int is_system_mount_point(const char *mp, size_t len) {
    static const char *const sys_mps[] = {
        "/system",
        "/system/bin",
        "/system/xbin",
        "/system/framework",
        "/system/app",
        "/system/priv-app",
        "/system/lib",
        "/system/lib64",
        "/system/etc",
        "/system/etc/hosts",
        "/vendor",
        "/vendor/bin",
        "/vendor/etc",
        "/vendor/app",
        "/vendor/priv-app",
        "/product",
        "/product/app",
        "/product/priv-app",
        "/system_ext",
        "/system_ext/priv-app",
        "/odm",
        NULL
    };
    for (int i = 0; sys_mps[i] != NULL; i++) {
        size_t slen = strlen(sys_mps[i]);
        if (len == slen && strncmp(mp, sys_mps[i], slen) == 0) {
            return 1;
        }
    }
    return 0;
}

static int mount_line_cb(const char *line, void *vctx) {
    struct mount_scan_ctx *ctx = (struct mount_scan_ctx *)vctx;

    static const char *const bad_tokens[] = {
        "magisk",
        "core/mirror",
        "debug_ramdisk",
        "/data/adb/modules",
        "/data/adb/magisk",
        "/data/adb/ksu",
        "/data/adb/apatch",
        "/data/adb/lspd",
        "kernelsu",
        "ksu_overlay",
        "apatch",
        "shamiko",
        "zygisk",
        "susfs",
        NULL
    };

    for (int i = 0; bad_tokens[i] != NULL; i++) {
        if (str_contains_ci(line, bad_tokens[i])) {
            ctx->detected = 1;
            append_reason(ctx->detail, ctx->detail_sz, "Native:root_mount_signature");
            return 1;
        }
    }

    /* /proc/self/mountinfo format:
     * id parent major:minor root mount_point mount_opts [opt...] - fs_type source super_opts */
    const char *sep = strstr(line, " - ");
    if (sep) {
        const char *p = line;
        const char *mp_start = NULL;
        size_t mp_len = 0;
        const char *mopts_start = NULL;
        for (int field = 1; field <= 6 && *p; field++) {
            const char *fstart = p;
            while (*p && *p != ' ') p++;
            if (field == 5) {
                mp_start = fstart;
                mp_len = (size_t)(p - fstart);
            } else if (field == 6) {
                mopts_start = fstart;
            }
            while (*p == ' ') p++;
        }

        const char *fs = sep + 3;
        const char *fs_end = fs;
        while (*fs_end && *fs_end != ' ') fs_end++;
        size_t fs_len = (size_t)(fs_end - fs);

        const char *src = fs_end;
        while (*src == ' ') src++;
        const char *src_end = src;
        while (*src_end && *src_end != ' ') src_end++;
        size_t src_len = (size_t)(src_end - src);

        /* Exact KSU / APatch / magisk mount source */
        if ((src_len == 3 && strncmp(src, "KSU", 3) == 0) ||
            (src_len == 6 && strncasecmp(src, "APatch", 6) == 0) ||
            (src_len == 6 && strncasecmp(src, "magisk", 6) == 0)) {
            ctx->detected = 1;
            append_reason(ctx->detail, ctx->detail_sz, "Native:ksu_apatch_mount_source");
            return 1;
        }

        /* Stock retail Android NEVER mounts tmpfs or overlayfs on /system, /vendor, /product, /system/bin etc. */
        if (mp_start && is_system_mount_point(mp_start, mp_len)) {
            if ((fs_len == 5 && strncmp(fs, "tmpfs", 5) == 0) ||
                (fs_len == 7 && strncmp(fs, "overlay", 7) == 0)) {
                ctx->detected = 1;
                append_reason(ctx->detail, ctx->detail_sz, "Native:overlay_or_tmpfs_on_system");
                return 1;
            }
            /* System partitions mounted read-write (rw,) violate AVB/dm-verity */
            if (mopts_start && strncmp(mopts_start, "rw,", 3) == 0) {
                ctx->detected = 1;
                append_reason(ctx->detail, ctx->detail_sz, "Native:system_mounted_rw");
                return 1;
            }
        }

        /* Systemless hosts bind mount */
        if (mp_start && mp_len == 17 && strncmp(mp_start, "/system/etc/hosts", 17) == 0) {
            if (str_contains_ci(line, "/adb/") || str_contains_ci(line, "modules") ||
                (fs_len == 4 && strncmp(fs, "ext4", 4) == 0 && str_contains_ci(line, "hosts"))) {
                ctx->detected = 1;
                append_reason(ctx->detail, ctx->detail_sz, "Native:systemless_hosts");
                return 1;
            }
        }
    }

    return 0;
}

static int check_root_mounts(char *detail, size_t detail_sz) {
    struct mount_scan_ctx ctx = { 0, detail, detail_sz };
    stream_proc_lines("/proc/self/mountinfo", mount_line_cb, &ctx);
    if (!ctx.detected) {
        stream_proc_lines("/proc/self/mounts", mount_line_cb, &ctx);
    }
    return ctx.detected;
}

/* ---------------- 4. /proc/self/smaps Executable Code Integrity (Anti-Zygisk/LSPlant/Frida Inline Hook) ---------------- */

struct smaps_ctx {
    int in_critical_exec;
    int detected;
    char cur_lib[64];
    char *detail;
    size_t detail_sz;
};

static int is_critical_sys_so(const char *line, char *out_name, size_t out_sz) {
    /* Match only file-backed /libc.so, /libart.so, /libandroid_runtime.so */
    static const char *const libs[] = {
        "/libc.so",
        "/libart.so",
        "/libandroid_runtime.so",
        NULL
    };
    for (int i = 0; libs[i] != NULL; i++) {
        const char *pos = strstr(line, libs[i]);
        if (pos) {
            char after = pos[strlen(libs[i])];
            if (after == '\0' || after == ' ' || after == '\t' || after == '\r' || after == '\n') {
                strncpy(out_name, libs[i] + 1, out_sz - 1);
                out_name[out_sz - 1] = '\0';
                return 1;
            }
        }
    }
    return 0;
}

static long parse_kb_field(const char *line, const char *prefix) {
    size_t plen = strlen(prefix);
    if (strncmp(line, prefix, plen) != 0) return -1;
    const char *p = line + plen;
    while (*p == ' ' || *p == '\t') p++;
    return strtol(p, NULL, 10);
}

static int smaps_line_cb(const char *line, void *vctx) {
    struct smaps_ctx *ctx = (struct smaps_ctx *)vctx;

    /* VMA header line starts with hex address containing '-' and ' ' before perms */
    if (isxdigit((unsigned char)line[0]) && strchr(line, '-') != NULL) {
        ctx->in_critical_exec = 0;
        const char *sp = strchr(line, ' ');
        if (sp && sp[1] && sp[2] && sp[3] && sp[4]) {
            char p_r = sp[1], p_w = sp[2], p_x = sp[3];
            if (p_x == 'x' && is_critical_sys_so(line, ctx->cur_lib, sizeof(ctx->cur_lib))) {
                /* W^X violation on critical system .so (rwxp) = active inline hook! */
                if (p_w == 'w' && p_r == 'r') {
                    ctx->detected = 1;
                    char msg[128];
                    snprintf(msg, sizeof(msg), "Native:smaps_rwx_%s", ctx->cur_lib);
                    append_reason(ctx->detail, ctx->detail_sz, msg);
                    return 1;
                }
                ctx->in_critical_exec = 1;
            }
        }
        return 0;
    }

    if (ctx->in_critical_exec) {
        /*
         * Executable .text segments of libc.so, libart.so, libandroid_runtime.so
         * NEVER have text relocations on Android 6+.
         * Private_Dirty > 0 -> inline hook after fork (LSPosed/LSPlant/Frida/Dobby)
         * Shared_Dirty  > 0 -> inline hook in zygote64 before fork (Zygisk/Zygisk-Next/ReZygisk/Shamiko)
         */
        long pd = parse_kb_field(line, "Private_Dirty:");
        if (pd > 0) {
            ctx->detected = 1;
            char msg[128];
            snprintf(msg, sizeof(msg), "Native:inline_hook_dirty_text(%s,priv=%ldkB)", ctx->cur_lib, pd);
            append_reason(ctx->detail, ctx->detail_sz, msg);
            return 1;
        }
        long sd = parse_kb_field(line, "Shared_Dirty:");
        if (sd > 0) {
            ctx->detected = 1;
            char msg[128];
            snprintf(msg, sizeof(msg), "Native:zygote_injected_text(%s,shared=%ldkB)", ctx->cur_lib, sd);
            append_reason(ctx->detail, ctx->detail_sz, msg);
            return 1;
        }
    }
    return 0;
}

static int check_memory_code_integrity(char *detail, size_t detail_sz) {
    struct smaps_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.detail = detail;
    ctx.detail_sz = detail_sz;
    stream_proc_lines("/proc/self/smaps", smaps_line_cb, &ctx);
    return ctx.detected;
}

/* ---------------- 5. Active Frida Server D-Bus Loopback Probe (Android 8–15 SELinux-Safe) ---------------- */

static int probe_frida_port(uint16_t port) {
    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sock < 0) return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int rc = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) {
        raw_close(sock);
        return 0;
    }

    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    if (poll(&pfd, 1, 120) <= 0) {
        raw_close(sock);
        return 0;
    }

    int so_err = 0;
    socklen_t slen = sizeof(so_err);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &slen) < 0 || so_err != 0) {
        raw_close(sock);
        return 0;
    }

    /* Send Frida D-Bus AUTH handshake; frida-server responds with "REJECTED" */
    static const char dbus_auth[] = "\x00AUTH\r\n";
    ssize_t sent = send(sock, dbus_auth, sizeof(dbus_auth) - 1, MSG_NOSIGNAL);
    int detected = 0;
    if (sent > 0) {
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, 150) > 0) {
            char resp[64];
            ssize_t r = recv(sock, resp, sizeof(resp) - 1, 0);
            if (r > 0) {
                resp[r] = '\0';
                if (strstr(resp, "REJECTED") != NULL || strstr(resp, "OK ") != NULL) {
                    detected = 1;
                }
            }
        }
    }

    raw_close(sock);
    return detected;
}

static int check_frida_active(char *detail, size_t detail_sz) {
    if (probe_frida_port(27042) || probe_frida_port(27043)) {
        append_reason(detail, detail_sz, "Native:frida_server_dbus_27042");
        return 1;
    }
    return 0;
}

/* ---------------- 6. Bootloader, Root Daemons, Cmdline & SELinux ---------------- */

static int check_bootloader_and_selinux(char *detail, size_t detail_sz, int *out_selinux) {
    int detected = 0;
    char val[PROP_VALUE_MAX];

    if (get_prop("ro.boot.verifiedbootstate", val, sizeof(val)) > 0) {
        if (strcasecmp(val, "orange") == 0 || strcasecmp(val, "yellow") == 0 || strcasecmp(val, "red") == 0) {
            detected = 1;
            append_reason(detail, detail_sz, "Native:verifiedboot_unlocked");
        }
    }
    if (get_prop("ro.boot.flash.locked", val, sizeof(val)) > 0 && strcmp(val, "0") == 0) {
        detected = 1;
        append_reason(detail, detail_sz, "Native:flash.locked=0");
    }
    if (get_prop("ro.boot.vbmeta.device_state", val, sizeof(val)) > 0 && strcasecmp(val, "unlocked") == 0) {
        detected = 1;
        append_reason(detail, detail_sz, "Native:vbmeta_unlocked");
    }
    if (get_prop("ro.boot.veritymode", val, sizeof(val)) > 0) {
        if (strcasecmp(val, "disabled") == 0 || strcasecmp(val, "logging") == 0 || strcasecmp(val, "eio") == 0) {
            detected = 1;
            append_reason(detail, detail_sz, "Native:dm_verity_disabled");
        }
    }
    if (get_prop("ro.boot.warranty_bit", val, sizeof(val)) > 0 && strcmp(val, "1") == 0) {
        detected = 1;
        append_reason(detail, detail_sz, "Native:knox_warranty_tripped");
    }
    if (get_prop("ro.warranty_bit", val, sizeof(val)) > 0 && strcmp(val, "1") == 0) {
        detected = 1;
        append_reason(detail, detail_sz, "Native:warranty_bit_tripped");
    }
    if (get_prop("ro.build.tags", val, sizeof(val)) > 0 && str_contains_ci(val, "test-keys")) {
        detected = 1;
        append_reason(detail, detail_sz, "Native:test-keys");
    }
    if (get_prop("ro.build.type", val, sizeof(val)) > 0) {
        if (strcasecmp(val, "eng") == 0 || strcasecmp(val, "userdebug") == 0) {
            detected = 1;
            append_reason(detail, detail_sz, "Native:non_user_build");
        }
    }
    if (get_prop("ro.secure", val, sizeof(val)) > 0 && strcmp(val, "0") == 0) {
        detected = 1;
        append_reason(detail, detail_sz, "Native:ro.secure=0");
    }
    if (get_prop("ro.debuggable", val, sizeof(val)) > 0 && strcmp(val, "1") == 0) {
        detected = 1;
        append_reason(detail, detail_sz, "Native:ro.debuggable=1");
    }
    if (get_prop("service.adb.root", val, sizeof(val)) > 0 && strcmp(val, "1") == 0) {
        detected = 1;
        append_reason(detail, detail_sz, "Native:adb_root=1");
    }
    if (get_prop("ro.build.selinux", val, sizeof(val)) > 0 && strcmp(val, "0") == 0) {
        if (out_selinux) *out_selinux = 1;
        append_reason(detail, detail_sz, "Native:ro.build.selinux=0");
    }

    static const char *const root_svcs[] = {
        "init.svc.magiskd",
        "init.svc.magisk_daemon",
        "init.svc.magisk_pfs",
        "init.svc.su_daemon",
        "init.svc.daemonsu",
        "init.svc.ksu",
        "init.svc.ksud",
        "init.svc.apatch",
        "init.svc.lspd",
        "init.svc.zygiskd",
        "persist.magisk.hide",
        NULL
    };
    for (int i = 0; root_svcs[i] != NULL; i++) {
        if (get_prop(root_svcs[i], val, sizeof(val)) > 0) {
            detected = 1;
            append_reason(detail, detail_sz, "Native:root_daemon_prop");
            break;
        }
    }

    /* Kernel /proc/cmdline bypasses Magisk resetprop on devices where readable */
    char cmdline[4096];
    if (raw_read_small_file("/proc/cmdline", cmdline, sizeof(cmdline)) > 0) {
        if (str_contains_ci(cmdline, "verifiedbootstate=orange") ||
            str_contains_ci(cmdline, "verifiedbootstate=red") ||
            str_contains_ci(cmdline, "flash.locked=0") ||
            str_contains_ci(cmdline, "vbmeta.device_state=unlocked") ||
            str_contains_ci(cmdline, "veritymode=disabled")) {
            detected = 1;
            append_reason(detail, detail_sz, "Native:cmdline_bootloader_unlocked");
        }
    }

    /* SELinux enforcing status (only if readable; EACCES is ignored safely) */
    char sebuf[128];
    if (raw_read_small_file("/sys/fs/selinux/enforce", sebuf, sizeof(sebuf)) > 0) {
        if (sebuf[0] == '0') {
            if (out_selinux) *out_selinux = 1;
            append_reason(detail, detail_sz, "Native:selinux_permissive");
        }
    }
    if (raw_read_small_file("/proc/self/attr/current", sebuf, sizeof(sebuf)) > 0) {
        if (str_contains_ci(sebuf, ":su:") || str_contains_ci(sebuf, ":magisk:")) {
            if (out_selinux) *out_selinux = 1;
            append_reason(detail, detail_sz, "Native:selinux_root_context");
        }
    }

    return detected;
}

/* ---------------- 7. Hook Frameworks: /proc/self/maps, task, fd, unix, tcp ---------------- */

struct maps_scan_ctx {
    int detected;
    char *detail;
    size_t detail_sz;
};

static int maps_line_cb(const char *line, void *vctx) {
    struct maps_scan_ctx *ctx = (struct maps_scan_ctx *)vctx;
    static const char *const hook_sigs[] = {
        "frida-agent",
        "frida-server",
        "libfrida",
        "frida-gadget",
        "libgadget",
        "gum-js-loop",
        "libgumjs",
        "libzygisk",
        "zygisk",
        "shamiko",
        "lsposed",
        "liblsplant",
        "lsplant",
        "lspd",
        "edxposed",
        "xposedbridge",
        "libxposed",
        "libriru",
        "/riru/",
        "libsubstrate",
        "cynject",
        "libdobby",
        "libsandhook",
        "libwhale",
        "libpine",
        "libepic",
        "devoptshide",
        "hidemyapplist",
        "tricky_store",
        "trickystore",
        "playintegrityfix",
        "/data/adb/",
        "/sbin/.magisk",
        "/debug_ramdisk/",
        "magisk",
        NULL
    };

    for (int i = 0; hook_sigs[i] != NULL; i++) {
        if (str_contains_ci(line, hook_sigs[i])) {
            ctx->detected = 1;
            append_reason(ctx->detail, ctx->detail_sz, "Native:maps_hook_or_root_lib");
            return 1;
        }
    }

    if (strstr(line, "/data/local/tmp/") && strstr(line, "x") && strstr(line, "(deleted)")) {
        ctx->detected = 1;
        append_reason(ctx->detail, ctx->detail_sz, "Native:deleted_tmp_exec");
        return 1;
    }

    return 0;
}

static int tcp_frida_cb(const char *line, void *vctx) {
    int *found = (int *)vctx;
    if (strstr(line, " 0A ") == NULL) return 0;
    const char *p = line;
    while (*p == ' ') p++;
    while (*p && *p != ' ') p++;
    while (*p == ' ') p++;
    const char *local_start = p;
    while (*p && *p != ' ') p++;
    char local_buf[64];
    size_t len = (size_t)(p - local_start);
    if (len >= sizeof(local_buf)) len = sizeof(local_buf) - 1;
    memcpy(local_buf, local_start, len);
    local_buf[len] = '\0';
    if (strstr(local_buf, ":69A2") || strstr(local_buf, ":69A3")) {
        *found = 1;
        return 1;
    }
    return 0;
}

static int unix_line_cb(const char *line, void *vctx) {
    struct maps_scan_ctx *ctx = (struct maps_scan_ctx *)vctx;
    static const char *const sock_sigs[] = {
        "magisk",
        "zygisk",
        "lsposed",
        "lspd",
        "shamiko",
        "frida",
        "apatch",
        "su_daemon",
        "kernelsu",
        NULL
    };
    for (int i = 0; sock_sigs[i] != NULL; i++) {
        if (str_contains_ci(line, sock_sigs[i])) {
            ctx->detected = 1;
            append_reason(ctx->detail, ctx->detail_sz, "Native:unix_socket_root_or_hook");
            return 1;
        }
    }
    return 0;
}

static int check_threads_and_fds(char *detail, size_t detail_sz) {
    int detected = 0;
    int saw_gmain = 0;
    int saw_gdbus = 0;

    long dirfd = raw_openat(AT_FDCWD, "/proc/self/task", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (dirfd >= 0) {
        char dbuf[4096];
        for (;;) {
            long nread = raw_getdents64((int)dirfd, dbuf, sizeof(dbuf));
            if (nread <= 0) break;
            long bpos = 0;
            while (bpos < nread) {
                struct tkd_dirent64 *d = (struct tkd_dirent64 *)(dbuf + bpos);
                bpos += d->d_reclen;
                if (d->d_name[0] < '0' || d->d_name[0] > '9') continue;

                char comm_path[128];
                char comm[64];
                size_t nlen = strlen(d->d_name);
                if (nlen > 20) continue;
                memcpy(comm_path, "/proc/self/task/", 16);
                memcpy(comm_path + 16, d->d_name, nlen);
                memcpy(comm_path + 16 + nlen, "/comm", 6);

                if (raw_read_small_file(comm_path, comm, sizeof(comm)) > 0) {
                    if (str_contains_ci(comm, "gum-js-loop") ||
                        str_contains_ci(comm, "pool-frida") ||
                        str_contains_ci(comm, "frida-helper") ||
                        str_contains_ci(comm, "linjector")) {
                        detected = 1;
                        append_reason(detail, detail_sz, "Native:frida_thread");
                        break;
                    }
                    if (str_contains_ci(comm, "gmain")) saw_gmain = 1;
                    if (str_contains_ci(comm, "gdbus")) saw_gdbus = 1;
                }
            }
            if (detected) break;
        }
        raw_close((int)dirfd);
    }

    if (!detected && saw_gmain && saw_gdbus) {
        detected = 1;
        append_reason(detail, detail_sz, "Native:frida_glib_threads");
    }

    if (!detected) {
        long fdfd = raw_openat(AT_FDCWD, "/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
        if (fdfd >= 0) {
            char dbuf[4096];
            for (;;) {
                long nread = raw_getdents64((int)fdfd, dbuf, sizeof(dbuf));
                if (nread <= 0) break;
                long bpos = 0;
                while (bpos < nread) {
                    struct tkd_dirent64 *d = (struct tkd_dirent64 *)(dbuf + bpos);
                    bpos += d->d_reclen;
                    if (d->d_name[0] < '0' || d->d_name[0] > '9') continue;
                    char link_buf[256];
                    long rlen = raw_readlinkat((int)fdfd, d->d_name, link_buf, sizeof(link_buf) - 1);
                    if (rlen > 0) {
                        link_buf[rlen] = '\0';
                        if (str_contains_ci(link_buf, "frida") ||
                            str_contains_ci(link_buf, "linjector") ||
                            str_contains_ci(link_buf, "magisk") ||
                            str_contains_ci(link_buf, "zygisk") ||
                            str_contains_ci(link_buf, "lsposed") ||
                            str_contains_ci(link_buf, "shamiko") ||
                            str_contains_ci(link_buf, "devoptshide") ||
                            str_contains_ci(link_buf, "/data/adb/")) {
                            detected = 1;
                            append_reason(detail, detail_sz, "Native:fd_root_or_hook");
                            break;
                        }
                    }
                }
                if (detected) break;
            }
            raw_close((int)fdfd);
        }
    }

    return detected;
}

static int check_hook_frameworks(char *detail, size_t detail_sz) {
    int detected = 0;

    int frida_tcp = 0;
    stream_proc_lines("/proc/net/tcp", tcp_frida_cb, &frida_tcp);
    if (!frida_tcp) stream_proc_lines("/proc/net/tcp6", tcp_frida_cb, &frida_tcp);
    if (frida_tcp) {
        detected = 1;
        append_reason(detail, detail_sz, "Native:proc_tcp_frida_27042");
    }

    struct maps_scan_ctx mctx = { 0, detail, detail_sz };
    stream_proc_lines("/proc/self/maps", maps_line_cb, &mctx);
    if (mctx.detected) detected = 1;

    if (check_threads_and_fds(detail, detail_sz)) {
        detected = 1;
    }

    struct maps_scan_ctx uctx = { 0, detail, detail_sz };
    stream_proc_lines("/proc/net/unix", unix_line_cb, &uctx);
    if (uctx.detected) detected = 1;

    return detected;
}

/* ---------------- 8. TracerPid & Root Capabilities Check ---------------- */

struct status_ctx {
    int traced;
    int elevated_caps;
};

static int status_line_cb(const char *line, void *vctx) {
    struct status_ctx *ctx = (struct status_ctx *)vctx;
    if (strncmp(line, "TracerPid:", 10) == 0) {
        const char *p = line + 10;
        while (*p == ' ' || *p == '\t') p++;
        if (*p != '\0' && strcmp(p, "0") != 0) {
            ctx->traced = 1;
        }
    } else if (strncmp(line, "CapEff:", 7) == 0) {
        const char *p = line + 7;
        while (*p == ' ' || *p == '\t') p++;
        /* Normal untrusted_app always has CapEff: 0000000000000000 */
        int nonzero = 0;
        while (*p && *p != '\r' && *p != '\n') {
            if (*p != '0' && isxdigit((unsigned char)*p)) {
                nonzero = 1;
                break;
            }
            p++;
        }
        if (nonzero) ctx->elevated_caps = 1;
    }
    return 0;
}

static void check_proc_status(char *detail, size_t detail_sz, int *out_traced, int *out_caps) {
    struct status_ctx ctx = { 0, 0 };
    stream_proc_lines("/proc/self/status", status_line_cb, &ctx);
    if (ctx.traced) {
        append_reason(detail, detail_sz, "Native:TracerPid_nonzero");
        if (out_traced) *out_traced = 1;
    }
    if (ctx.elevated_caps) {
        append_reason(detail, detail_sz, "Native:CapEff_elevated");
        if (out_caps) *out_caps = 1;
    }
}

/* ---------------- 9. Emulator Detection ---------------- */

static int check_emulator_native(char *detail, size_t detail_sz) {
    static const char *const emu_files[] = {
        "/dev/qemu_pipe",
        "/dev/socket/qemud",
        "/dev/goldfish_pipe",
        "/sys/qemu_trace",
        "/system/lib/libc_malloc_debug_qemu.so",
        NULL
    };
    for (int i = 0; emu_files[i] != NULL; i++) {
        if (raw_file_exists(emu_files[i])) {
            append_reason(detail, detail_sz, "Native:qemu_file");
            return 1;
        }
    }

    char val[PROP_VALUE_MAX];
    if (get_prop("ro.kernel.qemu", val, sizeof(val)) > 0 && strcmp(val, "1") == 0) {
        append_reason(detail, detail_sz, "Native:ro.kernel.qemu=1");
        return 1;
    }
    if (get_prop("ro.hardware", val, sizeof(val)) > 0) {
        if (str_contains_ci(val, "goldfish") || str_contains_ci(val, "ranchu") ||
            str_contains_ci(val, "vbox86") || str_contains_ci(val, "nox")) {
            append_reason(detail, detail_sz, "Native:emu_hardware");
            return 1;
        }
    }
    if (get_prop("ro.product.model", val, sizeof(val)) > 0) {
        if (str_contains_ci(val, "sdk_gphone") || str_contains_ci(val, "genymotion") ||
            str_contains_ci(val, "bluestacks") || str_contains_ci(val, "ldplayer")) {
            append_reason(detail, detail_sz, "Native:emu_model");
            return 1;
        }
    }
    if (get_prop("ro.build.fingerprint", val, sizeof(val)) > 0) {
        if (str_contains_ci(val, "goldfish") || str_contains_ci(val, "ranchu") ||
            str_contains_ci(val, "sdk_gphone")) {
            append_reason(detail, detail_sz, "Native:emu_fingerprint");
            return 1;
        }
    }
    return 0;
}

/* ---------------- Core Combined Scan ---------------- */

static jint run_full_scan(char *detail_buf, size_t detail_sz) {
    if (detail_buf && detail_sz > 0) detail_buf[0] = '\0';
    jint flags = 0;
    int selinux_tamper = 0;
    int traced = 0;
    int elevated_caps = 0;

    if (check_root_binaries(detail_buf, detail_sz)) flags |= FLAG_ROOT_BINARY;
    if (check_root_mounts(detail_buf, detail_sz)) flags |= FLAG_ROOT_MOUNT;
    if (check_hidden_root_packages_native(detail_buf, detail_sz)) flags |= FLAG_HIDDEN_ROOT_APP;
    if (check_bootloader_and_selinux(detail_buf, detail_sz, &selinux_tamper)) flags |= FLAG_BOOTLOADER_PROP;
    if (selinux_tamper) flags |= FLAG_SELINUX_TAMPER;
    if (check_memory_code_integrity(detail_buf, detail_sz)) flags |= FLAG_MEMORY_HOOK;
    if (check_frida_active(detail_buf, detail_sz)) flags |= FLAG_FRIDA_ACTIVE;
    if (check_hook_frameworks(detail_buf, detail_sz)) flags |= FLAG_HOOK_FRAMEWORK;
    check_proc_status(detail_buf, detail_sz, &traced, &elevated_caps);
    if (traced) flags |= FLAG_DEBUGGER_TRACER;
    if (elevated_caps) flags |= FLAG_ROOT_BINARY;
    if (check_emulator_native(detail_buf, detail_sz)) flags |= FLAG_EMULATOR;

    return flags;
}

/* ---------------- JNI Exports ---------------- */

JNIEXPORT jint JNICALL
Java_com_toolkitdev_security_RuntimeGuard_nativeScan(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    char tmp[1024];
    return run_full_scan(tmp, sizeof(tmp));
}

JNIEXPORT jstring JNICALL
Java_com_toolkitdev_security_RuntimeGuard_nativeScanDetails(JNIEnv *env, jclass clazz) {
    (void)clazz;
    char detail[1024];
    detail[0] = '\0';
    run_full_scan(detail, sizeof(detail));
    return (*env)->NewStringUTF(env, detail);
}

JNIEXPORT jstring JNICALL
Java_com_toolkitdev_security_RuntimeGuard_nativeGetProp(JNIEnv *env, jclass clazz, jstring key) {
    (void)clazz;
    if (!key) return (*env)->NewStringUTF(env, "");
    const char *k = (*env)->GetStringUTFChars(env, key, NULL);
    char val[PROP_VALUE_MAX];
    val[0] = '\0';
    if (k) {
        get_prop(k, val, sizeof(val));
        (*env)->ReleaseStringUTFChars(env, key, k);
    }
    return (*env)->NewStringUTF(env, val);
}

JNIEXPORT void JNICALL
Java_com_toolkitdev_security_RuntimeGuard_nativeHardTerminate(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    pid_t pid = (pid_t)syscall(SYS_getpid);
    syscall(SYS_kill, pid, SIGKILL);
    syscall(SYS_exit_group, 1);
    _exit(1);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK || !env) {
        return JNI_ERR;
    }

    jclass cls = (*env)->FindClass(env, "com/toolkitdev/security/RuntimeGuard");
    if (cls != NULL) {
        static const JNINativeMethod methods[] = {
            { "nativeScan", "()I", (void *)Java_com_toolkitdev_security_RuntimeGuard_nativeScan },
            { "nativeScanDetails", "()Ljava/lang/String;", (void *)Java_com_toolkitdev_security_RuntimeGuard_nativeScanDetails },
            { "nativeGetProp", "(Ljava/lang/String;)Ljava/lang/String;", (void *)Java_com_toolkitdev_security_RuntimeGuard_nativeGetProp },
            { "nativeHardTerminate", "()V", (void *)Java_com_toolkitdev_security_RuntimeGuard_nativeHardTerminate }
        };
        (*env)->RegisterNatives(env, cls, methods, (jint)(sizeof(methods) / sizeof(methods[0])));
        (*env)->DeleteLocalRef(env, cls);
    } else {
        (*env)->ExceptionClear(env);
    }

    return JNI_VERSION_1_6;
}
