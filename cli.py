#!/usr/bin/env python3
"""
ToolKitDev CLI - Headless Autonomous Mobile Security Inspector
Continuous DevSecOps CLI runner for GitHub Actions, GitLab CI, and terminal auditing.
Supports APK, AAB, and iOS IPA security scans, version diffs, and SCA dependency audits.
"""

import sys
import os
import json
import argparse
from typing import Dict, Any, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from engine.apk_analyzer import ApkAnalyzer
from engine.ipa_analyzer import IpaAnalyzer
from engine.apk_comparator import ApkComparator
from engine.sca_scanner import ScaScanner
from engine.fix_pack_generator import FixPackGenerator
from engine.pdf_reporter import ExecutivePdfReporter

# ANSI Terminal Colors
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
GRAY = "\033[90m"


def print_banner():
    banner = f"""{CYAN}{BOLD}
  ╔╦╗┌─┐┌─┐┬  ╦┌─┬┌┬┐╔╦╗┌─┐┬  ┬
   ║ │ ││ ││  ╠╩╗│ │  ║║├┤ └┐┌┘
   ╩ └─┘└─┘┴─┘╩ ╩┴ ┴ ═╩╝└─┘ └┘ 
   Autonomous Mobile DevSecOps Engine v2.0{RESET}
"""
    sys.stderr.write(banner)


def cmd_scan(args):
    file_path = args.target
    if not os.path.isfile(file_path):
        print(f"{RED}Error: File tidak ditemukan: {file_path}{RESET}", file=sys.stderr)
        return 2

    is_ios = file_path.lower().endswith(".ipa")
    print(f"{CYAN}➜ Memulai audit headless untuk:{RESET} {BOLD}{file_path}{RESET} ({'iOS IPA' if is_ios else 'Android APK/AAB'})")

    try:
        if is_ios:
            analyzer = IpaAnalyzer(file_path)
        else:
            analyzer = ApkAnalyzer(file_path)
        
        result = analyzer.analyze()
    except Exception as e:
        print(f"{RED}Gagal menganalisis biner: {e}{RESET}", file=sys.stderr)
        return 2

    score = result.get("security_score", 100)
    meta = result.get("metadata", {})
    findings = result.get("findings", [])
    app_name = meta.get("app_name") or meta.get("app_label") or os.path.basename(file_path)
    pkg = meta.get("package_name") or meta.get("bundle_id") or "unknown.app"

    # Export Fix Pack if requested
    if args.fix_pack:
        try:
            gen = FixPackGenerator(result, app_name=app_name)
            gen.save_zip(args.fix_pack)
            print(f"{GREEN}✓ Fix Pack ZIP berhasil disimpan ke:{RESET} {args.fix_pack}")
        except Exception as e:
            print(f"{RED}Gagal membuat Fix Pack: {e}{RESET}", file=sys.stderr)

    # Export PDF if requested
    if args.export_pdf:
        try:
            reporter = ExecutivePdfReporter(result, auditor_name="ToolKitDev CI/CD Runner", organization="Enterprise DevSecOps")
            reporter.save_pdf(args.export_pdf)
            print(f"{GREEN}✓ Laporan Audit PDF berhasil disimpan ke:{RESET} {args.export_pdf}")
        except Exception as e:
            print(f"{RED}Gagal membuat PDF Report: {e}{RESET}", file=sys.stderr)

    # Output formatting
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        # Table / Console Format
        score_color = GREEN if score >= 80 else (YELLOW if score >= 50 else RED)
        print(f"\n{BOLD}═══════════════════════════════════════════════════════════════════════{RESET}")
        print(f" {BOLD}Aplikasi:{RESET} {app_name} ({pkg})")
        print(f" {BOLD}Security Score:{RESET} {score_color}{BOLD}{score}/100{RESET} ({result.get('security_posture', 'UNKNOWN')})")
        print(f" {BOLD}Total Temuan:{RESET} {len(findings)} issues")
        print(f"{BOLD}═══════════════════════════════════════════════════════════════════════{RESET}\n")

        # Breakdown by severity
        crit_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
        med_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        low_count = sum(1 for f in findings if f.get("severity") == "LOW")

        print(f" {RED}{BOLD}● CRITICAL:{RESET} {crit_count}   {YELLOW}{BOLD}● HIGH:{RESET} {high_count}   {BLUE}{BOLD}● MEDIUM:{RESET} {med_count}   {GRAY}{BOLD}● LOW:{RESET} {low_count}\n")

        print(f"{BOLD}Daftar Temuan Keamanan Utama:{RESET}")
        for i, f in enumerate(findings[:10], 1):
            sev = f.get("severity", "LOW")
            color = RED if sev == "CRITICAL" else (YELLOW if sev == "HIGH" else BLUE)
            print(f"  {color}[{sev}]{RESET} {BOLD}{f.get('title')}{RESET}")
            print(f"    {GRAY}Kategori: {f.get('category')} | Ref: {f.get('id', 'N/A')}{RESET}")
            desc = f.get("description", "")
            if desc:
                short_desc = desc[:110] + ("..." if len(desc) > 110 else "")
                print(f"    {short_desc}")
            print()

        if len(findings) > 10:
            print(f"  {GRAY}... dan {len(findings) - 10} temuan lainnya.{RESET}\n")

    # CI/CD Quality Gate Evaluation
    exit_code = 0
    if args.min_score is not None and score < args.min_score:
        print(f"{RED}{BOLD}❌ CI GATE FAILED:{RESET} Skor keamanan ({score}) berada di bawah ambang batas minimum ({args.min_score}).", file=sys.stderr)
        exit_code = 1

    if args.fail_on:
        threshold = args.fail_on.upper()
        severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        if threshold in severities:
            min_idx = severities.index(threshold)
            failing_findings = [f for f in findings if severities.index(f.get("severity", "LOW")) >= min_idx]
            if failing_findings:
                print(f"{RED}{BOLD}❌ CI GATE FAILED:{RESET} Ditemukan {len(failing_findings)} celah berstatus {threshold} atau lebih tinggi.", file=sys.stderr)
                exit_code = 1

    if exit_code == 0:
        print(f"{GREEN}{BOLD}✓ CI GATE PASSED:{RESET} Biner memenuhi seluruh standar kepatuhan keamanan ToolKitDev.")

    return exit_code


def cmd_diff(args):
    base_file = args.base
    target_file = args.target

    if not os.path.isfile(base_file):
        print(f"{RED}Error: File baseline tidak ditemukan: {base_file}{RESET}", file=sys.stderr)
        return 2
    if not os.path.isfile(target_file):
        print(f"{RED}Error: File target tidak ditemukan: {target_file}{RESET}", file=sys.stderr)
        return 2

    print(f"{CYAN}➜ Membandingkan rilis basis vs target:{RESET}")
    print(f"   Basis  : {base_file}")
    print(f"   Target : {target_file}\n")

    try:
        comparator = ApkComparator(base_file, target_file)
        diff_res = comparator.compare()
    except Exception as e:
        print(f"{RED}Gagal membandingkan binary: {e}{RESET}", file=sys.stderr)
        return 2

    summary = diff_res.get("summary", {})
    delta = summary.get("delta_score", 0)
    verdict = summary.get("verdict_status", "NEUTRAL")

    if args.format == "json":
        print(json.dumps(diff_res, indent=2))
    else:
        v_color = GREEN if verdict == "IMPROVED" else (RED if verdict == "DEGRADED" else BLUE)
        print(f"{BOLD}═══════════════════════════════════════════════════════════════════════{RESET}")
        print(f" {BOLD}Skor Basis :{RESET} {summary.get('base_score')}/100  -->  {BOLD}Skor Target:{RESET} {summary.get('target_score')}/100")
        print(f" {BOLD}Delta Skor :{RESET} {v_color}{BOLD}{'+' if delta > 0 else ''}{delta} PTS ({verdict}){RESET}")
        print(f"{BOLD}═══════════════════════════════════════════════════════════════════════{RESET}\n")

        p_delta = diff_res.get("permissions_delta", {})
        c_delta = diff_res.get("components_delta", {})
        f_delta = diff_res.get("findings_delta", {})

        print(f"  ● Izin Baru Ditambahkan      : {p_delta.get('added_count', 0)} ({p_delta.get('dangerous_added_count', 0)} Dangerous)")
        print(f"  ● Komponen Baru Diekspos     : {c_delta.get('newly_exposed_count', 0)} exported")
        print(f"  ● Celah Terselesaikan        : {GREEN}{f_delta.get('resolved_count', 0)} fixed{RESET}")
        print(f"  ● Celah Regresi Baru         : {RED}{f_delta.get('regressed_count', 0)} new issues{RESET}\n")
        print(f"{summary.get('summary_narrative', '')}\n")

    # CI Check for regressions
    if args.fail_on_regression and (verdict == "DEGRADED" or delta < 0 or f_delta.get('regressed_count', 0) > 0):
        print(f"{RED}{BOLD}❌ CI REGRESSION GATE FAILED:{RESET} Rilis baru memperkenalkan regresi celah keamanan atau penurunan skor.", file=sys.stderr)
        return 1

    print(f"{GREEN}{BOLD}✓ CI REGRESSION GATE PASSED:{RESET} Tidak ada regresi keamanan yang melanggar threshold.")
    return 0


def cmd_sca(args):
    target = args.target
    if not os.path.isfile(target):
        print(f"{RED}Error: File tidak ditemukan: {target}{RESET}", file=sys.stderr)
        return 2

    print(f"{CYAN}➜ Memindai SDK pihak ketiga & CVE pada:{RESET} {target}\n")

    try:
        scanner = ScaScanner(target)
        res = scanner.scan()
    except Exception as e:
        print(f"{RED}Gagal memindai SCA: {e}{RESET}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(res, indent=2))
    else:
        print(f"{BOLD}Total SDK Terdeteksi:{RESET} {res.get('total_detected')} | {RED}{BOLD}Vulnerable:{RESET} {res.get('vulnerable_count')} | {YELLOW}{BOLD}Outdated:{RESET} {res.get('outdated_count')}\n")
        for s in res.get("sdks", []):
            status = f"{RED}[VULNERABLE]{RESET}" if s["is_vulnerable"] else f"{GREEN}[CLEAN]{RESET}"
            print(f" {status} {BOLD}{s['name']}{RESET} v{s['detected_version']} ({s['category']}) - {s['license']}")
            if s["is_vulnerable"]:
                for c in s.get("cves", []):
                    print(f"      ↳ {RED}{c['cve_id']}{RESET}: {c['title']} (CVSS {c['cvss']})")
                print(f"      ↳ {CYAN}Solusi:{RESET} Upgrade ke v{s.get('latest_safe_version')}")

    if args.fail_on_cve and res.get("vulnerable_count", 0) > 0:
        print(f"\n{RED}{BOLD}❌ CI SCA GATE FAILED:{RESET} Terdeteksi {res.get('vulnerable_count')} SDK dengan CVE berbahaya aktif.", file=sys.stderr)
        return 1

    print(f"\n{GREEN}{BOLD}✓ CI SCA GATE PASSED:{RESET} Seluruh dependensi pihak ketiga aman.")
    return 0


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="ToolKitDev CLI - Headless Autonomous Mobile Security & CI/CD Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Perintah audit yang tersedia")

    # Command: scan
    p_scan = subparsers.add_parser("scan", help="Pindai file APK, AAB, atau IPA secara headless")
    p_scan.add_argument("target", help="Path ke file .apk, .aab, atau .ipa")
    p_scan.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], help="Gagalkan exit code jika ada temuan pada tingkat ini")
    p_scan.add_argument("--min-score", type=int, help="Ambang batas minimum security score (0-100)")
    p_scan.add_argument("--format", choices=["table", "json"], default="table", help="Format output stdout")
    p_scan.add_argument("--fix-pack", help="Path untuk menyimpan bundel AI Fix Pack (.zip)")
    p_scan.add_argument("--export-pdf", help="Path untuk menyimpan laporan resmi PDF (.pdf)")

    # Command: diff
    p_diff = subparsers.add_parser("diff", help="Bandingkan dua rilis APK untuk audit regresi keamanan")
    p_diff.add_argument("base", help="Path ke file APK baseline (versi lama)")
    p_diff.add_argument("target", help="Path ke file APK target (versi rilis baru)")
    p_diff.add_argument("--fail-on-regression", action="store_true", help="Gagalkan exit code jika terjadi regresi keamanan")
    p_diff.add_argument("--format", choices=["table", "json"], default="table", help="Format output stdout")

    # Command: sca
    p_sca = subparsers.add_parser("sca", help="Pindai inventaris SDK pihak ketiga dan Advisory CVE")
    p_sca.add_argument("target", help="Path ke file APK atau AAB")
    p_sca.add_argument("--fail-on-cve", action="store_true", help="Gagalkan exit code jika ditemukan SDK berkerentanan CVE")
    p_sca.add_argument("--format", choices=["table", "json"], default="table", help="Format output stdout")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "diff":
        return cmd_diff(args)
    elif args.command == "sca":
        return cmd_sca(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
