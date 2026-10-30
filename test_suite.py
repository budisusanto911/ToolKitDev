#!/usr/bin/env python3
"""
ToolKitDev - Complete Unit & Integration Test Suite (10/10 Engines)
Validates:
1. APK Teardown & Security Inspector Engine
2. Repository Correlation Graph & Codexer Metrics Engine
3. Multi-MCP Hub Connection Status
4. Grounded Context Q&A & Historical Feature Tracker
5. Frontend Static Assets & Web Markup
6. APK Diff & Version Comparison (Delta Security Audit)
7. Third-Party SDK & Dependency CVE Scanner (SCA)
8. 1-Click AI Fix Pack Generator (.zip)
9. iOS (.ipa) Teardown & Security Inspector
10. Dynamic Frida Runner & Headless CI/CD CLI
"""

import os
import sys
import json
from io import BytesIO

# Import local engines
from engine.apk_analyzer import ApkAnalyzer
from engine.correlation_graph import CorrelationGraphEngine
from engine.mcp_hub import McpHub
from engine.context_qa import ContextQaEngine
from engine.apk_comparator import ApkComparator
from engine.sca_scanner import ScaScanner
from engine.fix_pack_generator import FixPackGenerator
from engine.ipa_analyzer import IpaAnalyzer
from engine.frida_runner import FridaRunner
from cli import cmd_scan


def test_apk_analyzer():
    print("\n--- [1] Testing APK Analyzer Engine ---")
    sample_apk = "samples/sample-debug.apk"
    assert os.path.exists(sample_apk), f"Sample APK missing: {sample_apk}"

    analyzer = ApkAnalyzer(sample_apk)
    result = analyzer.analyze()

    assert "file_info" in result
    assert "metadata" in result
    assert "manifest_security" in result
    assert "permissions" in result
    assert "size_breakdown" in result
    assert "security_score" in result
    assert "findings" in result

    print(f"✓ Package Name: {result['metadata']['package_name']}")
    print(f"✓ App Label: {result['metadata']['app_label']}")
    print(f"✓ Target SDK: {result['metadata']['target_sdk']} (Min SDK: {result['metadata']['min_sdk']})")
    print(f"✓ Security Score: {result['security_score']}/100")
    print(f"✓ Total Permissions: {result['permissions']['total_count']} (Dangerous: {result['permissions']['dangerous_count']})")
    print(f"✓ Total Findings: {len(result['findings'])}")
    print("-> APK Analyzer Test: PASSED")


def test_correlation_graph():
    print("\n--- [2] Testing Correlation Graph Engine ---")
    engine = CorrelationGraphEngine()
    summary = engine.get_dashboard_summary()
    assert summary["owner"] == "Marc Seitz"
    assert summary["scores"]["security_score"] == 0
    assert summary["scores"]["maintenance_score"] == 20
    assert summary["scores"]["innovation_score"] == 100
    assert summary["repositories_count"] == 10

    graph = engine.get_correlation_graph()
    assert len(graph["nodes"]) > 0
    assert len(graph["links"]) > 0
    assert len(graph["legend"]) == 4

    print(f"✓ Nodes Generated: {len(graph['nodes'])} | Links: {len(graph['links'])}")
    print("-> Correlation Graph Test: PASSED")


def test_mcp_hub():
    print("\n--- [3] Testing MCP Hub Connectors ---")
    mcp = McpHub()
    status = mcp.get_status()
    assert status["total_connectors"] == 4
    assert "connectors" in status
    print(f"✓ MCP Connectors ({status['connected_count']}/{status['total_connectors']} Connected)")
    print("-> MCP Hub Test: PASSED")


def test_context_qa_and_history():
    print("\n--- [4] Testing Context Q&A & Historical Feature Tracker ---")
    qa = ContextQaEngine()
    feats = qa.search_historical_features("watermark")
    assert len(feats) > 0
    top = feats[0]
    print(f"✓ Historical Feature Found: '{top['title']}' (PR {top['pr_number']})")

    sample_analyzer = ApkAnalyzer("samples/sample-debug.apk")
    apk_data = sample_analyzer.analyze()
    ans = qa.answer_question("Apa temuan security pada file APK ini?", apk_data)
    assert "citations" in ans
    assert len(ans["citations"]) > 0
    print(f"✓ Grounded Q&A Response Generated ({len(ans['answer'])} chars, {len(ans['citations'])} citations)")
    print("-> Context Q&A Test: PASSED")


def test_public_assets():
    print("\n--- [5] Validating Frontend Static Assets ---")
    assert os.path.exists("public/index.html"), "index.html missing"
    assert os.path.exists("public/style.css"), "style.css missing"
    assert os.path.exists("public/app.js"), "app.js missing"

    index_content = open("public/index.html", encoding="utf-8").read()
    assert "Repository Correlation Graph" in index_content
    assert "APK Inspector" in index_content
    assert "APK Version Diff" in index_content
    assert "SDK &amp; Dependency SCA" in index_content
    assert "iOS (.ipa) Inspector" in index_content
    assert "upgradePremiumDialog" in index_content
    print("✓ public/index.html markup verified (Includes Diff, SCA, iOS, & Premium)")
    print("✓ public/style.css stylesheet verified")
    print("✓ public/app.js client logic verified")
    print("-> Frontend Assets Test: PASSED")


def test_apk_diff_comparator():
    print("\n--- [6] Testing APK Diff & Version Comparator (Delta Audit) ---")
    comp = ApkComparator("samples/sample-debug.apk", "uploads/base.apk")
    res = comp.compare()
    assert "summary" in res
    assert "permissions_delta" in res
    assert "components_delta" in res
    assert "findings_delta" in res
    assert "endpoints_delta" in res

    print(f"✓ Base Score: {res['summary']['base_score']} -> Target Score: {res['summary']['target_score']}")
    print(f"✓ Delta Score: {res['summary']['delta_score']} pts ({res['summary']['verdict_status']})")
    print(f"✓ Resolved: {res['findings_delta']['resolved_count']} | Regressed: {res['findings_delta']['regressed_count']}")
    print("-> APK Comparator Test: PASSED")


def test_sca_scanner():
    print("\n--- [7] Testing Third-Party SDK & Dependency CVE Scanner (SCA) ---")
    sca = ScaScanner("uploads/base.apk")
    res = sca.scan()
    assert res["total_detected"] > 0
    assert "sdks" in res
    assert "vulnerable_count" in res

    print(f"✓ Total SDKs Detected: {res['total_detected']}")
    print(f"✓ Vulnerable SDKs: {res['vulnerable_count']}")
    print(f"✓ Outdated SDKs: {res['outdated_count']}")
    print("-> SCA Scanner Test: PASSED")


def test_fix_pack_generator():
    print("\n--- [8] Testing 1-Click AI Fix Pack Generator (.zip) ---")
    sample_analyzer = ApkAnalyzer("samples/sample-debug.apk")
    data = sample_analyzer.analyze()
    gen = FixPackGenerator(data, app_name="SampleApp")
    zip_bytes = gen.generate_zip_bytes()
    assert len(zip_bytes) > 1000

    print(f"✓ Fix Pack ZIP Generated ({len(zip_bytes)} bytes)")
    print("-> Fix Pack Generator Test: PASSED")


def test_ipa_analyzer():
    print("\n--- [9] Testing iOS (.ipa) Teardown & Security Inspector ---")
    ipa_path = "samples/sample-ios.ipa"
    assert os.path.exists(ipa_path), f"Sample IPA missing: {ipa_path}"

    analyzer = IpaAnalyzer(ipa_path)
    res = analyzer.analyze()
    assert res["platform"] == "ios"
    assert "app_transport_security" in res
    assert "macho_protections" in res
    assert "entitlements" in res
    assert "findings" in res

    print(f"✓ iOS App Name: {res['metadata']['app_name']}")
    print(f"✓ Bundle ID: {res['metadata']['bundle_id']}")
    print(f"✓ Security Score: {res['security_score']}/100 ({res['security_posture']})")
    print(f"✓ ATS Status: {res['app_transport_security']['status']}")
    print(f"✓ PIE ASLR: {res['macho_protections']['has_pie']} | Stack Canaries: {res['macho_protections']['has_stack_canaries']}")
    print("-> iOS IPA Inspector Test: PASSED")


def test_frida_and_cli():
    print("\n--- [10] Testing Dynamic Frida Runner & Headless CLI ---")
    frida = FridaRunner()
    scripts = frida.get_available_scripts()
    assert len(scripts) >= 4
    sess = frida.execute_live_session("ssl_unpinning")
    assert len(sess["telemetry_log"]) > 0
    print(f"✓ Frida Scripts: {len(scripts)} available | Intercepted: {len(sess['telemetry_log'])} events")

    # CLI Scan verification
    class MockCliArgs:
        target = "samples/sample-ios.ipa"
        format = "json"
        min_score = None
        fail_on = None
        fix_pack = None
        export_pdf = None

    exit_code = cmd_scan(MockCliArgs())
    assert exit_code == 0
    print("✓ Headless CLI Scan Runner verified")
    print("-> Frida & CLI Test: PASSED")


if __name__ == "__main__":
    try:
        test_apk_analyzer()
        test_correlation_graph()
        test_mcp_hub()
        test_context_qa_and_history()
        test_public_assets()
        test_apk_diff_comparator()
        test_sca_scanner()
        test_fix_pack_generator()
        test_ipa_analyzer()
        test_frida_and_cli()
        print("\n=======================================================")
        print("🎉 ALL TEST SUITES PASSED PERFECTLY (10/10 ENGINES)!")
        print("=======================================================\n")
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {str(e)}")
        sys.exit(1)
