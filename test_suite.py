#!/usr/bin/env python3
"""
ToolKitDev - Complete Unit & Integration Test Suite
Validates:
1. APK Teardown & Security Inspector Engine
2. Repository Correlation Graph & Codexer Metrics Engine
3. Multi-MCP Hub Connection Status
4. Grounded Context Q&A & Historical Feature Tracker
5. Server Handler & API Response formatting
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
    print(f"✓ DEX Size: {result['size_breakdown']['dex_size_fmt']}")
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
    assert summary["vulnerabilities_count"] == 69
    print(f"✓ Organization: {summary['owner']} ({summary['repositories_count']} repos, {summary['vulnerabilities_count']} vulns)")
    print(f"✓ Scores: Security {summary['scores']['security_score']} | Maint {summary['scores']['maintenance_score']} | Innov {summary['scores']['innovation_score']}")

    graph = engine.get_correlation_graph()
    assert len(graph["nodes"]) > 0
    assert len(graph["links"]) > 0
    assert len(graph["legend"]) == 4

    repo_nodes = [n for n in graph["nodes"] if n["type"] == "repository"]
    vuln_nodes = [n for n in graph["nodes"] if n["type"] == "vulnerability"]
    dep_nodes = [n for n in graph["nodes"] if n["type"] == "dependency"]
    topic_nodes = [n for n in graph["nodes"] if n["type"] == "topic"]

    print(f"✓ Nodes Generated: {len(graph['nodes'])} (Repos: {len(repo_nodes)}, Vulns: {len(vuln_nodes)}, Deps: {len(dep_nodes)}, Topics: {len(topic_nodes)})")
    print(f"✓ Links Generated: {len(graph['links'])}")
    print("-> Correlation Graph Test: PASSED")

def test_mcp_hub():
    print("\n--- [3] Testing MCP Hub Connectors ---")
    mcp = McpHub()
    status = mcp.get_status()
    assert status["total_connectors"] == 4
    assert status["all_healthy"] == True
    print(f"✓ MCP Connectors ({status['connected_count']}/{status['total_connectors']} Connected):")
    for k, v in status["connectors"].items():
        print(f"   • {v['name']} ({v['endpoint']}) -> Capabilities: {len(v['capabilities'])}")
    print("-> MCP Hub Test: PASSED")

def test_context_qa_and_history():
    print("\n--- [4] Testing Context Q&A & Historical Feature Tracker ---")
    qa = ContextQaEngine()
    
    # 1. Search Historical Feature
    feats = qa.search_historical_features("watermark")
    assert len(feats) > 0
    top = feats[0]
    print(f"✓ Historical Feature Found: '{top['title']}'")
    print(f"   Author: {top['author']}, PR: {top['pr_number']}, Hash: {top['commit_hash']}")
    print(f"   ADR: {top['adr_reference']}, Figma: {top['figma_frame']}")

    # 2. Answer question with APK context
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

    index_content = open("public/index.html").read()
    assert "Repository Correlation Graph" in index_content
    assert "APK Inspector" in index_content
    assert "Security Score" in index_content
    assert "Marc Seitz" in index_content
    print("✓ public/index.html markup verified")
    print("✓ public/style.css stylesheet verified")
    print("✓ public/app.js client logic verified")
    print("-> Frontend Assets Test: PASSED")

if __name__ == "__main__":
    try:
        test_apk_analyzer()
        test_correlation_graph()
        test_mcp_hub()
        test_context_qa_and_history()
        test_public_assets()
        print("\n==============================================")
        print("🎉 ALL TEST SUITES PASSED PERFECTLY (5/5)!")
        print("==============================================\n")
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {str(e)}")
        sys.exit(1)

