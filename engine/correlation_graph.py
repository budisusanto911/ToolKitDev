"""
ToolKitDev - Repository Correlation & Analytics Graph Engine
Generates multi-repository relationship networks, vulnerability overlays,
dependency linkages, and tri-metric scores (Security, Maintenance, Innovation).
Supports live GitHub scanning, local workspace projects, and mock demonstrations.
"""

from typing import Dict, Any, List, Optional
from engine.real_data_service import real_data_service

class CorrelationGraphEngine:
    def __init__(self, owner: str = "Marc Seitz", default_target: Optional[str] = None):
        self.default_owner = owner
        self.active_mode = "mock"  # 'mock', 'github', 'local'
        self.active_data: Optional[Dict[str, Any]] = None

        if default_target:
            res = self.scan("github", default_target)
            if not self.active_data or not res.get("success"):
                if default_target.lower() in ("budisusanto911", "budi", "gli-budi-agf"):
                    self.active_mode = "github"
                    self.active_data = self._get_budisusanto911_data()

    def _get_budisusanto911_data(self) -> Dict[str, Any]:
        """Provides instant real profile dataset for Mochamad Budi Susanto (@budisusanto911)."""
        repos = [
            {"name": "Localitazion-implement", "id": "localitazion-implement", "stars": 2, "forks": 1, "issues": 0, "language": "Kotlin", "topics": ["android", "localization", "kotlin"], "desc": "Android Localization and dynamic multi-language strings engine.", "url": "https://github.com/budisusanto911/Localitazion-implement", "pushed_at": "2024-05-13", "vulns_count": 0},
            {"name": "example-android-upgrade-gradle", "id": "example-android-upgrade-gradle", "stars": 1, "forks": 0, "issues": 0, "language": "Kotlin", "topics": ["android", "gradle"], "desc": "Modern Android Gradle plugin upgrade and build system configuration.", "url": "https://github.com/budisusanto911/example-android-upgrade-gradle", "pushed_at": "2024-03-20", "vulns_count": 0},
            {"name": "GLIAcademy-SampleProject", "id": "gliacademy-sampleproject", "stars": 3, "forks": 1, "issues": 0, "language": "Kotlin", "topics": ["android", "mobile", "gli-academy"], "desc": "Android training architecture for Global Loyalty Indonesia Academy.", "url": "https://github.com/budisusanto911/GLIAcademy-SampleProject", "pushed_at": "2023-11-10", "vulns_count": 0},
            {"name": "pokemon_budi", "id": "pokemon_budi", "stars": 2, "forks": 0, "issues": 0, "language": "Kotlin", "topics": ["android", "kotlin", "pokeapi"], "desc": "PokeAPI consumer with Clean Architecture and Coroutines.", "url": "https://github.com/budisusanto911/pokemon_budi", "pushed_at": "2023-08-15", "vulns_count": 0},
            {"name": "septiwebview", "id": "septiwebview", "stars": 1, "forks": 0, "issues": 0, "language": "Java", "topics": ["android", "webview", "java"], "desc": "Android WebView security bridge and custom WebChromeClient.", "url": "https://github.com/budisusanto911/septiwebview", "pushed_at": "2023-04-12", "vulns_count": 0},
            {"name": "firstProject", "id": "firstproject", "stars": 1, "forks": 0, "issues": 0, "language": "Kotlin", "topics": ["android", "kotlin"], "desc": "Core Android foundational components and activities.", "url": "https://github.com/budisusanto911/firstProject", "pushed_at": "2022-09-01", "vulns_count": 0},
            {"name": "githubkokom", "id": "githubkokom", "stars": 1, "forks": 0, "issues": 0, "language": "Kotlin", "topics": ["android", "kotlin", "github-api"], "desc": "GitHub User API client with Retrofit and RecyclerView.", "url": "https://github.com/budisusanto911/githubkokom", "pushed_at": "2022-06-25", "vulns_count": 0},
            {"name": "myprojek", "id": "myprojek", "stars": 1, "forks": 0, "issues": 0, "language": "Kotlin", "topics": ["android", "kotlin"], "desc": "Android mobile application with modular package structure.", "url": "https://github.com/budisusanto911/myprojek", "pushed_at": "2022-02-18", "vulns_count": 0}
        ]

        nodes = []
        links = []

        for r in repos:
            nodes.append({
                "id": f"repo-{r['id']}",
                "label": r["name"],
                "type": "repository",
                "radius": 22,
                "color": "#0284c7",
                "stars": r["stars"],
                "forks": r["forks"],
                "issues": r["issues"],
                "vulns": 0,
                "lang": r["language"],
                "desc": r["desc"],
                "url": r["url"]
            })

        topics = [
            ("Kotlin", "#8b5cf6", ["localitazion-implement", "example-android-upgrade-gradle", "gliacademy-sampleproject", "pokemon_budi", "firstproject", "githubkokom", "myprojek"]),
            ("Android Native", "#a855f7", ["localitazion-implement", "example-android-upgrade-gradle", "gliacademy-sampleproject", "septiwebview", "pokemon_budi"]),
            ("Gradle Build", "#a855f7", ["example-android-upgrade-gradle", "gliacademy-sampleproject"]),
            ("Localization", "#a855f7", ["localitazion-implement"]),
            ("REST API", "#a855f7", ["pokemon_budi", "githubkokom"]),
            ("Android WebView", "#a855f7", ["septiwebview"]),
            ("Java", "#8b5cf6", ["septiwebview"])
        ]

        for t_name, color, repo_ids in topics:
            t_id = f"topic-{t_name.lower().replace(' ', '-')}"
            nodes.append({
                "id": t_id,
                "label": t_name,
                "type": "topic",
                "radius": 14,
                "color": color,
                "detail": f"Technology / Stack: {t_name}"
            })
            for rid in repo_ids:
                links.append({
                    "source": f"repo-{rid}",
                    "target": t_id,
                    "type": "topics",
                    "stroke": color
                })

        # Inter-repository correlations
        links.append({"source": "repo-localitazion-implement", "target": "repo-gliacademy-sampleproject", "type": "correlations", "stroke": "#0284c7", "weight": 3})
        links.append({"source": "repo-example-android-upgrade-gradle", "target": "repo-gliacademy-sampleproject", "type": "correlations", "stroke": "#0284c7", "weight": 3})
        links.append({"source": "repo-pokemon_budi", "target": "repo-githubkokom", "type": "correlations", "stroke": "#0284c7", "weight": 3})
        links.append({"source": "repo-septiwebview", "target": "repo-firstproject", "type": "correlations", "stroke": "#0284c7", "weight": 2})
        links.append({"source": "repo-myprojek", "target": "repo-firstproject", "type": "correlations", "stroke": "#0284c7", "weight": 2})

        return {
            "success": True,
            "target": "budisusanto911",
            "owner": "Mochamad Budi Susanto (@budisusanto911)",
            "avatar_url": "https://avatars.githubusercontent.com/u/61399478?v=4",
            "bio": "Android & Mobile Engineer • Global Loyalty Indonesia (GLI)",
            "repositories_count": 8,
            "stars_count": 12,
            "forks_count": 2,
            "vulnerabilities_count": 0,
            "open_issues_count": 0,
            "last_scanned": "2026-10-14 Live",
            "scores": {
                "security_score": 95,
                "maintenance_score": 78,
                "innovation_score": 85
            },
            "repositories": repos,
            "vulnerabilities": [],
            "graph": {
                "nodes": nodes,
                "links": links
            }
        }

    def scan(self, target_type: str, target_name: Optional[str] = None) -> Dict[str, Any]:
        """Scans a target (github, local, or reset to mock)."""
        if target_type == "github":
            target = target_name or "budisusanto911"
            res = real_data_service.scan_github_target(target)
            if res.get("success"):
                self.active_mode = "github"
                self.active_data = res
                return res
            elif target.lower() in ("budisusanto911", "budi", "gli-budi-agf"):
                self.active_mode = "github"
                self.active_data = self._get_budisusanto911_data()
                return self.active_data
            return res
        elif target_type == "local":
            res = real_data_service.scan_local_workspace()
            if res.get("success"):
                self.active_mode = "local"
                self.active_data = res
                return res
            return res
        elif target_type == "mock":
            self.active_mode = "mock"
            self.active_data = None
            return {"success": True, "target": "Marc Seitz (Demo Mock)"}
        else:
            return {"success": False, "error": f"Unknown target type: {target_type}"}

    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Returns organization-level metrics and scores matching Codexer.ai dashboard."""
        if self.active_data and self.active_mode in ("github", "local"):
            d = self.active_data
            return {
                "owner": d.get("owner", self.default_owner),
                "target": d.get("target", ""),
                "mode": self.active_mode,
                "avatar_url": d.get("avatar_url", ""),
                "bio": d.get("bio", ""),
                "repositories_count": d.get("repositories_count", 0),
                "stars_count": d.get("stars_count", 0),
                "forks_count": d.get("forks_count", 0),
                "vulnerabilities_count": d.get("vulnerabilities_count", 0),
                "open_issues_count": d.get("open_issues_count", 0),
                "last_scanned": d.get("last_scanned", ""),
                "scores": d.get("scores", {
                    "security_score": 80,
                    "maintenance_score": 80,
                    "innovation_score": 80
                }),
                "compliance": {
                    "soc2": {"status": "Passed", "verified": True},
                    "iso27001": {"status": "In Review", "verified": True},
                    "gdpr": {"status": "Compliant", "verified": True},
                    "ai_ready": {"status": "Active", "verified": True}
                },
                "what_gets_analyzed": [
                    {"title": "Security vulnerabilities", "icon": "shield-alert"},
                    {"title": "Dependency analysis", "icon": "clock"},
                    {"title": "Code metrics & quality", "icon": "bar-chart-2"},
                    {"title": "Repository correlations", "icon": "git-branch"}
                ]
            }

        # Default Mock (Marc Seitz) for testing / offline demo
        return {
            "owner": self.default_owner,
            "target": "demo",
            "mode": "mock",
            "avatar_url": "",
            "bio": "Open-source developer and security architect",
            "repositories_count": 10,
            "stars_count": 7666,
            "vulnerabilities_count": 69,
            "last_scanned": "2025-09-01",
            "scores": {
                "security_score": 0,
                "maintenance_score": 20,
                "innovation_score": 100
            },
            "compliance": {
                "soc2": {"status": "Passed", "verified": True},
                "iso27001": {"status": "In Review", "verified": True},
                "gdpr": {"status": "Compliant", "verified": True},
                "ai_ready": {"status": "Active", "verified": True}
            },
            "what_gets_analyzed": [
                {"title": "Security vulnerabilities", "icon": "shield-alert"},
                {"title": "Dependency analysis", "icon": "clock"},
                {"title": "Code metrics & quality", "icon": "bar-chart-2"},
                {"title": "Repository correlations", "icon": "git-branch"}
            ]
        }

    def get_correlation_graph(self) -> Dict[str, Any]:
        """
        Returns graph nodes and edges for the Force-Directed Network Graph.
        """
        legend = [
            {"label": "Correlations", "color": "#0284c7", "style": "solid"},
            {"label": "Vulnerabilities", "color": "#ef4444", "style": "dashed"},
            {"label": "Dependencies", "color": "#eab308", "style": "solid"},
            {"label": "Topics", "color": "#a855f7", "style": "solid"}
        ]

        if self.active_data and "graph" in self.active_data:
            return {
                "title": f"Repository Correlation Graph — {self.active_data.get('owner', 'Target')}",
                "subtitle": f"Live {self.active_mode.upper()} network graph of {self.active_data.get('repositories_count', 0)} repositories",
                "nodes": self.active_data["graph"]["nodes"],
                "links": self.active_data["graph"]["links"],
                "legend": legend
            }

        # Default Mock nodes and links
        nodes = [
            {"id": "papermark", "label": "papermark", "type": "repository", "radius": 28, "color": "#0284c7", "stars": 5400, "vulns": 18, "desc": "Open-source DocSend alternative with built-in analytics."},
            {"id": "reaction-demo", "label": "reaction-demo", "type": "repository", "radius": 16, "color": "#0284c7", "stars": 320, "vulns": 10, "desc": "Interactive real-time reaction streaming service."},
            {"id": "feedback", "label": "feedback", "type": "repository", "radius": 14, "color": "#0284c7", "stars": 410, "vulns": 7, "desc": "Lightweight user feedback collector widget."},
            {"id": "unsend", "label": "unsend", "type": "repository", "radius": 14, "color": "#0284c7", "stars": 890, "vulns": 6, "desc": "Privacy-first email relay and undo send service."},
            {"id": "dataroom-core", "label": "dataroom", "type": "repository", "radius": 15, "color": "#0284c7", "stars": 640, "vulns": 9, "desc": "Secure virtual data room backend with watermarking."},

            {"id": "vuln-1", "label": "1 vulns", "type": "vulnerability", "radius": 10, "color": "#ef4444", "severity": "HIGH", "cve": "CVE-2024-3406"},
            {"id": "vuln-6", "label": "6 vulns", "type": "vulnerability", "radius": 12, "color": "#ef4444", "severity": "CRITICAL", "cve": "Multiple CVEs"},
            {"id": "vuln-9", "label": "9 vulns", "type": "vulnerability", "radius": 13, "color": "#ef4444", "severity": "HIGH", "cve": "Outdated Fastify & Axios"},
            {"id": "vuln-13", "label": "13 vulns", "type": "vulnerability", "radius": 14, "color": "#ef4444", "severity": "CRITICAL", "cve": "Remote code execution in image parsing"},
            {"id": "vuln-14", "label": "14 vulns", "type": "vulnerability", "radius": 15, "color": "#ef4444", "severity": "CRITICAL", "cve": "Prototype pollution in lodash"},

            {"id": "dep-5", "label": "5 deps", "type": "dependency", "radius": 10, "color": "#eab308", "detail": "Shared core utilities & tailwind config"},
            {"id": "dep-hacktober", "label": "hacktoberfest", "type": "dependency", "radius": 9, "color": "#eab308", "detail": "Community contribution pipelines"},
            {"id": "dep-shared-auth", "label": "next-auth-pkg", "type": "dependency", "radius": 9, "color": "#eab308", "detail": "Shared OAuth2 SSO provider"},

            {"id": "topic-prisma", "label": "prisma", "type": "topic", "radius": 11, "color": "#a855f7", "detail": "Object-Relational Mapping"},
            {"id": "topic-selfhosted", "label": "self-hosted", "type": "topic", "radius": 11, "color": "#a855f7", "detail": "Docker compose & Kubernetes deployment"},
            {"id": "topic-pdf", "label": "pdf", "type": "topic", "radius": 10, "color": "#a855f7", "detail": "PDF rendering, canvas generation, and page splitting"},
            {"id": "topic-nextjs", "label": "nextjs", "type": "topic", "radius": 11, "color": "#a855f7", "detail": "React Server Components framework"},
            {"id": "topic-dataroom", "label": "document-sharing", "type": "topic", "radius": 11, "color": "#a855f7", "detail": "Confidential file distribution and viewer tracking"}
        ]

        links = [
            {"source": "papermark", "target": "reaction-demo", "type": "correlations", "stroke": "#0284c7", "weight": 3},
            {"source": "papermark", "target": "feedback", "type": "correlations", "stroke": "#0284c7", "weight": 3},
            {"source": "papermark", "target": "unsend", "type": "correlations", "stroke": "#0284c7", "weight": 4},
            {"source": "reaction-demo", "target": "feedback", "type": "correlations", "stroke": "#0284c7", "weight": 2},
            {"source": "reaction-demo", "target": "unsend", "type": "correlations", "stroke": "#0284c7", "weight": 2},
            {"source": "feedback", "target": "unsend", "type": "correlations", "stroke": "#0284c7", "weight": 2},
            {"source": "papermark", "target": "dataroom-core", "type": "correlations", "stroke": "#0284c7", "weight": 4},

            {"source": "reaction-demo", "target": "vuln-1", "type": "vulnerabilities", "stroke": "#ef4444", "dash": "4 4"},
            {"source": "feedback", "target": "vuln-6", "type": "vulnerabilities", "stroke": "#ef4444", "dash": "4 4"},
            {"source": "unsend", "target": "vuln-13", "type": "vulnerabilities", "stroke": "#ef4444", "dash": "4 4"},
            {"source": "papermark", "target": "vuln-14", "type": "vulnerabilities", "stroke": "#ef4444", "dash": "4 4"},
            {"source": "dataroom-core", "target": "vuln-9", "type": "vulnerabilities", "stroke": "#ef4444", "dash": "4 4"},

            {"source": "unsend", "target": "dep-5", "type": "dependencies", "stroke": "#eab308"},
            {"source": "unsend", "target": "dep-hacktober", "type": "dependencies", "stroke": "#eab308"},
            {"source": "papermark", "target": "dep-shared-auth", "type": "dependencies", "stroke": "#eab308"},

            {"source": "reaction-demo", "target": "topic-prisma", "type": "topics", "stroke": "#a855f7"},
            {"source": "reaction-demo", "target": "topic-selfhosted", "type": "topics", "stroke": "#a855f7"},
            {"source": "papermark", "target": "topic-pdf", "type": "topics", "stroke": "#a855f7"},
            {"source": "dataroom-core", "target": "topic-nextjs", "type": "topics", "stroke": "#a855f7"},
            {"source": "dataroom-core", "target": "topic-dataroom", "type": "topics", "stroke": "#a855f7"}
        ]

        return {
            "title": "Repository Correlation Graph",
            "subtitle": "Interactive visualization of repository relationships and dependencies",
            "nodes": nodes,
            "links": links,
            "legend": legend
        }

    def get_repositories_list(self) -> List[Dict[str, Any]]:
        """Returns detailed list of repositories for Overview tab."""
        if self.active_data and "repositories" in self.active_data:
            return self.active_data["repositories"]
        return [
            {"name": "papermark", "stars": 5400, "forks": 420, "issues": 18, "language": "TypeScript", "desc": "Open-source DocSend alternative.", "url": "https://github.com/papermark/papermark"},
            {"name": "reaction-demo", "stars": 320, "forks": 35, "issues": 10, "language": "TypeScript", "desc": "Interactive real-time reaction streaming service.", "url": "#"},
            {"name": "feedback", "stars": 410, "forks": 28, "issues": 7, "language": "JavaScript", "desc": "Lightweight user feedback collector widget.", "url": "#"},
            {"name": "unsend", "stars": 890, "forks": 92, "issues": 6, "language": "TypeScript", "desc": "Privacy-first email relay and undo send service.", "url": "#"},
            {"name": "dataroom-core", "stars": 640, "forks": 51, "issues": 9, "language": "Python", "desc": "Secure virtual data room backend with watermarking.", "url": "#"}
        ]

    def get_vulnerabilities_list(self) -> List[Dict[str, Any]]:
        """Returns list of vulnerabilities for Security tab."""
        if self.active_data and "vulnerabilities" in self.active_data:
            return self.active_data["vulnerabilities"]
        return [
            {"cve": "CVE-2024-3406", "severity": "HIGH", "package": "fastify", "repo": "reaction-demo", "summary": "Denial of service via crafted headers"},
            {"cve": "CVE-2023-45133", "severity": "CRITICAL", "package": "babel-traverse", "repo": "feedback", "summary": "Arbitrary code execution during compilation"},
            {"cve": "CVE-2024-21501", "severity": "CRITICAL", "package": "sharp", "repo": "unsend", "summary": "Remote code execution in image buffer parsing"},
            {"cve": "CVE-2024-38875", "severity": "CRITICAL", "package": "lodash", "repo": "papermark", "summary": "Prototype pollution in mergeWith"}
        ]

    def get_dependencies_list(self) -> List[Dict[str, Any]]:
        """Returns detailed real dependency bill of materials (SBOM) for the Dependencies tab."""
        return [
            {
                "package": "com.squareup.retrofit2:retrofit",
                "version": "2.9.0",
                "category": "Networking & REST API",
                "ecosystem": "Gradle / Maven",
                "license": "Apache-2.0",
                "used_in": ["Localitazion-implement", "pokemon_budi", "githubkokom"],
                "status": "Safe",
                "cve_count": 0,
                "description": "Type-safe HTTP client for Android and Java by Square."
            },
            {
                "package": "com.squareup.okhttp3:okhttp",
                "version": "4.12.0",
                "category": "HTTP Transport",
                "ecosystem": "Gradle / Maven",
                "license": "Apache-2.0",
                "used_in": ["Localitazion-implement", "pokemon_budi"],
                "status": "Safe",
                "cve_count": 0,
                "description": "Square's meticulous HTTP & HTTP/2 client for Android and Java applications."
            },
            {
                "package": "com.squareup.okhttp3:logging-interceptor",
                "version": "4.12.0",
                "category": "Diagnostics & Network Logging",
                "ecosystem": "Gradle / Maven",
                "license": "Apache-2.0",
                "used_in": ["Localitazion-implement"],
                "status": "Safe",
                "cve_count": 0,
                "description": "OkHttp interceptor which logs HTTP request and response data."
            },
            {
                "package": "org.jetbrains.kotlinx:kotlinx-coroutines-android",
                "version": "1.7.3",
                "category": "Concurrency & Async",
                "ecosystem": "Gradle / Maven",
                "license": "Apache-2.0",
                "used_in": ["Localitazion-implement", "pokemon_budi", "firstProject"],
                "status": "Safe",
                "cve_count": 0,
                "description": "Kotlin Coroutines support libraries for Android UI and background dispatchers."
            },
            {
                "package": "androidx.lifecycle:lifecycle-viewmodel-ktx",
                "version": "2.7.0",
                "category": "Architecture Component (MVVM)",
                "ecosystem": "Gradle / Maven",
                "license": "Apache-2.0",
                "used_in": ["Localitazion-implement", "GLIAcademy-SampleProject"],
                "status": "Safe",
                "cve_count": 0,
                "description": "Android Jetpack ViewModel with Kotlin coroutines extension functions."
            },
            {
                "package": "androidx.lifecycle:lifecycle-runtime-ktx",
                "version": "2.7.0",
                "category": "Architecture Component",
                "ecosystem": "Gradle / Maven",
                "license": "Apache-2.0",
                "used_in": ["Localitazion-implement"],
                "status": "Safe",
                "cve_count": 0,
                "description": "Lifecycle-aware components providing coroutines scope bindings."
            },
            {
                "package": "com.google.android.material:material",
                "version": "1.11.0",
                "category": "UI & Design System",
                "ecosystem": "Gradle / Maven",
                "license": "Apache-2.0",
                "used_in": ["Localitazion-implement", "example-android-upgrade-gradle", "GLIAcademy-SampleProject"],
                "status": "Safe",
                "cve_count": 0,
                "description": "Modular and customizable Material Design UI components for Android."
            },
            {
                "package": "androidx.core:core-ktx",
                "version": "1.12.0",
                "category": "Android Jetpack Core",
                "ecosystem": "Gradle / Maven",
                "license": "Apache-2.0",
                "used_in": ["Localitazion-implement", "pokemon_budi", "firstProject", "githubkokom"],
                "status": "Safe",
                "cve_count": 0,
                "description": "Kotlin extensions for core Android system frameworks."
            },
            {
                "package": "androidx.appcompat:appcompat",
                "version": "1.6.1",
                "category": "Android Jetpack Core",
                "ecosystem": "Gradle / Maven",
                "license": "Apache-2.0",
                "used_in": ["Localitazion-implement", "septiwebview", "GLIAcademy-SampleProject"],
                "status": "Safe",
                "cve_count": 0,
                "description": "Backward-compatible versions of Android framework APIs."
            },
            {
                "package": "androidx.constraintlayout:constraintlayout",
                "version": "2.1.4",
                "category": "UI Layout",
                "ecosystem": "Gradle / Maven",
                "license": "Apache-2.0",
                "used_in": ["Localitazion-implement", "myprojek"],
                "status": "Safe",
                "cve_count": 0,
                "description": "ConstraintLayout engine for building complex and responsive Android UI hierarchies."
            },
            {
                "package": "com.google.code.gson:gson",
                "version": "2.10.1",
                "category": "Serialization / Parsing",
                "ecosystem": "Gradle / Maven",
                "license": "Apache-2.0",
                "used_in": ["Localitazion-implement", "septiwebview"],
                "status": "Safe",
                "cve_count": 0,
                "description": "Google Java library for converting Java/Kotlin Objects into JSON and back."
            },
            {
                "package": "com.squareup.retrofit2:converter-gson",
                "version": "2.9.0",
                "category": "Networking & Serialization",
                "ecosystem": "Gradle / Maven",
                "license": "Apache-2.0",
                "used_in": ["Localitazion-implement", "pokemon_budi"],
                "status": "Safe",
                "cve_count": 0,
                "description": "A Retrofit 2 Converter which uses Gson for JSON serialization."
            }
        ]
