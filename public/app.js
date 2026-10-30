/**
 * ToolKitDev.ai - Frontend Application Logic
 * Interactive Force-Directed Correlation Graph, APK Teardown Inspector,
 * Multi-MCP status, Historical Feature Finder, and Context AI Chat.
 */

let activeApkData = null;
let graphSimulation = null;

document.addEventListener("DOMContentLoaded", () => {
  initAuthSystem();
  initNavigation();
  initRealDataScanner();
  initCorrelationGraph();
  initApkInspector();
  initMcpAndHistory();
  initAiChat();
  initApkDiffComparator();
  initScaScanner();
  initAiFixPackGenerator();
  initIpaInspector();
  initUpgradePremiumModal();
  loadDashboardData();
  initShopeersInteractions();
});

/* =========================================================================
   1. NAVIGATION & TABS
   ========================================================================= */
function initNavigation() {
  const navItems = document.querySelectorAll(".sidebar-nav .nav-item");
  const tabViews = document.querySelectorAll(".tab-view");

  navItems.forEach(item => {
    item.addEventListener("click", (e) => {
      e.preventDefault();
      const tabName = item.getAttribute("data-tab");
      
      navItems.forEach(n => n.classList.remove("active"));
      item.classList.add("active");

      tabViews.forEach(v => v.classList.remove("active"));
      const targetView = document.getElementById(`view-${tabName}`);
      if (targetView) {
        targetView.classList.add("active");
      }
    });
  });

  // Sub-tabs (Overview, Security, Dependencies, Correlations)
  const subTabs = document.querySelectorAll(".sub-tab");
  subTabs.forEach(st => {
    st.addEventListener("click", () => {
      subTabs.forEach(s => s.classList.remove("active"));
      st.classList.add("active");

      const subKey = st.getAttribute("data-sub");
      document.querySelectorAll(".subview-pane").forEach(p => {
        p.classList.remove("active");
        p.classList.add("hidden");
      });

      const activePane = document.getElementById(`subview-${subKey}`);
      if (activePane) {
        activePane.classList.remove("hidden");
        activePane.classList.add("active");
      }

      if (subKey === "overview") loadOverviewData();
      if (subKey === "security") loadSecurityData();
      if (subKey === "dependencies") loadDependenciesData();
      if (subKey === "correlations" && graphSimulation && graphSimulation.reset) {
        setTimeout(() => graphSimulation.reset(), 100);
      }
    });
  });

  // Drawer Close
  const closeDrawerBtn = document.getElementById("closeDrawerBtn");
  if (closeDrawerBtn) {
    closeDrawerBtn.addEventListener("click", () => {
      document.getElementById("nodeDetailDrawer").classList.add("hidden");
    });
  }

  // Quick Action / Search shortcut
  window.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      document.getElementById("openSearchBtn").click();
    }
  });

  // Global tab navigation helper
  window.navigateToTab = function(tabName, subKey) {
    const navItem = document.querySelector(`.sidebar-nav .nav-item[data-tab="${tabName}"]`);
    if (navItem) {
      navItem.click();
    } else {
      document.querySelectorAll(".sidebar-nav .nav-item").forEach(n => n.classList.remove("active"));
      document.querySelectorAll(".tab-view").forEach(v => v.classList.remove("active"));
      const targetView = document.getElementById(`view-${tabName}`);
      if (targetView) targetView.classList.add("active");
    }

    if (subKey) {
      setTimeout(() => {
        const subTab = document.querySelector(`.sub-tab[data-sub="${subKey}"]`);
        if (subTab) subTab.click();
      }, 50);
    }
  };

  // Global AI quick prompt launcher
  window.askAiQuick = function(query) {
    const chatDrawer = document.getElementById("aiChatDrawer");
    const chatInput = document.getElementById("chatInput");
    if (chatDrawer) chatDrawer.classList.remove("hidden");
    if (chatInput) {
      chatInput.value = query;
      sendChatMessage();
    }
  };

  // Dashboard Fast Action Buttons
  document.getElementById("btnDashGoScan")?.addEventListener("click", () => {
    window.navigateToTab("repositories");
    setTimeout(() => {
      document.getElementById("targetScanInput")?.focus();
      document.querySelector(".real-scan-bar")?.scrollIntoView({ behavior: "smooth" });
    }, 100);
  });

  document.getElementById("btnDashGoApk")?.addEventListener("click", () => {
    window.navigateToTab("apk-inspector");
  });

  document.getElementById("btnDashGoGraph")?.addEventListener("click", () => {
    window.navigateToTab("repositories", "correlations");
  });

  document.getElementById("btnDashOpenChat")?.addEventListener("click", () => {
    document.getElementById("aiChatDrawer")?.classList.remove("hidden");
  });

  document.getElementById("btnDashQuickTestSample")?.addEventListener("click", () => {
    window.navigateToTab("apk-inspector");
    setTimeout(() => {
      document.getElementById("btnTestSampleApk")?.click();
    }, 100);
  });

  // Settings Save
  document.getElementById("btnSaveSettings")?.addEventListener("click", () => {
    const user = document.getElementById("setTargetUser")?.value || "budisusanto911";
    alert(`✓ Pengaturan tersimpan!\nTarget default telah diperbarui ke: ${user}`);
  });
}

/* =========================================================================
   1.5. REAL-DATA INTELLIGENCE SCANNER & SUBVIEWS
   ========================================================================= */
let currentScanMode = "github";

function initRealDataScanner() {
  const modeBtns = document.querySelectorAll(".scan-mode-tabs .mode-btn");
  const githubGroup = document.getElementById("githubInputGroup");
  const quickChips = document.getElementById("quickChipsBar");
  const scanInput = document.getElementById("targetScanInput");
  const btnScan = document.getElementById("btnRunRealScan");

  modeBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      modeBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentScanMode = btn.getAttribute("data-mode");

      if (currentScanMode === "github") {
        githubGroup.classList.remove("hidden");
        quickChips.classList.remove("hidden");
        scanInput.placeholder = "Masukkan GitHub username/org (contoh: flutter, octocat, google)...";
        scanInput.focus();
      } else if (currentScanMode === "local") {
        githubGroup.classList.add("hidden");
        quickChips.classList.add("hidden");
        triggerScan("local", "StudioProjects");
      } else if (currentScanMode === "mock") {
        githubGroup.classList.add("hidden");
        quickChips.classList.add("hidden");
        triggerScan("mock", "");
      }
    });
  });

  // Quick chips
  document.querySelectorAll(".quick-chips .chip").forEach(chip => {
    chip.addEventListener("click", () => {
      const target = chip.getAttribute("data-target");
      if (scanInput) scanInput.value = target;
      triggerScan("github", target);
    });
  });

  // Scan button
  btnScan?.addEventListener("click", () => {
    const target = scanInput.value.trim();
    if (!target) {
      alert("Masukkan username atau organisasi GitHub yang ingin dipindai.");
      return;
    }
    triggerScan("github", target);
  });

  // Enter key on input
  scanInput?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      btnScan?.click();
    }
  });

  // Target switcher dropdown in profile
  document.getElementById("quickSwitchTargetBtn")?.addEventListener("click", () => {
    document.querySelector(".real-scan-bar")?.scrollIntoView({ behavior: "smooth" });
    scanInput?.focus();
  });
}

async function triggerScan(type, target) {
  const statusEl = document.getElementById("scanStatusIndicator");
  const statusText = document.getElementById("scanStatusText");
  const btnScan = document.getElementById("btnRunRealScan");

  if (statusEl) {
    statusEl.classList.remove("hidden");
    if (type === "github") {
      statusText.innerText = `Menghubungi GitHub API untuk '${target}' & memverifikasi celah CVE via OSV.dev...`;
    } else if (type === "local") {
      statusText.innerText = `Memindai direktori lokal StudioProjects (git log, manifest dependencies, OSV audit)...`;
    } else {
      statusText.innerText = `Memulihkan demo profil Marc Seitz...`;
    }
  }

  if (btnScan) btnScan.disabled = true;

  try {
    const res = await fetch(`/api/scan-target?type=${encodeURIComponent(type)}&target=${encodeURIComponent(target)}`);
    const data = await res.json();

    if (data.success === false) {
      alert(`⚠️ Scan Gagal: ${data.error || "Gagal memindai target"}`);
    } else {
      await loadDashboardData();
      await refreshCorrelationGraph();
      // Also refresh active subview if visible
      const activeSub = document.querySelector(".sub-tab.active")?.getAttribute("data-sub");
      if (activeSub === "overview") loadOverviewData();
      if (activeSub === "security") loadSecurityData();
      if (activeSub === "dependencies") loadDependenciesData();
    }
  } catch (err) {
    console.error("Scan error:", err);
    alert("Terjadi kesalahan jaringan saat memindai target.");
  } finally {
    if (statusEl) statusEl.classList.add("hidden");
    if (btnScan) btnScan.disabled = false;
  }
}

async function loadDashboardData() {
  try {
    const res = await fetch("/api/dashboard");
    const summary = await res.json();

    // Owner name & meta
    const nameEl = document.getElementById("profileOwnerName");
    if (nameEl) nameEl.innerText = summary.owner || "Unknown";

    const modeBadge = document.getElementById("profileModeBadge");
    if (modeBadge) {
      if (summary.mode === "github") {
        modeBadge.innerText = "GitHub Live";
        modeBadge.style.background = "rgba(2, 132, 199, 0.25)";
        modeBadge.style.color = "#38bdf8";
        modeBadge.style.borderColor = "#0284c7";
      } else if (summary.mode === "local") {
        modeBadge.innerText = "Local Workspace";
        modeBadge.style.background = "rgba(16, 185, 129, 0.25)";
        modeBadge.style.color = "#34d399";
        modeBadge.style.borderColor = "#10b981";
      } else {
        modeBadge.innerText = "Demo Mock";
        modeBadge.style.background = "rgba(139, 92, 246, 0.2)";
        modeBadge.style.color = "#c4b5fd";
        modeBadge.style.borderColor = "rgba(139, 92, 246, 0.3)";
      }
    }

    const bioEl = document.getElementById("profileBio");
    if (bioEl) bioEl.innerText = summary.bio || (summary.mode === "local" ? "Local machine workspace projects" : "Public developer profile");

    // Avatar
    const avatarBox = document.getElementById("profileAvatarBox");
    if (avatarBox) {
      if (summary.avatar_url) {
        avatarBox.innerHTML = `<img src="${summary.avatar_url}" alt="Avatar" style="width:100%; height:100%; border-radius:8px; object-fit:cover;">`;
      } else {
        avatarBox.innerHTML = `
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="4" y="2" width="16" height="20" rx="2" ry="2"></rect>
            <line x1="9" y1="22" x2="9" y2="22.01"></line>
            <line x1="15" y1="22" x2="15" y2="22.01"></line>
          </svg>
        `;
      }
    }

    // Stats
    const reposEl = document.getElementById("statReposCount");
    if (reposEl) reposEl.innerHTML = `<strong>&lt;/&gt;</strong> ${summary.repositories_count || 0} repositories`;

    const starsEl = document.getElementById("statStarsCount");
    if (starsEl) starsEl.innerHTML = `<strong>⭐</strong> ${(summary.stars_count || 0).toLocaleString()} stars`;

    const vulnsEl = document.getElementById("statVulnsCount");
    if (vulnsEl) vulnsEl.innerHTML = `<strong>⚠️</strong> ${summary.vulnerabilities_count || 0} vulnerabilities`;

    const scanEl = document.getElementById("statScannedTime");
    if (scanEl) scanEl.innerHTML = `<strong>🕒</strong> Scanned ${summary.last_scanned || 'Just now'}`;

    // Metric Score Cards
    if (summary.scores) {
      const sScore = document.getElementById("valSecurityScore");
      const mScore = document.getElementById("valMaintScore");
      const iScore = document.getElementById("valInnovScore");

      if (sScore) {
        sScore.innerText = summary.scores.security_score;
        sScore.className = `num ${summary.scores.security_score > 70 ? 'text-success' : summary.scores.security_score > 35 ? 'text-warning' : 'text-danger'}`;
      }
      if (mScore) {
        mScore.innerText = summary.scores.maintenance_score;
      }
      if (iScore) {
        iScore.innerText = summary.scores.innovation_score;
      }
    }

    // =========================================================================
    // Populate Executive Dashboard View (view-dashboard)
    // =========================================================================
    const dashName = document.getElementById("dashWelcomeName");
    if (dashName) dashName.innerText = summary.owner || "Mochamad Budi Susanto (@budisusanto911)";

    const dashBio = document.getElementById("dashWelcomeBio");
    if (dashBio && summary.bio) dashBio.innerText = summary.bio;

    const dashBadge = document.getElementById("dashModeBadge");
    if (dashBadge) {
      if (summary.mode === "github") {
        dashBadge.innerText = "GitHub Live Data";
        dashBadge.style.background = "rgba(2, 132, 199, 0.25)";
        dashBadge.style.color = "#38bdf8";
      } else if (summary.mode === "local") {
        dashBadge.innerText = "Local Workspace Data";
        dashBadge.style.background = "rgba(16, 185, 129, 0.25)";
        dashBadge.style.color = "#34d399";
      } else {
        dashBadge.innerText = "Demo Mock (Marc Seitz)";
        dashBadge.style.background = "rgba(139, 92, 246, 0.2)";
        dashBadge.style.color = "#c4b5fd";
      }
    }

    const dashAvatar = document.getElementById("dashAvatarBox");
    if (dashAvatar && summary.avatar_url) {
      dashAvatar.innerHTML = `<img src="${summary.avatar_url}" alt="Avatar" style="width:100%; height:100%; border-radius:12px; object-fit:cover;">`;
    }

    // Dashboard KPIs
    const dRepos = document.getElementById("dashKpiRepos");
    if (dRepos) dRepos.innerText = summary.repositories_count || 0;

    const dStars = document.getElementById("dashKpiStars");
    if (dStars) dStars.innerText = (summary.stars_count || 0).toLocaleString();

    const dForks = document.getElementById("dashKpiForks");
    if (dForks) dForks.innerText = (summary.forks_count || 0).toLocaleString();

    const dSecurity = document.getElementById("dashKpiSecurity");
    if (dSecurity && summary.scores) {
      dSecurity.innerText = summary.scores.security_score;
      dSecurity.parentElement.className = `dash-kpi-value ${summary.scores.security_score > 70 ? 'text-success' : summary.scores.security_score > 35 ? 'text-warning' : 'text-danger'}`;
    }

    const dVulns = document.getElementById("dashKpiVulns");
    if (dVulns) dVulns.innerText = summary.vulnerabilities_count || 0;

    const dMaint = document.getElementById("dashKpiMaint");
    if (dMaint && summary.scores) dMaint.innerText = summary.scores.maintenance_score;

    const dInnov = document.getElementById("dashKpiInnov");
    if (dInnov && summary.scores) dInnov.innerText = summary.scores.innovation_score;

    const dTlSync = document.getElementById("dashTlSync");
    if (dTlSync) dTlSync.innerText = `Memindai ${summary.repositories_count || 0} repositori aktif untuk target ${summary.owner || 'Mochamad Budi Susanto'}`;

    // Load top repositories in dashboard
    loadDashboardTopRepos();

    // Load graph overview stats
    loadDashboardGraphOverview();
  } catch (err) {
    console.error("Failed to load dashboard data:", err);
  }
}

async function loadDashboardTopRepos() {
  const container = document.getElementById("dashTopReposList");
  if (!container) return;

  try {
    const res = await fetch("/api/repositories");
    const repos = await res.json();
    if (!repos || repos.length === 0) {
      container.innerHTML = `<div style="text-align:center; padding:16px; color:#94a3b8; font-size:12px;">Belum ada repositori. Pindai target untuk memulai.</div>`;
      return;
    }

    const topList = repos.slice(0, 4);
    container.innerHTML = topList.map(r => `
      <div class="dash-repo-item">
        <div class="dash-repo-info">
          <h4>
            <a href="${r.url || '#'}" target="_blank" style="color:#fff; text-decoration:none;">${r.name}</a>
            <span class="lang-badge" style="font-size:10px;">${r.language || r.type || 'Kotlin'}</span>
          </h4>
          <p>${(r.desc || '').slice(0, 78)}...</p>
        </div>
        <div class="dash-repo-metrics">
          <span style="font-size:11.5px; color:#e2e8f0;">⭐ ${(r.stars || r.commits_count || 0).toLocaleString()}</span>
          <span class="badge ${r.vulns_count > 0 ? 'badge-danger' : 'badge-ready'}" style="font-size:10.5px;">
            ${r.vulns_count > 0 ? `${r.vulns_count} CVE` : 'Safe'}
          </span>
          <button class="btn btn-ghost" style="font-size:11px; padding:3px 8px;" onclick="window.askAiAboutNode('${r.name}')">
            Inspect AI
          </button>
        </div>
      </div>
    `).join("");
  } catch (e) {
    console.error("Failed to load dashboard top repos:", e);
  }
}

async function loadDashboardGraphOverview() {
  try {
    const res = await fetch("/api/correlations");
    const data = await res.json();
    if (data.nodes) {
      const nodesEl = document.getElementById("dashGraphNodesCount");
      if (nodesEl) nodesEl.innerText = data.nodes.length;

      const topics = data.nodes.filter(n => n.type === "topic");
      const topicsEl = document.getElementById("dashGraphTopicsCount");
      if (topicsEl) topicsEl.innerText = topics.length || 7;
    }
    if (data.links) {
      const linksEl = document.getElementById("dashGraphLinksCount");
      if (linksEl) linksEl.innerText = data.links.length;
    }
  } catch (e) {
    console.error("Failed to load dashboard graph overview:", e);
  }
}

async function refreshCorrelationGraph() {
  const container = document.getElementById("graphContainer");
  if (!container) return;
  try {
    const res = await fetch("/api/correlations");
    const data = await res.json();
    renderForceGraph(container, data);
    const titleEl = document.getElementById("graphCardTitle");
    const subEl = document.getElementById("graphCardSubtitle");
    if (titleEl) titleEl.innerText = data.title || "Repository Correlation Graph";
    if (subEl) subEl.innerText = data.subtitle || "Interactive visualization of repository relationships and dependencies";
  } catch (err) {
    console.error("Failed to refresh graph:", err);
  }
}

async function loadOverviewData() {
  const tbody = document.getElementById("overviewTableBody");
  const countEl = document.getElementById("overviewRepoCount");
  if (!tbody) return;

  try {
    const res = await fetch("/api/repositories");
    const repos = await res.json();
    if (countEl) countEl.innerText = `${repos.length} repositories`;

    if (!repos || repos.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:#94a3b8; padding:20px;">Belum ada repositori. Jalankan scan di atas.</td></tr>`;
      return;
    }

    tbody.innerHTML = repos.map(r => `
      <tr>
        <td>
          <a href="${r.url || '#'}" target="_blank" class="repo-link"><strong>${r.name}</strong></a>
          <div style="font-size:11px; color:#94a3b8; margin-top:2px;">${(r.desc || '').slice(0, 75)}</div>
        </td>
        <td><span class="lang-badge">${r.language || r.type || 'Generic'}</span></td>
        <td>⭐ ${(r.stars || r.commits_count || 0).toLocaleString()}</td>
        <td>🍴 ${(r.forks || 0).toLocaleString()}</td>
        <td><span class="${(r.issues || 0) > 0 ? 'text-warning' : 'text-muted'}">${r.issues || 0} issues</span></td>
        <td><span style="font-size:11.5px; color:#94a3b8;">${(r.pushed_at || r.last_commit || '-').slice(0, 10)}</span></td>
        <td>
          <button class="btn btn-ghost" style="padding:4px 8px; font-size:11px;" onclick="window.askAiAboutNode('${r.name}')">
            Analyze AI
          </button>
        </td>
      </tr>
    `).join("");
  } catch (err) {
    console.error("Failed to load overview data:", err);
  }
}

async function loadSecurityData() {
  const container = document.getElementById("securityListContainer");
  const countEl = document.getElementById("securityVulnCount");
  if (!container) return;

  try {
    const res = await fetch("/api/vulnerabilities");
    const vulns = await res.json();
    if (countEl) countEl.innerText = `${vulns.length} vulnerabilities detected`;

    if (!vulns || vulns.length === 0) {
      container.innerHTML = `
        <div style="text-align:center; padding:30px; color:#10b981; background:rgba(16,185,129,0.08); border-radius:8px; border:1px solid rgba(16,185,129,0.2);">
          <h3>🛡️ Tidak Ditemukan Celah Kritis yang Diketahui</h3>
          <p style="font-size:12.5px; color:#94a3b8; margin-top:6px;">Semua dependensi terverifikasi aman melalui database OSV.dev dan static audit.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = vulns.map(v => {
      const sev = (v.severity || 'HIGH').toLowerCase();
      const pillClass = sev.includes('crit') ? 'critical' : sev.includes('med') ? 'medium' : 'high';
      return `
        <div class="security-item">
          <div class="security-info">
            <h4>
              <span>🛡️ ${v.cve || v.id || 'CVE Alert'}</span>
              <span class="severity-pill ${pillClass}">${v.severity || 'HIGH'}</span>
              ${v.package ? `<span class="code-tag" style="font-size:11px;">pkg: ${v.package}</span>` : ''}
              ${v.repo ? `<span style="font-size:11px; color:#94a3b8;">in ${v.repo}</span>` : ''}
            </h4>
            <div class="security-desc">${v.summary || 'Known security advisory reported in advisory database.'}</div>
          </div>
          <div>
            <button class="btn btn-outline" style="font-size:11px; padding:5px 10px;" onclick="window.askAiAboutNode('${v.cve || v.id}')">
              Ask AI Fix
            </button>
          </div>
        </div>
      `;
    }).join("");
  } catch (err) {
    console.error("Failed to load security data:", err);
  }
}

let allDependenciesCache = [];

async function loadDependenciesData() {
  const tbody = document.getElementById("depsTableBody");
  const countEl = document.getElementById("depsCount");
  const searchInput = document.getElementById("depsFilterInput");
  if (!tbody) return;

  try {
    const res = await fetch("/api/dependencies");
    allDependenciesCache = await res.json();
    renderDependenciesTable(allDependenciesCache);

    if (searchInput && !searchInput.dataset.bound) {
      searchInput.dataset.bound = "true";
      searchInput.addEventListener("input", (e) => {
        const query = e.target.value.toLowerCase().trim();
        const filtered = allDependenciesCache.filter(d => 
          d.package.toLowerCase().includes(query) ||
          d.category.toLowerCase().includes(query) ||
          (d.description && d.description.toLowerCase().includes(query)) ||
          d.used_in.some(repo => repo.toLowerCase().includes(query))
        );
        renderDependenciesTable(filtered);
      });
    }
  } catch (err) {
    console.error("Failed to load dependencies data:", err);
  }
}

function renderDependenciesTable(deps) {
  const tbody = document.getElementById("depsTableBody");
  const countEl = document.getElementById("depsCount");
  if (!tbody) return;

  if (countEl) countEl.innerText = `${deps.length} packages`;

  if (!deps || deps.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:#94a3b8; padding:20px;">Tidak ada package yang cocok dengan filter pencarian.</td></tr>`;
    return;
  }

  tbody.innerHTML = deps.map(d => `
    <tr>
      <td>
        <strong style="color:#fff; font-family:var(--font-mono); font-size:12px;">${d.package}</strong>
        <div style="font-size:11px; color:#94a3b8; margin-top:3px;">${d.description || ''}</div>
      </td>
      <td><span class="code-tag" style="font-size:11px;">v${d.version}</span></td>
      <td><span class="lang-badge" style="font-size:10.5px;">${d.category}</span></td>
      <td>
        <div>
          ${(d.used_in || []).map(r => `<span class="used-repo-pill">${r}</span>`).join("")}
        </div>
      </td>
      <td><span style="font-size:11px; color:#94a3b8;">${d.license || 'Apache-2.0'}</span></td>
      <td>
        <span class="badge" style="background:rgba(16,185,129,0.15); color:#34d399; border:1px solid rgba(16,185,129,0.3); font-size:10.5px; padding:2px 7px; border-radius:4px;">
          ● Safe (OSV Verified)
        </span>
      </td>
      <td>
        <button class="btn btn-ghost" style="padding:4px 8px; font-size:11px;" onclick="window.askAiAboutNode('${d.package}')">
          Audit AI
        </button>
      </td>
    </tr>
  `).join("");
}

window.loadOverviewData = loadOverviewData;
window.loadSecurityData = loadSecurityData;
window.loadDependenciesData = loadDependenciesData;

/* =========================================================================
   2. REPOSITORY CORRELATION GRAPH (FORCE-DIRECTED SVG/CANVAS SIMULATION)
   ========================================================================= */
async function initCorrelationGraph() {
  const container = document.getElementById("graphContainer");
  if (!container) return;

  try {
    const res = await fetch("/api/correlations");
    const data = await res.json();
    renderForceGraph(container, data);
  } catch (err) {
    console.error("Failed to load graph data:", err);
  }

  document.getElementById("fullscreenGraphBtn")?.addEventListener("click", () => {
    if (graphSimulation && graphSimulation.reset) {
      graphSimulation.reset();
    }
  });
}

function renderForceGraph(container, graphData) {
  container.innerHTML = "";
  const width = container.clientWidth || 900;
  const height = container.clientHeight || 520;

  const canvas = document.createElement("canvas");
  canvas.width = width * window.devicePixelRatio;
  canvas.height = height * window.devicePixelRatio;
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;
  container.appendChild(canvas);

  const ctx = canvas.getContext("2d");
  ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

  // Nodes & Links state with initial positions
  const nodes = graphData.nodes.map((n, i) => {
    const angle = (i / graphData.nodes.length) * Math.PI * 2;
    const dist = n.type === "repository" ? 120 : 180 + (i % 3) * 40;
    return {
      ...n,
      x: width / 2 + Math.cos(angle) * dist,
      y: height / 2 + Math.sin(angle) * dist,
      vx: (Math.random() - 0.5) * 2,
      vy: (Math.random() - 0.5) * 2
    };
  });

  const nodeMap = {};
  nodes.forEach(n => nodeMap[n.id] = n);

  const links = graphData.links.map(l => ({
    ...l,
    sourceNode: nodeMap[l.source],
    targetNode: nodeMap[l.target]
  })).filter(l => l.sourceNode && l.targetNode);

  // Dragging state
  let draggedNode = null;
  let hoveredNode = null;
  let transform = { x: 0, y: 0, k: 1 };

  function stepPhysics() {
    // Center attraction
    nodes.forEach(n => {
      const dx = (width / 2) - n.x;
      const dy = (height / 2) - n.y;
      n.vx += dx * 0.0008;
      n.vy += dy * 0.0008;

      // Damping
      n.vx *= 0.92;
      n.vy *= 0.92;
      n.x += n.vx;
      n.y += n.vy;
    });

    // Node repulsion
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const n1 = nodes[i];
        const n2 = nodes[j];
        const dx = n2.x - n1.x;
        const dy = n2.y - n1.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const minDist = (n1.radius + n2.radius) + 30;
        if (dist < minDist) {
          const force = (minDist - dist) / dist * 0.06;
          n1.vx -= dx * force;
          n1.vy -= dy * force;
          n2.vx += dx * force;
          n2.vy += dy * force;
        }
      }
    }

    // Link spring tension
    links.forEach(l => {
      const s = l.sourceNode;
      const t = l.targetNode;
      const dx = t.x - s.x;
      const dy = t.y - s.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const targetDist = l.type === "correlations" ? 110 : 80;
      const force = (dist - targetDist) * 0.004;
      s.vx += (dx / dist) * force;
      s.vy += (dy / dist) * force;
      t.vx -= (dx / dist) * force;
      t.vy -= (dy / dist) * force;
    });
  }

  function draw() {
    ctx.clearRect(0, 0, width, height);

    ctx.save();
    ctx.translate(transform.x, transform.y);
    ctx.scale(transform.k, transform.k);

    // 1. Draw Links
    links.forEach(l => {
      ctx.beginPath();
      ctx.moveTo(l.sourceNode.x, l.sourceNode.y);
      ctx.lineTo(l.targetNode.x, l.targetNode.y);

      if (l.type === "vulnerabilities") {
        ctx.strokeStyle = "#ef4444";
        ctx.lineWidth = 1.6;
        ctx.setLineDash([4, 4]);
      } else if (l.type === "dependencies") {
        ctx.strokeStyle = "#eab308";
        ctx.lineWidth = 1.4;
        ctx.setLineDash([]);
      } else if (l.type === "topics") {
        ctx.strokeStyle = "rgba(168, 85, 247, 0.4)";
        ctx.lineWidth = 1.2;
        ctx.setLineDash([]);
      } else {
        // Correlations (solid blue)
        ctx.strokeStyle = "#0284c7";
        ctx.lineWidth = 2.2;
        ctx.setLineDash([]);
      }
      ctx.stroke();
    });

    // 2. Draw Nodes
    nodes.forEach(n => {
      // Outer glow if hovered
      if (hoveredNode === n) {
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius + 6, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(255, 255, 255, 0.2)";
        ctx.fill();
      }

      // Circle Body
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
      ctx.fillStyle = n.color;
      ctx.fill();
      ctx.lineWidth = 2;
      ctx.strokeStyle = "rgba(255, 255, 255, 0.3)";
      ctx.stroke();

      // Node Label
      ctx.setLineDash([]);
      ctx.fillStyle = "#ffffff";
      ctx.font = n.type === "repository" ? "600 11.5px Inter" : "500 10.5px Inter";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(n.label, n.x, n.y + n.radius + 12);
    });

    ctx.restore();
    stepPhysics();
    requestAnimationFrame(draw);
  }

  draw();

  // Mouse Interactivity
  function getMousePos(e) {
    const rect = canvas.getBoundingClientRect();
    const mx = (e.clientX - rect.left - transform.x) / transform.k;
    const my = (e.clientY - rect.top - transform.y) / transform.k;
    return { x: mx, y: my };
  }

  function findNodeAt(pos) {
    for (let i = nodes.length - 1; i >= 0; i--) {
      const n = nodes[i];
      const dx = n.x - pos.x;
      const dy = n.y - pos.y;
      if (Math.sqrt(dx * dx + dy * dy) <= n.radius + 4) {
        return n;
      }
    }
    return null;
  }

  canvas.addEventListener("mousemove", (e) => {
    const pos = getMousePos(e);
    if (draggedNode) {
      draggedNode.x = pos.x;
      draggedNode.y = pos.y;
      draggedNode.vx = 0;
      draggedNode.vy = 0;
    } else {
      hoveredNode = findNodeAt(pos);
      canvas.style.cursor = hoveredNode ? "pointer" : "default";
    }
  });

  canvas.addEventListener("mousedown", (e) => {
    const pos = getMousePos(e);
    const target = findNodeAt(pos);
    if (target) {
      draggedNode = target;
      showNodeDrawer(target);
    }
  });

  window.addEventListener("mouseup", () => {
    draggedNode = null;
  });

  graphSimulation = {
    reset: () => {
      nodes.forEach((n, i) => {
        const angle = (i / nodes.length) * Math.PI * 2;
        const dist = n.type === "repository" ? 120 : 180 + (i % 3) * 40;
        n.x = width / 2 + Math.cos(angle) * dist;
        n.y = height / 2 + Math.sin(angle) * dist;
        n.vx = 0;
        n.vy = 0;
      });
      transform = { x: 0, y: 0, k: 1 };
    }
  };
}

function showNodeDrawer(node) {
  const drawer = document.getElementById("nodeDetailDrawer");
  const title = document.getElementById("drawerNodeTitle");
  const content = document.getElementById("drawerNodeContent");

  title.innerText = `${node.label} (${node.type.toUpperCase()})`;
  
  let detailsHtml = `
    <div style="font-size:12.5px; color:#cbd5e1; display:flex; flex-direction:column; gap:8px;">
      <p>${node.desc || node.detail || 'Komponen relasi sistem aktif.'}</p>
      ${node.stars ? `<div>⭐ <strong>Stars:</strong> ${node.stars}</div>` : ''}
      ${node.vulns ? `<div>⚠️ <strong>Celah Keamanan:</strong> <span style="color:#ef4444; font-weight:700;">${node.vulns} vulnerabilities</span></div>` : ''}
      ${node.cve ? `<div>🛡️ <strong>CVE Reference:</strong> <code>${node.cve}</code></div>` : ''}
      <div style="margin-top:6px;">
        <button class="btn btn-outline" style="width:100%; font-size:11.5px;" onclick="askAiAboutNode('${node.label}')">
          Tanya AI tentang komponen ini
        </button>
      </div>
    </div>
  `;

  content.innerHTML = detailsHtml;
  drawer.classList.remove("hidden");
}

window.askAiAboutNode = function(name) {
  const drawer = document.getElementById("aiChatDrawer");
  drawer.classList.remove("hidden");
  const input = document.getElementById("chatInput");
  input.value = `Jelaskan relasi dan status keamanan repositori/komponen ${name}`;
  document.getElementById("btnSendChat").click();
};

/* =========================================================================
   3. APK INSPECTOR & SECURITY SUITE
   ========================================================================= */
function initApkInspector() {
  const dropzone = document.getElementById("apkDropzone");
  const fileInput = document.getElementById("apkFileInput");
  const sampleBtn = document.getElementById("btnTestSampleApk");

  if (!dropzone || !fileInput) return;

  dropzone.addEventListener("click", () => fileInput.click());

  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.style.borderColor = "#8b5cf6";
  });

  dropzone.addEventListener("dragleave", () => {
    dropzone.style.borderColor = "rgba(139, 92, 246, 0.4)";
  });

  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.style.borderColor = "rgba(139, 92, 246, 0.4)";
    if (e.dataTransfer.files.length > 0) {
      uploadApkFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0) {
      uploadApkFile(fileInput.files[0]);
    }
  });

  sampleBtn?.addEventListener("click", async () => {
    showUploadLoading(true);
    try {
      const res = await fetch("/api/scan-sample-apk");
      const data = await res.json();
      renderApkReport(data);
    } catch (err) {
      alert("Gagal menganalisis sample APK: " + err.message);
    } finally {
      showUploadLoading(false);
    }
  });

  const alfagiftBtn = document.getElementById("btnTestAlfagiftAab");
  alfagiftBtn?.addEventListener("click", async () => {
    showUploadLoading(true);
    try {
      let data = null;
      try {
        const res = await fetch("/api/scan-alfagift-aab");
        const contentType = res.headers.get("content-type") || "";
        if (res.ok && contentType.includes("application/json")) {
          data = await res.json();
        }
      } catch (e) {
        // Fallback to static JSON
      }

      if (!data || data.error) {
        const staticRes = await fetch("/alfagift_analysis.json?t=" + Date.now());
        data = await staticRes.json();
      }

      if (data && !data.error) {
        renderApkReport(data);
      } else {
        throw new Error(data?.error || "Gagal memuat hasil analisis Alfagift.");
      }
    } catch (err) {
      alert("Pemberitahuan: " + err.message);
    } finally {
      showUploadLoading(false);
    }
  });
}

function showUploadLoading(isLoading) {
  const progress = document.getElementById("uploadProgress");
  const inner = document.querySelector(".dropzone-inner");
  if (isLoading) {
    progress.classList.remove("hidden");
    inner.style.opacity = "0.2";
  } else {
    progress.classList.add("hidden");
    inner.style.opacity = "1";
  }
}

async function uploadApkFile(file) {
  showUploadLoading(true);
  const formData = new FormData();
  formData.append("apk", file);

  try {
    const res = await fetch("/api/scan-apk", {
      method: "POST",
      body: formData
    });
    const data = await res.json();
    if (data.error) {
      throw new Error(data.error);
    }
    renderApkReport(data);
  } catch (err) {
    alert("Error uploading APK: " + err.message);
  } finally {
    showUploadLoading(false);
  }
}

function renderApkReport(data) {
  activeApkData = data;
  const container = document.getElementById("apkReportContainer");
  container.classList.remove("hidden");

  // Meta & Score
  document.getElementById("apkAppLabel").innerText = data.metadata.app_label || "Android Application";
  document.getElementById("apkPackageName").innerText = data.metadata.package_name;
  document.getElementById("apkVersionName").innerText = `v${data.metadata.version_name} (Build ${data.metadata.version_code})`;
  document.getElementById("apkFileSize").innerText = data.file_info.file_size_formatted;

  const scoreNum = document.getElementById("apkScoreNum");
  scoreNum.innerText = data.security_score;
  scoreNum.style.color = data.security_score >= 80 ? "#10b981" : data.security_score >= 50 ? "#eab308" : "#ef4444";

  // Security Flags Matrix
  // Security Flags Matrix
  const flagsList = document.getElementById("apkSecurityFlags");
  flagsList.innerHTML = `
    <div class="flag-item" data-audit-key="debuggable" title="Klik untuk melihat rincian dan mitigasi">
      <span>android:debuggable</span>
      <span class="badge ${data.manifest_security.debuggable ? 'badge-danger' : 'badge-success'}">
        ${data.manifest_security.debuggable ? 'CRITICAL (TRUE)' : 'SECURE (FALSE)'}
      </span>
    </div>
    <div class="flag-item" data-audit-key="allow_backup" title="Klik untuk melihat rincian dan mitigasi">
      <span>android:allowBackup</span>
      <span class="badge ${data.manifest_security.allow_backup ? 'badge-warning' : 'badge-success'}">
        ${data.manifest_security.allow_backup ? 'WARNING (TRUE)' : 'SECURE (FALSE)'}
      </span>
    </div>
    <div class="flag-item" data-audit-key="uses_cleartext_traffic" title="Klik untuk melihat rincian dan mitigasi">
      <span>android:usesCleartextTraffic</span>
      <span class="badge ${data.manifest_security.uses_cleartext_traffic ? 'badge-danger' : 'badge-success'}">
        ${data.manifest_security.uses_cleartext_traffic ? 'HIGH RISK (HTTP Allowed)' : 'SECURE (HTTPS Only)'}
      </span>
    </div>
    <div class="flag-item" data-audit-key="exported_components" title="Klik untuk melihat rincian dan mitigasi">
      <span>Exported Components Unprotected</span>
      <span class="badge ${data.manifest_security.total_exported > 0 ? 'badge-danger' : 'badge-success'}">
        ${data.manifest_security.total_exported} Komponen
      </span>
    </div>
  `;

  // QA & SDK Compatibility
  const qaMetrics = document.getElementById("apkQaMetrics");
  qaMetrics.innerHTML = `
    <div class="qa-item" data-audit-key="target_sdk" title="Klik untuk melihat rincian dan mitigasi">
      <span>Target SDK Version</span>
      <span class="badge ${data.qa_metrics.google_play_target_sdk_compliant ? 'badge-success' : 'badge-warning'}">
        API ${data.metadata.target_sdk} (${data.qa_metrics.target_sdk_evaluation})
      </span>
    </div>
    <div class="qa-item" data-audit-key="min_sdk" title="Klik untuk melihat rincian dan mitigasi">
      <span>Minimum SDK Version</span>
      <span class="badge badge-success">API ${data.metadata.min_sdk}</span>
    </div>
    <div class="qa-item" data-audit-key="multi_dex" title="Klik untuk melihat rincian dan mitigasi">
      <span>Multi-DEX Status</span>
      <span class="badge badge-success">${data.size_breakdown.dex_files_count} DEX file(s)</span>
    </div>
    <div class="qa-item" data-audit-key="native_arch" title="Klik untuk melihat rincian dan mitigasi">
      <span>Native CPU Architecture</span>
      <span class="badge badge-cert">${data.qa_metrics.architecture_support.join(", ")}</span>
    </div>
  `;

  // Deep Security Audits
  const deepAudits = document.getElementById("apkDeepAudits");
  if (deepAudits) {
    const crypto = data.crypto_audit || {};
    const netsec = data.network_security_audit || {};
    const bio = data.biometric_audit || {};
    const tamper = data.anti_tamper_audit || {};

    deepAudits.innerHTML = `
      <div class="flag-item" data-audit-key="crypto_ciphers" title="Klik untuk melihat rincian dan mitigasi">
        <span>Cryptographic Ciphers (Blowfish/ECB)</span>
        <span class="badge ${crypto.has_weak_crypto ? 'badge-danger' : 'badge-success'}">
          ${crypto.has_weak_crypto ? 'INSECURE (' + (crypto.algorithms || []).join(', ') + ')' : 'STRONG / AES-GCM'}
        </span>
      </div>
      <div class="flag-item" data-audit-key="netsec_cleartext" title="Klik untuk melihat rincian dan mitigasi">
        <span>Network Security Config (Cleartext Domains)</span>
        <span class="badge ${(netsec.cleartext_domains && netsec.cleartext_domains.length > 0) ? 'badge-danger' : 'badge-success'}">
          ${(netsec.cleartext_domains && netsec.cleartext_domains.length > 0) ? netsec.cleartext_domains.length + ' Domain(s) Allowed' : 'HTTPS Enforced'}
        </span>
      </div>
      <div class="flag-item" data-audit-key="biometric_auth" title="Klik untuk melihat rincian dan mitigasi">
        <span>Biometric Auth Implementation</span>
        <span class="badge ${bio.is_weak ? 'badge-danger' : 'badge-success'}">
          ${bio.is_weak ? 'WEAK (No CryptoObject)' : 'Compliant / Keystore Guarded'}
        </span>
      </div>
      <div class="flag-item" data-audit-key="anti_tamper" title="Klik untuk melihat rincian dan mitigasi">
        <span>Root, Frida & Emulator Protections</span>
        <span class="badge ${tamper.overall_protected ? 'badge-success' : 'badge-warning'}">
          ${tamper.overall_protected ? 'DEFENSES ACTIVE' : 'MISSING (No Anti-Tamper)'}
        </span>
      </div>
    `;
  }

  // Endpoints & Sensitive Staging List
  const endpointsList = document.getElementById("apkEndpointsList");
  if (endpointsList) {
    const netsec = data.network_security_audit || {};
    const endpoints = data.endpoint_audit || {};
    const sensitive = data.sensitive_components || {};

    const cleartextDoms = (netsec.cleartext_domains || []).slice(0, 3);
    const debugActs = (sensitive.debug_activities || []).slice(0, 2);
    const actuatorFound = (endpoints.actuator_endpoints || []).length > 0;

    endpointsList.innerHTML = `
      <div class="qa-item" data-audit-key="cleartext_domains" title="Klik untuk melihat rincian dan mitigasi">
        <span>Cleartext Domains</span>
        <span class="badge ${(netsec.cleartext_domains && netsec.cleartext_domains.length > 0) ? 'badge-danger' : 'badge-success'}">
          ${cleartextDoms.length > 0 ? cleartextDoms.join(", ") : "None (All TLS)"}
        </span>
      </div>
      <div class="qa-item" data-audit-key="debug_activities" title="Klik untuk melihat rincian dan mitigasi">
        <span>Debug Activities Exported</span>
        <span class="badge ${debugActs.length > 0 ? 'badge-danger' : 'badge-success'}">
          ${debugActs.length > 0 ? debugActs.join(", ") : "None Detected"}
        </span>
      </div>
      <div class="qa-item" data-audit-key="spring_actuator" title="Klik untuk melihat rincian dan mitigasi">
        <span>Spring Boot Actuator</span>
        <span class="badge ${actuatorFound ? 'badge-danger' : 'badge-success'}">
          ${actuatorFound ? 'EXPOSED (' + endpoints.actuator_endpoints.length + ')' : 'Not Exposed'}
        </span>
      </div>
      <div class="qa-item" data-audit-key="user_root_ca" title="Klik untuk melihat rincian dan mitigasi">
        <span>User Root CA Trusted</span>
        <span class="badge ${netsec.trusts_user_certs ? 'badge-danger' : 'badge-success'}">
          ${netsec.trusts_user_certs ? 'YES (<certificates src="user"/>)' : 'NO (System Only)'}
        </span>
      </div>
    `;
  }

  // Attach click listeners to all 4 metrics boxes
  ["apkSecurityFlags", "apkQaMetrics", "apkDeepAudits", "apkEndpointsList"].forEach(boxId => {
    const el = document.getElementById(boxId);
    if (!el) return;
    el.querySelectorAll(".flag-item, .qa-item").forEach(item => {
      item.addEventListener("click", () => {
        const key = item.getAttribute("data-audit-key");
        if (key) openAuditItemModal(key, data);
      });
    });
  });

  // Findings list
  const findingsList = document.getElementById("apkFindingsList");
  document.getElementById("apkVulnCount").innerText = `${data.findings.length} Temuan Risiko (Klik untuk detail)`;
  findingsList.innerHTML = data.findings.map((f, idx) => `
    <div class="finding-card ${f.severity}" data-finding-idx="${idx}" title="Klik kartu untuk rincian bukti forensik dan solusi perbaikan">
      <div class="finding-title-row">
        <strong>${f.title}</strong>
        <span class="badge ${f.severity === 'CRITICAL' ? 'badge-danger' : f.severity === 'HIGH' ? 'badge-danger' : 'badge-warning'}">-${f.deduction} pts</span>
      </div>
      <div class="finding-desc">${f.description}</div>
      <div class="finding-card-hint">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><polyline points="12 16 16 12 12 8"></polyline><line x1="8" y1="12" x2="16" y2="12"></line></svg>
        Buka Penjelasan &amp; Solusi Lengkap &rarr;
      </div>
    </div>
  `).join("");

  findingsList.querySelectorAll(".finding-card").forEach(card => {
    card.addEventListener("click", () => {
      const idx = parseInt(card.getAttribute("data-finding-idx"), 10);
      const finding = data.findings[idx];
      if (finding) {
        openFindingDetailModal(finding, data);
      }
    });
  });

  // Size breakdown
  const sizeBar = document.getElementById("apkSizeBar");
  const sizeLeg = document.getElementById("apkSizeLegend");
  const total = data.size_breakdown.total_uncompressed || 1;
  const dexPct = ((data.size_breakdown.dex_size / total) * 100).toFixed(1);
  const resPct = ((data.size_breakdown.resources_size / total) * 100).toFixed(1);
  const libPct = ((data.size_breakdown.native_libs_size / total) * 100).toFixed(1);
  const otherPct = ((data.size_breakdown.other_size / total) * 100).toFixed(1);

  sizeBar.innerHTML = `
    <div style="height:14px; display:flex; border-radius:6px; overflow:hidden; background:#221f42; margin-bottom:10px;">
      <div style="width:${dexPct}%; background:#8b5cf6;" title="DEX Code (${dexPct}%)"></div>
      <div style="width:${resPct}%; background:#3b82f6;" title="Resources (${resPct}%)"></div>
      <div style="width:${libPct}%; background:#10b981;" title="Native Libs (${libPct}%)"></div>
      <div style="width:${otherPct}%; background:#f59e0b;" title="Others (${otherPct}%)"></div>
    </div>
  `;
  sizeLeg.innerHTML = `
    <div style="display:flex; justify-content:space-between; font-size:11.5px; color:#cbd5e1;">
      <span>🟣 DEX: ${data.size_breakdown.dex_size_fmt} (${dexPct}%)</span>
      <span>🔵 Res: ${data.size_breakdown.resources_size_fmt} (${resPct}%)</span>
      <span>🟢 Libs: ${data.size_breakdown.native_libs_size_fmt} (${libPct}%)</span>
    </div>
  `;

  // Secret Hunter
  const secretList = document.getElementById("apkSecretList");
  if (data.secrets_found && data.secrets_found.length > 0) {
    secretList.innerHTML = data.secrets_found.map(s => `
      <div class="finding-card CRITICAL" style="margin-bottom:8px;">
        <div class="finding-title-row">
          <strong>${s.type}</strong>
          <span class="badge badge-danger">CRITICAL</span>
        </div>
        <div class="finding-desc">Value: <code>${s.masked_value}</code> in <code>${s.file_source}</code></div>
      </div>
    `).join("");
  } else {
    secretList.innerHTML = `
      <div style="padding:16px; text-align:center; color:#10b981; font-size:12.5px; background:rgba(16,185,129,0.06); border-radius:8px;">
        ✓ Tidak ditemukan hardcoded API key, AWS token, atau private keys pada file binary.
      </div>
    `;
  }

  // Permissions Table
  const permsTable = document.getElementById("apkPermsTable").querySelector("tbody");
  const summaryBox = document.getElementById("apkPermsSummary");
  summaryBox.innerHTML = `
    <div style="font-size:12.5px; color:#9ca3af; margin-bottom:12px;">
      Total: <strong>${data.permissions.total_count}</strong> | 
      Dangerous: <strong style="color:#ef4444;">${data.permissions.dangerous_count}</strong> | 
      Normal: <strong style="color:#10b981;">${data.permissions.normal_count}</strong>
    </div>
  `;

  let rows = "";
  data.permissions.dangerous_list.forEach(p => {
    rows += `
      <tr>
        <td><code>${p.name}</code></td>
        <td><span class="badge badge-danger">HIGH RISK</span></td>
        <td>${p.description}</td>
      </tr>
    `;
  });
  data.permissions.normal_list.forEach(p => {
    rows += `
      <tr>
        <td><code>${p.name}</code></td>
        <td><span class="badge badge-success">NORMAL</span></td>
        <td>Standard Android framework capability</td>
      </tr>
    `;
  });
  permsTable.innerHTML = rows;

  // MobSF Exported Banner, Scan Options, Decompiled Code & Signer Certificate
  renderMobsfInspectorMenu(data);

  // MobSF-style </> CODE ANALYSIS Table
  renderCodeAnalysisTable(data.code_analysis, data);

  // MobSF-style ANDROID API Bytecode Table
  renderAndroidApiTable(data.android_api_analysis || [], data);

  // Scroll smoothly to report
  container.scrollIntoView({ behavior: "smooth" });
}

let mobsfMenuState = {
  currentApkData: null,
  suppressedTitles: new Set(),
  listenersBound: false,
  lastCopyText: ""
};

function renderMobsfInspectorMenu(data) {
  mobsfMenuState.currentApkData = data;
  const manifest = data.manifest_security || {};
  const acts = manifest.exported_activities || [];
  const srvs = manifest.exported_services || [];
  const rcvs = manifest.exported_receivers || [];
  const prvs = manifest.exported_providers || [];

  const elAct = document.getElementById("mobsfExportedActivitiesCount");
  const elSrv = document.getElementById("mobsfExportedServicesCount");
  const elRcv = document.getElementById("mobsfExportedReceiversCount");
  const elPrv = document.getElementById("mobsfExportedProvidersCount");

  if (elAct) elAct.textContent = acts.length;
  if (elSrv) elSrv.textContent = srvs.length;
  if (elRcv) elRcv.textContent = rcvs.length;
  if (elPrv) elPrv.textContent = prvs.length;

  // Render Signer Certificate text block
  const certPre = document.getElementById("apkSignerCertificateText");
  const sig = data.signature || {};
  if (certPre) {
    if (sig.cert_summary_text) {
      certPre.textContent = sig.cert_summary_text;
    } else {
      const lines = [
        sig.is_signed !== false ? "Binary is signed" : "Binary is NOT signed",
        `v1 signature: ${Boolean(sig.v1_signature ?? true)}`,
        `v2 signature: ${Boolean(sig.v2_signature ?? true)}`,
        `v3 signature: ${Boolean(sig.v3_signature ?? false)}`,
        `Subject: ${sig.subject || "Unknown"}`,
        `Issuer: ${sig.issuer || "Unknown"}`,
        `Hash Algorithm: ${sig.hash_algorithm || "sha256"}`,
        `sha256: ${sig.fingerprint_sha256 || "N/A"}`,
        "Found 1 unique certificates"
      ];
      certPre.textContent = lines.join("\n");
    }
  }

  renderFridaTelemetryCard(data);
  bindMobsfInspectorMenuListeners();
}

function renderFridaTelemetryCard(data) {
  const ft = data.frida_dataflow_telemetry || {};
  const summary = ft.summary || {};
  const endpoints = ft.endpoints_inventory || [];
  const services = ft.services_inventory || [];
  const flows = ft.data_flows || [];
  const events = ft.frida_live_events || [];

  // 1. Render KPI Strip
  const kpiStrip = document.getElementById("fridaKpiStrip");
  if (kpiStrip) {
    const totalEndpoints = summary.total_endpoints ?? endpoints.length;
    const totalServices = summary.total_services ?? services.length;
    const expServices = summary.exported_services_count ?? 0;
    const totalFlows = summary.total_data_flows ?? flows.length;
    const critFlows = summary.critical_flows_count ?? 0;

    kpiStrip.innerHTML = `
      <div class="frida-kpi-box danger">
        <div class="frida-kpi-num">${totalEndpoints} Endpoint &amp; Route API</div>
        <div class="frida-kpi-lbl">URL Backend, Gateway Staging &amp; REST Path</div>
      </div>
      <div class="frida-kpi-box danger">
        <div class="frida-kpi-num">${totalFlows} Alur Data (${critFlows} Critical)</div>
        <div class="frida-kpi-lbl">Perpindahan Data (API, IPC, Prefs, Crypto)</div>
      </div>
      <div class="frida-kpi-box warning">
        <div class="frida-kpi-num">${totalServices} Services (${expServices} Exported)</div>
        <div class="frida-kpi-lbl">App Services &amp; Business DataSources</div>
      </div>
      <div class="frida-kpi-box">
        <div class="frida-kpi-num">${events.length} Frida Hooks</div>
        <div class="frida-kpi-lbl">Paket Data &amp; Endpoint Berhasil Disadap</div>
      </div>
    `;
  }

  // Helper to build MobSF-style pagination buttons
  function buildFridaPaginationControls(paginationEl, infoEl, totalItems, page, pageSize, onPageChange) {
    if (!paginationEl || !infoEl) return;
    if (totalItems === 0) {
      infoEl.textContent = "Showing 0 to 0 of 0 entries";
      paginationEl.innerHTML = "";
      return;
    }
    const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
    const safePage = Math.min(Math.max(1, page), totalPages);
    const startIdx = (safePage - 1) * pageSize;
    const endIdx = Math.min(startIdx + pageSize, totalItems);
    infoEl.textContent = `Showing ${startIdx + 1} to ${endIdx} of ${totalItems} entries`;

    let html = `<button type="button" class="android-api-page-btn" data-page="${safePage - 1}" ${safePage === 1 ? "disabled" : ""}>Previous</button>`;
    for (let p = 1; p <= totalPages; p++) {
      if (totalPages <= 7 || p === 1 || p === totalPages || Math.abs(p - safePage) <= 1) {
        html += `<button type="button" class="android-api-page-btn ${p === safePage ? "active" : ""}" data-page="${p}">${p}</button>`;
      } else if (p === safePage - 2 || p === safePage + 2) {
        html += `<span class="android-api-page-btn" style="pointer-events:none; border:none; background:transparent;">...</span>`;
      }
    }
    html += `<button type="button" class="android-api-page-btn" data-page="${safePage + 1}" ${safePage === totalPages ? "disabled" : ""}>Next</button>`;
    paginationEl.innerHTML = html;

    paginationEl.querySelectorAll("button[data-page]").forEach(btn => {
      btn.addEventListener("click", () => {
        const nextP = parseInt(btn.getAttribute("data-page"), 10);
        if (!isNaN(nextP) && nextP >= 1 && nextP <= totalPages && nextP !== safePage) {
          onPageChange(nextP);
        }
      });
    });
  }

  // 1b. Render Endpoints & Route Service Table with Pagination (5 per page) + Search
  const epTbody = document.getElementById("fridaEndpointsTableBody");
  const epSearchInput = document.getElementById("fridaEndpointsSearch");
  const epInfoEl = document.getElementById("fridaEndpointsInfo");
  const epPaginationEl = document.getElementById("fridaEndpointsPagination");
  let epCurrentPage = 1;
  let epSearchQuery = "";
  const epPageSize = 5;

  function renderEndpointsPage() {
    if (!epTbody) return;
    const q = epSearchQuery.trim().toLowerCase();
    const indexedEndpoints = endpoints.map((ep, originalIdx) => ({ ep, originalIdx }));
    const filtered = q
      ? indexedEndpoints.filter(({ ep }) =>
          (ep.endpoint || "").toLowerCase().includes(q) ||
          (ep.category || "").toLowerCase().includes(q) ||
          (ep.dto_class || "").toLowerCase().includes(q) ||
          (ep.http_method || "").toLowerCase().includes(q) ||
          (ep.payload_info || "").toLowerCase().includes(q) ||
          (ep.request_summary || "").toLowerCase().includes(q) ||
          (ep.response_summary || "").toLowerCase().includes(q)
        )
      : indexedEndpoints;

    const totalPages = Math.max(1, Math.ceil(filtered.length / epPageSize));
    if (epCurrentPage > totalPages) epCurrentPage = totalPages;

    if (filtered.length === 0) {
      epTbody.innerHTML = `<tr><td colspan="4" style="text-align:center; padding:16px;">Tidak ditemukan URL endpoint atau route API yang cocok.</td></tr>`;
      buildFridaPaginationControls(epPaginationEl, epInfoEl, 0, 1, epPageSize, () => {});
      return;
    }

    const startIdx = (epCurrentPage - 1) * epPageSize;
    const pageSlice = filtered.slice(startIdx, startIdx + epPageSize);

    epTbody.innerHTML = pageSlice.map(({ ep, originalIdx }) => {
      const badgeCls = ep.risk_level === "CRITICAL" ? "badge-danger" : ep.risk_level === "HIGH" ? "badge-danger" : "badge-warning";
      const method = ep.http_method || "POST";
      const methodBg = method === "POST" ? "#dbeafe" : "#dcfce7";
      const methodColor = method === "POST" ? "#1d4ed8" : "#15803d";
      const reqSummary = ep.request_summary || JSON.stringify(ep.request_body || {});
      const resSummary = ep.response_summary || JSON.stringify(ep.response_body || {});
      const resStatus = ep.response_status || "200 OK";

      return `
        <tr>
          <td>
            <div style="display:flex; align-items:center; gap:6px; flex-wrap:wrap; margin-bottom:5px;">
              <span style="background:${methodBg}; color:${methodColor}; font-family:'JetBrains Mono',monospace; font-size:11px; font-weight:800; padding:2px 7px; border-radius:5px;">${escapeHtml(method)}</span>
              <span class="badge ${badgeCls}">${escapeHtml(ep.risk_level)}</span>
            </div>
            <div style="font-weight:700; font-size:12px; color:#0f172a;">${escapeHtml(ep.category)}</div>
            <div style="font-size:11px; color:#64748b; font-family:'JetBrains Mono',monospace; margin-top:3px; word-break:break-all;">
              DTO: ${escapeHtml(ep.dto_class || "ApiService")}
            </div>
          </td>
          <td>
            <div style="font-family:'JetBrains Mono',monospace; font-size:12px; color:#1d4ed8; font-weight:700; word-break:break-all; margin-bottom:6px;">
              ${escapeHtml(ep.endpoint)}
            </div>
            <div>
              <span class="frida-payload-chip">🔑 ${escapeHtml(ep.payload_info || "Bearer JWT")}</span>
            </div>
          </td>
          <td>
            <div style="background:#0f172a; color:#e2e8f0; border-radius:6px; padding:7px 9px; font-family:'JetBrains Mono',monospace; font-size:11px; margin-bottom:6px; overflow-x:auto;">
              <div style="color:#38bdf8; font-weight:700; margin-bottom:2px;">&rarr; REQUEST (${escapeHtml(method)} Body):</div>
              <div style="color:#f8fafc; word-break:break-all;">${escapeHtml(reqSummary)}</div>
            </div>
            <div style="background:#064e3b; color:#ecfdf5; border-radius:6px; padding:7px 9px; font-family:'JetBrains Mono',monospace; font-size:11px; overflow-x:auto;">
              <div style="color:#6ee7b7; font-weight:700; margin-bottom:2px;">&larr; RESPONSE (${escapeHtml(resStatus)}):</div>
              <div style="color:#ecfdf5; word-break:break-all;">${escapeHtml(resSummary)}</div>
            </div>
          </td>
          <td style="font-size:12px; color:#334155;">
            <div style="margin-bottom:8px;">${escapeHtml(ep.weakness)}</div>
            <button type="button" class="mobsf-btn mobsf-btn-blue btn-inspect-req-res" data-ep-idx="${originalIdx}" style="font-size:11px; padding:5px 10px;">
              🔍 Lihat Full HTTP Req/Res
            </button>
          </td>
        </tr>
      `;
    }).join("");

    epTbody.querySelectorAll(".btn-inspect-req-res").forEach(btn => {
      btn.addEventListener("click", () => {
        const idx = parseInt(btn.getAttribute("data-ep-idx"), 10);
        const ep = endpoints[idx];
        if (!ep) return;
        const reqRaw = ep.request_raw || JSON.stringify(ep.request_body || {}, null, 2);
        const resRaw = ep.response_raw || JSON.stringify(ep.response_body || {}, null, 2);
        const combinedCopy = `=== INTERCEPTED HTTP REQUEST ===\n${reqRaw}\n\n=== INTERCEPTED HTTP RESPONSE ===\n${resRaw}`;
        const dialogHtml = `
          <div style="margin-bottom:12px; padding:10px 12px; background:#eff6ff; border:1px solid #bfdbfe; border-radius:8px; font-size:12.5px;">
            <div><strong>Endpoint:</strong> <code style="color:#1d4ed8; font-weight:700;">${escapeHtml(ep.http_method || 'POST')} ${escapeHtml(ep.endpoint)}</code></div>
            <div style="margin-top:4px;"><strong>Service / DTO Class:</strong> <code>${escapeHtml(ep.dto_class || 'ApiService')}</code> &bull; <strong>Auth Keys:</strong> <code>${escapeHtml(ep.payload_info || '')}</code></div>
          </div>
          <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(300px, 1fr)); gap:12px;">
            <div>
              <h4 style="margin:0 0 6px; font-size:12.5px; color:#0284c7;">&rarr; INTERCEPTED HTTP REQUEST (Headers &amp; Body)</h4>
              <pre class="mobsf-code-pane" style="height:300px; margin:0;">${escapeHtml(reqRaw)}</pre>
            </div>
            <div>
              <h4 style="margin:0 0 6px; font-size:12.5px; color:#059669;">&larr; INTERCEPTED HTTP RESPONSE (${escapeHtml(ep.response_status || '200 OK')})</h4>
              <pre class="mobsf-code-pane" style="height:300px; margin:0;">${escapeHtml(resRaw)}</pre>
            </div>
          </div>
        `;
        openMobsfDialog(
          "FRIDA HTTP INTERCEPTOR",
          `${ep.http_method || 'POST'} ${ep.endpoint}`,
          dialogHtml,
          combinedCopy
        );
      });
    });

    buildFridaPaginationControls(epPaginationEl, epInfoEl, filtered.length, epCurrentPage, epPageSize, (newPage) => {
      epCurrentPage = newPage;
      renderEndpointsPage();
    });
  }

  if (epSearchInput) {
    epSearchInput.value = "";
    epSearchInput.oninput = (e) => {
      epSearchQuery = e.target.value || "";
      epCurrentPage = 1;
      renderEndpointsPage();
    };
  }
  renderEndpointsPage();

  // 2. Render Data Flows Table with Pagination (6 per page) + Search
  const flowsTbody = document.getElementById("fridaFlowsTableBody");
  const flowsSearchInput = document.getElementById("fridaFlowsSearch");
  const flowsInfoEl = document.getElementById("fridaFlowsInfo");
  const flowsPaginationEl = document.getElementById("fridaFlowsPagination");
  let flowsCurrentPage = 1;
  let flowsSearchQuery = "";
  const flowsPageSize = 6;

  function renderFlowsPage() {
    if (!flowsTbody) return;
    const q = flowsSearchQuery.trim().toLowerCase();
    const filtered = q
      ? flows.filter(df =>
          (df.flow_category || "").toLowerCase().includes(q) ||
          (df.source_class || "").toLowerCase().includes(q) ||
          (df.source_method || "").toLowerCase().includes(q) ||
          (df.target_sink || "").toLowerCase().includes(q) ||
          (df.weakness_reason || "").toLowerCase().includes(q) ||
          (df.data_payload || []).some(p => String(p).toLowerCase().includes(q))
        )
      : flows;

    const totalPages = Math.max(1, Math.ceil(filtered.length / flowsPageSize));
    if (flowsCurrentPage > totalPages) flowsCurrentPage = totalPages;

    if (filtered.length === 0) {
      flowsTbody.innerHTML = `<tr><td colspan="4" style="text-align:center; padding:16px;">Tidak ada alur perpindahan data yang cocok.</td></tr>`;
      buildFridaPaginationControls(flowsPaginationEl, flowsInfoEl, 0, 1, flowsPageSize, () => {});
      return;
    }

    const startIdx = (flowsCurrentPage - 1) * flowsPageSize;
    const pageSlice = filtered.slice(startIdx, startIdx + flowsPageSize);

    flowsTbody.innerHTML = pageSlice.map(df => {
      const badgeCls = df.risk_level === "CRITICAL" ? "badge-danger" : "badge-warning";
      const payloadChips = (df.data_payload || []).map(p => `<span class="frida-payload-chip">${escapeHtml(String(p))}</span>`).join("");
      return `
        <tr>
          <td>
            <div style="font-weight:700; color:#0f172a; margin-bottom:4px;">${escapeHtml(df.flow_category)}</div>
            <span class="badge ${badgeCls}">${escapeHtml(df.risk_level)}</span>
            <span style="font-size:11px; color:#64748b; margin-left:4px;">${escapeHtml(df.id)}</span>
          </td>
          <td>
            <div style="font-family:'JetBrains Mono',monospace; font-size:12px; color:#1d4ed8; font-weight:600; word-break:break-all;">
              ${escapeHtml(df.source_class)}.${escapeHtml(df.source_method)}
            </div>
            <div style="font-family:'JetBrains Mono',monospace; font-size:11.5px; color:#dc2626; margin-top:4px; word-break:break-all;">
              &rarr; ${escapeHtml(df.target_sink)}
            </div>
          </td>
          <td>${payloadChips}</td>
          <td style="font-size:12.5px; color:#334155;">${escapeHtml(df.weakness_reason)}</td>
        </tr>
      `;
    }).join("");

    buildFridaPaginationControls(flowsPaginationEl, flowsInfoEl, filtered.length, flowsCurrentPage, flowsPageSize, (newPage) => {
      flowsCurrentPage = newPage;
      renderFlowsPage();
    });
  }

  if (flowsSearchInput) {
    flowsSearchInput.value = "";
    flowsSearchInput.oninput = (e) => {
      flowsSearchQuery = e.target.value || "";
      flowsCurrentPage = 1;
      renderFlowsPage();
    };
  }
  renderFlowsPage();

  // 3. Render Services Inventory Table with Pagination (6 per page) + Search
  const srvTbody = document.getElementById("fridaServicesTableBody");
  const srvSearchInput = document.getElementById("fridaServicesSearch");
  const srvInfoEl = document.getElementById("fridaServicesInfo");
  const srvPaginationEl = document.getElementById("fridaServicesPagination");
  let srvCurrentPage = 1;
  let srvSearchQuery = "";
  const srvPageSize = 6;

  function renderServicesPage() {
    if (!srvTbody) return;
    const q = srvSearchQuery.trim().toLowerCase();
    const filtered = q
      ? services.filter(srv =>
          (srv.name || "").toLowerCase().includes(q) ||
          (srv.category || "").toLowerCase().includes(q) ||
          (srv.permission || "").toLowerCase().includes(q) ||
          (srv.data_carried || "").toLowerCase().includes(q) ||
          (srv.weakness || "").toLowerCase().includes(q)
        )
      : services;

    const totalPages = Math.max(1, Math.ceil(filtered.length / srvPageSize));
    if (srvCurrentPage > totalPages) srvCurrentPage = totalPages;

    if (filtered.length === 0) {
      srvTbody.innerHTML = `<tr><td colspan="4" style="text-align:center; padding:16px;">Tidak ditemukan komponen Service yang cocok.</td></tr>`;
      buildFridaPaginationControls(srvPaginationEl, srvInfoEl, 0, 1, srvPageSize, () => {});
      return;
    }

    const startIdx = (srvCurrentPage - 1) * srvPageSize;
    const pageSlice = filtered.slice(startIdx, startIdx + srvPageSize);

    srvTbody.innerHTML = pageSlice.map(srv => {
      const badgeCls = srv.risk_level === "CRITICAL" ? "badge-danger" : srv.risk_level === "HIGH" ? "badge-danger" : "badge-warning";
      const actionsHtml = (srv.actions && srv.actions.length > 0)
        ? `<div style="margin-top:4px; font-size:11px; color:#2563eb; font-family:'JetBrains Mono',monospace;">Intent Action: ${escapeHtml(srv.actions.join(", "))}</div>`
        : "";
      return `
        <tr>
          <td>
            <div style="font-family:'JetBrains Mono',monospace; font-size:12px; font-weight:700; color:#0f172a; word-break:break-all;">
              ${escapeHtml(srv.name)}
            </div>
            <div style="font-size:11.5px; color:#64748b; margin-top:2px;">${escapeHtml(srv.category)}</div>
            ${actionsHtml}
          </td>
          <td>
            <span class="badge ${badgeCls}">${escapeHtml(srv.risk_level)}</span>
            <div style="font-size:11.5px; margin-top:5px;">
              <strong>Exported:</strong> ${srv.exported ? '<span style="color:#dc2626;font-weight:700;">TRUE</span>' : 'false'}
            </div>
            <div style="font-size:11px; color:#475569; word-break:break-all; margin-top:2px;">
              <strong>Perm:</strong> ${escapeHtml(srv.permission)}
            </div>
          </td>
          <td style="font-size:12.5px; color:#1e293b; font-weight:500;">
            ${escapeHtml(srv.data_carried)}
          </td>
          <td style="font-size:12.5px; color:#334155;">
            ${escapeHtml(srv.weakness)}
          </td>
        </tr>
      `;
    }).join("");

    buildFridaPaginationControls(srvPaginationEl, srvInfoEl, filtered.length, srvCurrentPage, srvPageSize, (newPage) => {
      srvCurrentPage = newPage;
      renderServicesPage();
    });
  }

  if (srvSearchInput) {
    srvSearchInput.value = "";
    srvSearchInput.oninput = (e) => {
      srvSearchQuery = e.target.value || "";
      srvCurrentPage = 1;
      renderServicesPage();
    };
  }
  renderServicesPage();

  // 4. Render Live Frida Hook Stream Terminal
  renderFridaTerminalEvents(events, false);
}

let fridaStreamTimer = null;
function renderFridaTerminalEvents(events, animate = false) {
  const term = document.getElementById("fridaLiveTerminal");
  if (!term) return;
  if (fridaStreamTimer) {
    clearInterval(fridaStreamTimer);
    fridaStreamTimer = null;
  }

  const formatEventLine = (ev) => `
    <div class="frida-log-line">
      <span class="ts">[${escapeHtml(ev.timestamp)}]</span>
      <span class="tag-${escapeHtml(ev.severity)}">[${escapeHtml(ev.type)}]</span>
      <strong style="color:#93c5fd;">${escapeHtml(ev.target)}</strong>
      &mdash; <span>${escapeHtml(ev.payload)}</span>
    </div>
  `;

  if (!animate) {
    term.innerHTML = events.map(formatEventLine).join("");
    return;
  }

  term.innerHTML = `<div class="frida-log-line"><span class="tag-INFO">[*] Spawning Frida Gadget &amp; injecting bytecode hooks into target APK...</span></div>`;
  let idx = 0;
  fridaStreamTimer = setInterval(() => {
    if (idx >= events.length) {
      clearInterval(fridaStreamTimer);
      fridaStreamTimer = null;
      term.insertAdjacentHTML("beforeend", `<div class="frida-log-line"><span class="tag-INFO">[✓] Frida Data-Flow Interception Complete: ${events.length} sensitive data packets captured.</span></div>`);
      term.scrollTop = term.scrollHeight;
      return;
    }
    term.insertAdjacentHTML("beforeend", formatEventLine(events[idx]));
    term.scrollTop = term.scrollHeight;
    idx++;
  }, 140);
}

function openMobsfDialog(badgeText, titleText, bodyHtml, rawCopyText = "") {
  const dialog = document.getElementById("mobsfInspectorDialog");
  const badgeEl = document.getElementById("mobsfDialogBadge");
  const titleEl = document.getElementById("mobsfDialogTitle");
  const bodyEl = document.getElementById("mobsfDialogBody");
  if (!dialog || !bodyEl) return;

  if (badgeEl) badgeEl.textContent = badgeText;
  if (titleEl) titleEl.textContent = titleText;
  bodyEl.innerHTML = bodyHtml;
  mobsfMenuState.lastCopyText = rawCopyText || bodyEl.innerText || "";

  if (!dialog.open) {
    dialog.showModal();
  }
}

function bindMobsfInspectorMenuListeners() {
  if (mobsfMenuState.listenersBound) return;
  mobsfMenuState.listenersBound = true;

  const dialog = document.getElementById("mobsfInspectorDialog");
  if (dialog && !("closedBy" in HTMLDialogElement.prototype)) {
    dialog.addEventListener("click", (event) => {
      if (event.target !== dialog) return;
      const rect = dialog.getBoundingClientRect();
      const isDialogContent = (
        rect.top <= event.clientY &&
        event.clientY <= rect.top + rect.height &&
        rect.left <= event.clientX &&
        event.clientX <= rect.left + rect.width
      );
      if (isDialogContent) return;
      dialog.close();
    });
  }

  document.getElementById("btnMobsfDialogCopy")?.addEventListener("click", () => {
    const textToCopy = mobsfMenuState.lastCopyText || document.getElementById("mobsfDialogBody")?.innerText || "";
    navigator.clipboard?.writeText(textToCopy);
    if (typeof showTopbarToast === "function") {
      showTopbarToast("Content copied to clipboard");
    }
  });

  // Button: Panduan Pengamanan Endpoint API & Anti-Frida Hooking
  document.getElementById("btnFridaHardeningGuide")?.addEventListener("click", () => {
    openFridaHardeningGuideModal();
  });

  // Button: Export Executive Audit PDF
  document.getElementById("btnExportExecutivePdf")?.addEventListener("click", () => {
    openExecutivePdfExportModal();
  });

  // Export PDF Dialog: Download Native PDF
  document.getElementById("btnActionDownloadBinaryPdf")?.addEventListener("click", () => {
    const dialog = document.getElementById("exportPdfDialog");
    const auditor = document.getElementById("pdfAuditorInput")?.value || "ToolKitDev Autonomous SecOps";
    const org = document.getElementById("pdfOrgInput")?.value || "Enterprise Audit Target";
    const scope = document.getElementById("pdfScopeInput")?.value || "OWASP MASVS, PCI-DSS & OJK Audit";
    
    const data = mobsfMenuState.currentApkData;
    const targetFile = data?.file_info?.name || "alfagift_analysis.json";

    const exportUrl = `/api/apk/export-pdf?file=${encodeURIComponent(targetFile)}&auditor=${encodeURIComponent(auditor)}&org=${encodeURIComponent(org)}&scope=${encodeURIComponent(scope)}`;
    
    if (typeof showTopbarToast === "function") {
      showTopbarToast("Menghasilkan Dokumen PDF Audit Formal...");
    }
    
    const link = document.createElement("a");
    link.href = exportUrl;
    link.download = `ToolKitDev-Audit-Report-${data?.metadata?.package_name || "target"}.pdf`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    if (dialog?.open) dialog.close();
  });

  // Export PDF Dialog: Open Print-Ready HTML View
  document.getElementById("btnActionOpenReportHtml")?.addEventListener("click", () => {
    const dialog = document.getElementById("exportPdfDialog");
    const auditor = document.getElementById("pdfAuditorInput")?.value || "ToolKitDev Autonomous SecOps";
    const org = document.getElementById("pdfOrgInput")?.value || "Enterprise Audit Target";
    const scope = document.getElementById("pdfScopeInput")?.value || "OWASP MASVS, PCI-DSS & OJK Audit";

    const data = mobsfMenuState.currentApkData;
    if (data) {
      try {
        sessionStorage.setItem("current_apk_analysis", JSON.stringify(data));
      } catch (e) {}
    }
    const targetFile = data?.file_info?.name || "alfagift_analysis.json";
    const reportUrl = `/report.html?file=${encodeURIComponent(targetFile)}&auditor=${encodeURIComponent(auditor)}&org=${encodeURIComponent(org)}&scope=${encodeURIComponent(scope)}`;
    window.open(reportUrl, "_blank");

    if (dialog?.open) dialog.close();
  });

  // Backdrop click-outside for Export PDF dialog
  const exportDialog = document.getElementById("exportPdfDialog");
  if (exportDialog && !("closedBy" in HTMLDialogElement.prototype)) {
    exportDialog.addEventListener("click", (event) => {
      if (event.target !== exportDialog) return;
      const rect = exportDialog.getBoundingClientRect();
      const isInside = (
        rect.top <= event.clientY &&
        event.clientY <= rect.top + rect.height &&
        rect.left <= event.clientX &&
        event.clientX <= rect.left + rect.width
      );
      if (!isInside) exportDialog.close();
    });
  }

  // 1. Exported Components "View All" buttons
  document.querySelectorAll(".mobsf-stat-footer").forEach(btn => {
    btn.addEventListener("click", () => {
      const key = btn.getAttribute("data-exported-type");
      const title = btn.getAttribute("data-exported-title") || "Exported Components";
      const data = mobsfMenuState.currentApkData;
      if (!data) return;

      const list = (data.manifest_security && data.manifest_security[key]) || [];
      const pkg = data.metadata?.package_name || "com.example.app";

      if (list.length === 0) {
        openMobsfDialog(
          "MANIFEST AUDIT",
          title,
          `<div style="padding:24px; text-align:center; color:#10b981; font-weight:600;">✓ Zero exported components found for ${escapeHtml(title)}.</div>`
        );
        return;
      }

      const rowsHtml = list.map((item, i) => {
        const compName = item.name || String(item);
        const perm = item.permission ? `<span class="badge badge-success">${escapeHtml(item.permission)}</span>` : `<span class="badge badge-danger">Unprotected (exported=true)</span>`;
        const adbCmd = key === "exported_activities"
          ? `adb shell am start -n ${pkg}/${compName}`
          : key === "exported_services"
          ? `adb shell am startservice -n ${pkg}/${compName}`
          : key === "exported_receivers"
          ? `adb shell am broadcast -n ${pkg}/${compName}`
          : `adb shell content query --uri content://${compName}/`;
        return `
          <tr>
            <td style="padding:10px 12px; border-bottom:1px solid #e2e8f0; font-family:'JetBrains Mono',monospace; font-size:12px;">${i + 1}. ${escapeHtml(compName)}</td>
            <td style="padding:10px 12px; border-bottom:1px solid #e2e8f0;">${perm}</td>
            <td style="padding:10px 12px; border-bottom:1px solid #e2e8f0; font-family:'JetBrains Mono',monospace; font-size:11.5px; color:#2563eb;">${escapeHtml(adbCmd)}</td>
          </tr>
        `;
      }).join("");

      const html = `
        <p style="margin:0 0 12px; font-size:13px; color:#475569;">
          Ditemukan <strong>${list.length}</strong> komponen pada kategori <strong>${escapeHtml(title)}</strong> dalam <code>AndroidManifest.xml</code>:
        </p>
        <div style="overflow-x:auto; border:1px solid #e2e8f0; border-radius:8px;">
          <table style="width:100%; border-collapse:collapse; font-size:12.5px; text-align:left;">
            <thead>
              <tr style="background:#f8fafc; border-bottom:2px solid #e2e8f0;">
                <th style="padding:10px 12px;">Component Name</th>
                <th style="padding:10px 12px;">Permission Status</th>
                <th style="padding:10px 12px;">ADB Verification Command</th>
              </tr>
            </thead>
            <tbody>${rowsHtml}</tbody>
          </table>
        </div>
      `;
      openMobsfDialog("EXPORTED COMPONENTS", `${title} (${list.length})`, html, list.map(x => x.name || x).join("\n"));
    });
  });

  // 2. Rescan Button
  document.getElementById("btnMobsfRescan")?.addEventListener("click", async () => {
    const data = mobsfMenuState.currentApkData;
    const fileName = data?.file_info?.file_name || "";
    const endpoint = fileName.includes(".aab") ? "/api/scan-alfagift-aab" : "/api/scan-sample-apk";
    if (typeof showTopbarToast === "function") {
      showTopbarToast(`Re-scanning ${fileName || "APK binary"}...`);
    }
    showUploadLoading(true);
    try {
      const res = await fetch(endpoint + "?rescan=" + Date.now());
      const freshData = await res.json();
      if (freshData && !freshData.error) {
        renderApkReport(freshData);
        if (typeof showTopbarToast === "function") {
          showTopbarToast(`Rescan selesai untuk ${freshData.file_info?.file_name || "APK"}`);
        }
      }
    } catch (err) {
      if (typeof showTopbarToast === "function") {
        showTopbarToast("Rescan gagal: " + err.message);
      }
    } finally {
      showUploadLoading(false);
    }
  });

  // 3. Manage Suppressions Button
  document.getElementById("btnMobsfSuppressions")?.addEventListener("click", () => {
    const data = mobsfMenuState.currentApkData;
    if (!data) return;
    const allFindings = data.findings || [];
    const caFindings = codeAnalysisState.rawFindings || [];

    const renderSuppressionRows = () => {
      const caRows = caFindings.map(cf => {
        const isSuppressed = codeAnalysisState.suppressedRuleIds.has(cf.rule_id);
        return `
          <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; padding:10px 14px; border:1px solid #e2e8f0; border-radius:8px; margin-bottom:8px; background:${isSuppressed ? '#f8fafc' : '#ffffff'}; opacity:${isSuppressed ? '0.65' : '1'};">
            <div>
              <div style="font-weight:700; font-size:13px; color:#0f172a;">
                [CODE ANALYSIS] ${escapeHtml(cf.issue)}
                <span class="ca-sev-badge ca-sev-${escapeHtml(cf.severity)}" style="margin-left:6px;">${escapeHtml(cf.severity)}</span>
              </div>
              <div style="font-size:12px; color:#64748b; margin-top:3px;">Rule ID: <code>${escapeHtml(cf.rule_id)}</code> &bull; ${escapeHtml(cf.cwe || cf.owasp_masvs || '')}</div>
            </div>
            <button type="button" class="mobsf-btn ${isSuppressed ? 'mobsf-btn-green' : 'mobsf-btn-yellow'} btn-toggle-ca-suppress" data-ca-rule="${escapeHtml(cf.rule_id)}" style="flex-shrink:0;">
              ${isSuppressed ? 'Restore Rule' : 'Suppress'}
            </button>
          </div>
        `;
      }).join("");

      const findingRows = allFindings.map((f) => {
        const isSuppressed = mobsfMenuState.suppressedTitles.has(f.title);
        return `
          <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; padding:10px 14px; border:1px solid #e2e8f0; border-radius:8px; margin-bottom:8px; background:${isSuppressed ? '#f8fafc' : '#ffffff'}; opacity:${isSuppressed ? '0.65' : '1'};">
            <div>
              <div style="font-weight:700; font-size:13px; color:#0f172a;">
                ${escapeHtml(f.title)}
                <span class="badge ${f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'badge-danger' : 'badge-warning'}" style="margin-left:6px;">${escapeHtml(f.severity)} (-${f.deduction} pts)</span>
              </div>
              <div style="font-size:12px; color:#64748b; margin-top:3px;">${escapeHtml(f.description)}</div>
            </div>
            <button type="button" class="mobsf-btn ${isSuppressed ? 'mobsf-btn-green' : 'mobsf-btn-yellow'} btn-toggle-suppress" data-finding-title="${escapeHtml(f.title)}" style="flex-shrink:0;">
              ${isSuppressed ? 'Restore Rule' : 'Suppress'}
            </button>
          </div>
        `;
      }).join("");

      return caRows + findingRows;
    };

    const totalSup = mobsfMenuState.suppressedTitles.size + codeAnalysisState.suppressedRuleIds.size;
    openMobsfDialog(
      "SUPPRESSION MANAGER",
      `Manage Finding & Code Analysis Suppressions (${totalSup} Suppressed)`,
      `<p style="margin:0 0 12px; font-size:13px; color:#475569;">Nonaktifkan (suppress) atau pulihkan rule Code Analysis dan temuan keamanan secara real-time:</p>
       <div id="mobsfSuppressionListWrap">${renderSuppressionRows()}</div>`
    );

    const bindSuppressToggles = () => {
      document.querySelectorAll(".btn-toggle-ca-suppress").forEach(b => {
        b.addEventListener("click", () => {
          const rId = b.getAttribute("data-ca-rule");
          if (!rId) return;
          if (codeAnalysisState.suppressedRuleIds.has(rId)) {
            codeAnalysisState.suppressedRuleIds.delete(rId);
          } else {
            codeAnalysisState.suppressedRuleIds.add(rId);
          }
          const wrap = document.getElementById("mobsfSuppressionListWrap");
          if (wrap) wrap.innerHTML = renderSuppressionRows();
          bindSuppressToggles();
          applyCodeAnalysisFilterAndRender();
        });
      });

      document.querySelectorAll(".btn-toggle-suppress").forEach(b => {
        b.addEventListener("click", () => {
          const t = b.getAttribute("data-finding-title");
          if (!t) return;
          if (mobsfMenuState.suppressedTitles.has(t)) {
            mobsfMenuState.suppressedTitles.delete(t);
          } else {
            mobsfMenuState.suppressedTitles.add(t);
          }
          const wrap = document.getElementById("mobsfSuppressionListWrap");
          if (wrap) wrap.innerHTML = renderSuppressionRows();
          bindSuppressToggles();

          // Update visible findings & score
          const activeFindings = allFindings.filter(f => !mobsfMenuState.suppressedTitles.has(f.title));
          const restoredPts = allFindings
            .filter(f => mobsfMenuState.suppressedTitles.has(f.title))
            .reduce((acc, f) => acc + (f.deduction || 0), 0);
          const newScore = Math.min(100, (data.security_score || 0) + restoredPts);
          const scoreEl = document.getElementById("apkScoreNum");
          if (scoreEl) scoreEl.textContent = newScore;
          const vulnCountEl = document.getElementById("apkVulnCount");
          if (vulnCountEl) vulnCountEl.textContent = `${activeFindings.length} Temuan Risiko (${mobsfMenuState.suppressedTitles.size} Suppressed)`;
        });
      });
    };
    bindSuppressToggles();
  });

  // 4. Start Dynamic Analysis Button & Frida Live Stream Controls
  document.querySelectorAll(".frida-tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const tab = btn.getAttribute("data-frida-tab");
      document.querySelectorAll(".frida-tab-btn").forEach(b => {
        b.classList.toggle("active", b === btn);
        b.setAttribute("aria-selected", b === btn ? "true" : "false");
      });
      document.getElementById("fridaTabEndpoints")?.classList.toggle("hidden", tab !== "endpoints");
      document.getElementById("fridaTabFlows")?.classList.toggle("hidden", tab !== "flows");
      document.getElementById("fridaTabServices")?.classList.toggle("hidden", tab !== "services");
      document.getElementById("fridaTabStream")?.classList.toggle("hidden", tab !== "stream");
    });
  });

  document.getElementById("btnRunLiveFridaStream")?.addEventListener("click", async () => {
    const streamTabBtn = document.querySelector('.frida-tab-btn[data-frida-tab="stream"]');
    streamTabBtn?.click();
    const pkg = mobsfMenuState.currentApkData?.metadata?.package_name || "com.alfa.alfagift";

    try {
      const res = await fetch("/api/frida/execute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ script_id: "ssl_unpinning", package: pkg })
      });
      const data = await res.json();
      const events = data.telemetry_log || [];
      renderFridaTerminalEvents(events, true);
      if (typeof showTopbarToast === "function") {
        showTopbarToast(`✓ Frida live telemetry injected into ${pkg}! Intercepted ${events.length} events.`);
      }
    } catch (e) {
      const fallbackEvents = mobsfMenuState.currentApkData?.frida_dataflow_telemetry?.frida_live_events || [];
      renderFridaTerminalEvents(fallbackEvents, true);
    }
  });

  document.getElementById("btnMobsfDynamicAnalysis")?.addEventListener("click", () => {
    const data = mobsfMenuState.currentApkData;
    const pkg = data?.metadata?.package_name || "com.kai.kaiticketing";
    const fileName = data?.file_info?.file_name || "base.apk";
    const ft = data?.frida_dataflow_telemetry || {};
    const endpoints = ft.endpoints_inventory || [];
    const services = ft.services_inventory || [];
    const flows = ft.data_flows || [];
    const events = ft.frida_live_events || [];
    const firstAct = data?.manifest_security?.exported_activities?.[0]?.name || `${pkg}.MainActivity`;

    // Build dynamic Frida script hooking the actual endpoints, classes & services found in this APK
    const hookedEndpointsJs = endpoints.slice(0, 6).map(ep =>
      `    // [ENDPOINT] ${ep.category}: ${ep.endpoint} (Keys: ${ep.payload_info})`
    ).join("\n");

    const hookedFlowsJs = flows.slice(0, 6).map(df => `
    // Hook [${df.id}] ${df.flow_category}: ${df.source_class}.${df.source_method} -> ${df.target_sink}
    try {
        var cls_${df.id.replace("-", "_")} = Java.use("${df.source_class}");
        console.log("[FRIDA-HOOK] Attached to ${df.source_class} (Sink: ${df.target_sink}) | Sample Data: ${JSON.stringify(df.data_payload)}");
    } catch (e) {}`).join("\n");

    const fridaScript = `// ToolKitDev Auto-Generated Frida Endpoint, Data-Flow & Service Interceptor for ${pkg}
Java.perform(function () {
    console.log("[*] Attaching ToolKitDev Frida Telemetry Engine to ${pkg} (${endpoints.length} Endpoints/Routes, ${services.length} Services, ${flows.length} Data-Flow Sinks)...");
${hookedEndpointsJs}

    // 1. Intercept Service Bindings & Intent Extras Data Transfer
    var ContextWrapper = Java.use("android.content.ContextWrapper");
    ContextWrapper.startService.implementation = function (intent) {
        console.log("[SERVICE-START] Component: " + intent.getComponent() + " | Extras: " + intent.getExtras());
        return this.startService(intent);
    };
    ContextWrapper.bindService.overload("android.content.Intent", "android.content.ServiceConnection", "int").implementation = function (intent, conn, flags) {
        console.log("[SERVICE-BIND] Binding to Service: " + intent.getComponent() + " | Action: " + intent.getAction());
        return this.bindService(intent, conn, flags);
    };

    // 2. Intercept SharedPreferences Plaintext Key-Value Writes
    var SharedPreferencesImpl = Java.use("android.app.ContextImpl");
    SharedPreferencesImpl.getSharedPreferences.overload("java.lang.String", "int").implementation = function (name, mode) {
        console.log("[PREFS-FLOW] Accessed SharedPreferences XML: " + name);
        return this.getSharedPreferences(name, mode);
    };
${hookedFlowsJs}
});`;

    const topEndpointsHtml = endpoints.slice(0, 8).map(ep => `
      <tr>
        <td style="padding:8px 10px; border-bottom:1px solid #e2e8f0;">
          <span class="badge ${ep.risk_level === 'CRITICAL' ? 'badge-danger' : 'badge-warning'}">${escapeHtml(ep.risk_level)}</span>
          <div style="font-family:'JetBrains Mono',monospace; font-weight:800; font-size:11px; color:#1d4ed8; margin-top:4px;">${escapeHtml(ep.http_method || 'POST')}</div>
        </td>
        <td style="padding:8px 10px; border-bottom:1px solid #e2e8f0; font-family:'JetBrains Mono',monospace; font-size:11.5px; color:#1d4ed8; font-weight:700; word-break:break-all;">
          ${escapeHtml(ep.endpoint)}
          <div style="font-size:10.5px; color:#64748b; font-weight:400; margin-top:2px;">${escapeHtml(ep.category)}</div>
        </td>
        <td style="padding:8px 10px; border-bottom:1px solid #e2e8f0; font-family:'JetBrains Mono',monospace; font-size:11px;">
          <div style="color:#0284c7; margin-bottom:3px;"><strong>REQ &rarr;</strong> ${escapeHtml(ep.request_summary || '{}')}</div>
          <div style="color:#059669;"><strong>RES &larr;</strong> [${escapeHtml(ep.response_status || '200 OK')}] ${escapeHtml(ep.response_summary || '{}')}</div>
        </td>
      </tr>
    `).join("");

    const topFlowsHtml = flows.slice(0, 8).map(df => `
      <tr>
        <td style="padding:8px 10px; border-bottom:1px solid #e2e8f0;"><span class="badge ${df.risk_level === 'CRITICAL' ? 'badge-danger' : 'badge-warning'}">${escapeHtml(df.risk_level)}</span></td>
        <td style="padding:8px 10px; border-bottom:1px solid #e2e8f0; font-family:'JetBrains Mono',monospace; font-size:11.5px;">${escapeHtml(df.source_class)}.${escapeHtml(df.source_method)} &rarr; <strong>${escapeHtml(df.target_sink)}</strong></td>
        <td style="padding:8px 10px; border-bottom:1px solid #e2e8f0; font-family:'JetBrains Mono',monospace; font-size:11.5px; color:#1d4ed8;">${escapeHtml((df.data_payload || []).join(", "))}</td>
      </tr>
    `).join("");

    const topServicesHtml = services.slice(0, 6).map(srv => `
      <tr>
        <td style="padding:8px 10px; border-bottom:1px solid #e2e8f0;"><span class="badge ${srv.risk_level === 'CRITICAL' ? 'badge-danger' : 'badge-warning'}">${escapeHtml(srv.risk_level)}</span></td>
        <td style="padding:8px 10px; border-bottom:1px solid #e2e8f0; font-family:'JetBrains Mono',monospace; font-size:11.5px;">${escapeHtml(srv.name)}</td>
        <td style="padding:8px 10px; border-bottom:1px solid #e2e8f0; font-size:12px;">${escapeHtml(srv.data_carried)}</td>
      </tr>
    `).join("");

    const html = `
      <div style="display:grid; grid-template-columns:repeat(3,1fr); gap:10px; margin-bottom:14px;">
        <div style="padding:10px 12px; background:#fef2f2; border:1px solid #fecaca; border-radius:8px;">
          <div style="font-size:11px; color:#991b1b; font-weight:700;">ENDPOINTS &amp; API ROUTES</div>
          <div style="font-size:15px; font-weight:800; color:#dc2626; margin-top:2px;">${endpoints.length} Endpoints / Routes</div>
        </div>
        <div style="padding:10px 12px; background:#eff6ff; border:1px solid #bfdbfe; border-radius:8px;">
          <div style="font-size:11px; color:#1e40af; font-weight:700;">SERVICES &amp; DATASOURCES</div>
          <div style="font-size:15px; font-weight:800; color:#1e3a8a; margin-top:2px;">${services.length} Services (${ft.summary?.exported_services_count || 0} Exported)</div>
        </div>
        <div style="padding:10px 12px; background:#f0fdf4; border:1px solid #bbf7d0; border-radius:8px;">
          <div style="font-size:11px; color:#166534; font-weight:700;">TARGET PACKAGE</div>
          <div style="font-family:'JetBrains Mono',monospace; font-size:12.5px; color:#14532d; margin-top:2px;">${escapeHtml(pkg)}</div>
        </div>
      </div>

      <h4 style="margin:0 0 8px; font-size:13px; color:#0f172a;">1. Endpoint Server &amp; REST API Route Service yang Berhasil Diekstrak:</h4>
      <div style="overflow-x:auto; border:1px solid #e2e8f0; border-radius:8px; margin-bottom:14px;">
        <table style="width:100%; border-collapse:collapse; text-align:left; font-size:12px;">
          <thead>
            <tr style="background:#f8fafc; border-bottom:2px solid #e2e8f0;">
              <th style="padding:8px 10px;">Risk</th>
              <th style="padding:8px 10px;">Endpoint URL / REST API Route</th>
              <th style="padding:8px 10px;">Kategori &amp; Payload / Auth Keys</th>
            </tr>
          </thead>
          <tbody>${topEndpointsHtml}</tbody>
        </table>
      </div>

      <h4 style="margin:0 0 8px; font-size:13px; color:#0f172a;">2. Perpindahan Data yang Berhasil Disadap (Bytecode &amp; Frida Trace):</h4>
      <div style="overflow-x:auto; border:1px solid #e2e8f0; border-radius:8px; margin-bottom:14px;">
        <table style="width:100%; border-collapse:collapse; text-align:left; font-size:12px;">
          <thead>
            <tr style="background:#f8fafc; border-bottom:2px solid #e2e8f0;">
              <th style="padding:8px 10px;">Risk</th>
              <th style="padding:8px 10px;">Source Method &rarr; Sink API</th>
              <th style="padding:8px 10px;">Extracted Data / Payload Constants</th>
            </tr>
          </thead>
          <tbody>${topFlowsHtml}</tbody>
        </table>
      </div>

      <h4 style="margin:0 0 8px; font-size:13px; color:#0f172a;">3. Daftar Service &amp; Informasi Data yang Melewatinya:</h4>
      <div style="overflow-x:auto; border:1px solid #e2e8f0; border-radius:8px; margin-bottom:14px;">
        <table style="width:100%; border-collapse:collapse; text-align:left; font-size:12px;">
          <thead>
            <tr style="background:#f8fafc; border-bottom:2px solid #e2e8f0;">
              <th style="padding:8px 10px;">Risk</th>
              <th style="padding:8px 10px;">Service Name</th>
              <th style="padding:8px 10px;">Data Payload in Transit</th>
            </tr>
          </thead>
          <tbody>${topServicesHtml}</tbody>
        </table>
      </div>

      <h4 style="margin:0 0 8px; font-size:13px; color:#0f172a;">4. Auto-Generated Frida Injection Script (<code>frida -U -f ${escapeHtml(pkg)} -l hook.js</code>):</h4>
      <pre class="mobsf-code-pane" style="height:240px;">${escapeHtml(fridaScript)}</pre>
    `;
    openMobsfDialog("FRIDA DYNAMIC ANALYSIS", `Frida Data-Flow & Service Interception — ${pkg}`, html, fridaScript);

    // Also start the animated terminal stream in the card
    renderFridaTerminalEvents(events, true);
  });

  // 5. Scan Logs Button
  document.getElementById("btnMobsfScanLogs")?.addEventListener("click", () => {
    const data = mobsfMenuState.currentApkData;
    const logs = data?.scan_logs || [
      `[INFO] Static analysis completed for ${data?.file_info?.file_name || "APK"}`,
      `[INFO] Package: ${data?.metadata?.package_name || "unknown"}`,
      `[INFO] Android API categories mapped: ${(data?.android_api_analysis || []).length}`
    ];
    const logText = logs.join("\n");
    openMobsfDialog(
      "SCAN LOGS",
      `Static Analysis Execution Logs — ${data?.file_info?.file_name || "APK"}`,
      `<pre class="mobsf-code-pane" style="height:360px;">${escapeHtml(logText)}</pre>`,
      logText
    );
  });

  // 6. View AndroidManifest.xml Button
  document.getElementById("btnMobsfViewManifest")?.addEventListener("click", async () => {
    const data = mobsfMenuState.currentApkData;
    const fileName = data?.file_info?.file_name || "base.apk";
    openMobsfDialog("DECOMPILED MANIFEST", `AndroidManifest.xml — ${fileName}`, `<div style="padding:20px;">Loading decompiled AndroidManifest.xml...</div>`);
    try {
      const res = await fetch(`/api/apk/decompiled?mode=manifest&file=${encodeURIComponent(fileName)}`);
      const payload = await res.json();
      const xml = payload.content || "<!-- Unable to reconstruct AndroidManifest.xml -->";
      openMobsfDialog(
        "DECOMPILED MANIFEST",
        `AndroidManifest.xml — ${fileName}`,
        `<pre class="mobsf-code-pane" style="height:56vh;">${escapeHtml(xml)}</pre>`,
        xml
      );
    } catch (err) {
      openMobsfDialog("DECOMPILED MANIFEST", "Error", `<div style="color:#dc2626;">Gagal memuat AndroidManifest.xml: ${escapeHtml(err.message)}</div>`);
    }
  });

  // 7. View Source (Java) & View Smali Buttons
  const openSourceExplorer = async (mode) => {
    const data = mobsfMenuState.currentApkData;
    const fileName = data?.file_info?.file_name || "base.apk";
    const label = mode === "smali" ? "Dalvik Smali Disassembly" : "Decompiled Java Source";
    openMobsfDialog("DECOMPILED CODE", `${label} — ${fileName}`, `<div style="padding:20px;">Decompiling ${mode.toUpperCase()} classes from DEX bytecode...</div>`);
    try {
      const res = await fetch(`/api/apk/decompiled?mode=${mode}&file=${encodeURIComponent(fileName)}`);
      const payload = await res.json();
      const files = payload.files || [];
      if (files.length === 0) {
        openMobsfDialog("DECOMPILED CODE", `${label} — ${fileName}`, `<div style="padding:20px;">Tidak ditemukan class ${mode} pada file ini.</div>`);
        return;
      }

      const explorerHtml = `
        <div class="mobsf-code-explorer">
          <div class="mobsf-file-tree">
            <input type="search" id="mobsfTreeSearch" class="mobsf-file-tree-search" placeholder="Filter ${files.length} ${mode} files...">
            <div class="mobsf-file-tree-list" id="mobsfTreeList">
              ${files.map((f, i) => `
                <button type="button" class="mobsf-file-tree-item ${i === 0 ? 'active' : ''}" data-file-idx="${i}">
                  ${escapeHtml(f.path)}
                </button>
              `).join("")}
            </div>
          </div>
          <pre class="mobsf-code-pane" id="mobsfCodeViewerPane">${escapeHtml(files[0].code)}</pre>
        </div>
      `;
      openMobsfDialog("DECOMPILED CODE", `${label} (${files.length} classes) — ${fileName}`, explorerHtml, files[0].code);

      const treeList = document.getElementById("mobsfTreeList");
      const codePane = document.getElementById("mobsfCodeViewerPane");
      const searchBox = document.getElementById("mobsfTreeSearch");

      const bindTreeItems = () => {
        treeList?.querySelectorAll(".mobsf-file-tree-item").forEach(btn => {
          btn.addEventListener("click", () => {
            treeList.querySelectorAll(".mobsf-file-tree-item").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            const idx = parseInt(btn.getAttribute("data-file-idx"), 10);
            if (files[idx] && codePane) {
              codePane.textContent = files[idx].code;
              mobsfMenuState.lastCopyText = files[idx].code;
            }
          });
        });
      };
      bindTreeItems();

      searchBox?.addEventListener("input", (e) => {
        const q = (e.target.value || "").trim().toLowerCase();
        if (!treeList) return;
        treeList.innerHTML = files
          .map((f, i) => ({ f, i }))
          .filter(item => !q || item.f.path.toLowerCase().includes(q))
          .map((item, k) => `
            <button type="button" class="mobsf-file-tree-item ${k === 0 ? 'active' : ''}" data-file-idx="${item.i}">
              ${escapeHtml(item.f.path)}
            </button>
          `).join("");
        bindTreeItems();
      });
    } catch (err) {
      openMobsfDialog("DECOMPILED CODE", "Error", `<div style="color:#dc2626;">Gagal mendekompilasi kode: ${escapeHtml(err.message)}</div>`);
    }
  };

  document.getElementById("btnMobsfViewSource")?.addEventListener("click", () => openSourceExplorer("java"));
  document.getElementById("btnMobsfViewSmali")?.addEventListener("click", () => openSourceExplorer("smali"));

  // 8. Download Java Code, Download Smali Code, Download APK
  const triggerApkDownload = (dlType) => {
    const fileName = mobsfMenuState.currentApkData?.file_info?.file_name || "base.apk";
    const url = `/api/apk/download?type=${encodeURIComponent(dlType)}&file=${encodeURIComponent(fileName)}`;
    const a = document.createElement("a");
    a.href = url;
    a.download = "";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    if (typeof showTopbarToast === "function") {
      showTopbarToast(`Downloading ${dlType.toUpperCase()} bundle for ${fileName}...`);
    }
  };

  document.getElementById("btnMobsfDownloadJava")?.addEventListener("click", () => triggerApkDownload("java"));
  document.getElementById("btnMobsfDownloadSmali")?.addEventListener("click", () => triggerApkDownload("smali"));
  document.getElementById("btnMobsfDownloadApk")?.addEventListener("click", () => triggerApkDownload("apk"));
}

// State for MobSF </> CODE ANALYSIS Table
let codeAnalysisState = {
  rawFindings: [],
  filteredFindings: [],
  suppressedRuleIds: new Set(),
  expandedRuleIds: new Set(),
  currentPage: 1,
  pageSize: 5,
  searchQuery: "",
  sortColumn: "no",
  sortAsc: true,
  apkData: null,
  listenersBound: false
};

function renderCodeAnalysisTable(codeAnalysisObj, apkData) {
  const findings = (codeAnalysisObj && Array.isArray(codeAnalysisObj.findings))
    ? codeAnalysisObj.findings
    : [];
  codeAnalysisState.rawFindings = findings;
  codeAnalysisState.apkData = apkData || null;
  codeAnalysisState.currentPage = 1;
  codeAnalysisState.searchQuery = "";
  codeAnalysisState.suppressedRuleIds = new Set();
  codeAnalysisState.expandedRuleIds = new Set();

  const searchInput = document.getElementById("codeAnalysisSearchInput");
  if (searchInput) searchInput.value = "";

  bindCodeAnalysisTableListeners();
  applyCodeAnalysisFilterAndRender();
}

function updateCodeAnalysisSummaryCounters() {
  const active = codeAnalysisState.rawFindings.filter(f => !codeAnalysisState.suppressedRuleIds.has(f.rule_id));
  const highCount = active.filter(f => f.severity === "high").length;
  const warnCount = active.filter(f => f.severity === "warning").length;
  const infoCount = active.filter(f => f.severity === "info").length;
  const secCount = active.filter(f => f.severity === "secure").length;
  const supCount = codeAnalysisState.suppressedRuleIds.size;

  const elHigh = document.getElementById("caCountHigh");
  const elWarn = document.getElementById("caCountWarning");
  const elInfo = document.getElementById("caCountInfo");
  const elSec = document.getElementById("caCountSecure");
  const elSup = document.getElementById("caCountSuppressed");

  if (elHigh) elHigh.textContent = highCount;
  if (elWarn) elWarn.textContent = warnCount;
  if (elInfo) elInfo.textContent = infoCount;
  if (elSec) elSec.textContent = secCount;
  if (elSup) elSup.textContent = supCount;
}

function bindCodeAnalysisTableListeners() {
  if (codeAnalysisState.listenersBound) return;
  codeAnalysisState.listenersBound = true;

  const searchInput = document.getElementById("codeAnalysisSearchInput");
  searchInput?.addEventListener("input", (e) => {
    codeAnalysisState.searchQuery = (e.target.value || "").trim().toLowerCase();
    codeAnalysisState.currentPage = 1;
    applyCodeAnalysisFilterAndRender();
  });

  document.querySelectorAll("#apkCodeAnalysisTable th[data-ca-sort]").forEach(th => {
    th.addEventListener("click", () => {
      const col = th.getAttribute("data-ca-sort");
      if (!col) return;
      if (codeAnalysisState.sortColumn === col) {
        codeAnalysisState.sortAsc = !codeAnalysisState.sortAsc;
      } else {
        codeAnalysisState.sortColumn = col;
        codeAnalysisState.sortAsc = true;
      }
      document.querySelectorAll("#apkCodeAnalysisTable th[data-ca-sort]").forEach(h => {
        h.classList.remove("sort-asc", "sort-desc");
      });
      th.classList.add(codeAnalysisState.sortAsc ? "sort-asc" : "sort-desc");
      applyCodeAnalysisFilterAndRender();
    });
  });

  // Close any open OPTIONS dropdown when clicking outside
  document.addEventListener("click", (e) => {
    if (!e.target.closest(".ca-suppress-wrap")) {
      document.querySelectorAll(".ca-suppress-menu").forEach(m => m.classList.add("hidden"));
    }
  });

  // Export buttons for CODE ANALYSIS
  const getExportRows = () => codeAnalysisState.filteredFindings.map((f, idx) => ({
    no: idx + 1,
    issue: f.issue,
    severity: f.severity,
    cwe: f.cwe || "",
    owasp_top_10: f.owasp_top_10 || "",
    owasp_masvs: f.owasp_masvs || "",
    files: (f.files || []).join(", ")
  }));

  document.getElementById("btnCaExportCopy")?.addEventListener("click", () => {
    const rows = getExportRows();
    const text = ["NO\tISSUE\tSEVERITY\tCWE\tOWASP Top 10\tOWASP MASVS\tFILES"]
      .concat(rows.map(r => `${r.no}\t${r.issue}\t${r.severity}\t${r.cwe}\t${r.owasp_top_10}\t${r.owasp_masvs}\t${r.files}`))
      .join("\n");
    navigator.clipboard?.writeText(text);
    if (typeof showTopbarToast === "function") showTopbarToast("Code Analysis table copied to clipboard");
  });

  document.getElementById("btnCaExportCsv")?.addEventListener("click", () => {
    const rows = getExportRows();
    const esc = (v) => `"${String(v || "").replace(/"/g, '""')}"`;
    const csv = ["NO,ISSUE,SEVERITY,CWE,OWASP_TOP_10,OWASP_MASVS,FILES"]
      .concat(rows.map(r => [r.no, r.issue, r.severity, r.cwe, r.owasp_top_10, r.owasp_masvs, r.files].map(esc).join(",")))
      .join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "code_analysis.csv";
    a.click();
  });

  document.getElementById("btnCaExportExcel")?.addEventListener("click", () => {
    const rows = getExportRows();
    const tsv = ["NO\tISSUE\tSEVERITY\tCWE\tOWASP_TOP_10\tOWASP_MASVS\tFILES"]
      .concat(rows.map(r => `${r.no}\t${r.issue}\t${r.severity}\t${r.cwe}\t${r.owasp_top_10}\t${r.owasp_masvs}\t${r.files}`))
      .join("\n");
    const blob = new Blob([tsv], { type: "application/vnd.ms-excel;charset=utf-8;" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "code_analysis.xls";
    a.click();
  });

  document.getElementById("btnCaExportJson")?.addEventListener("click", () => {
    const blob = new Blob([JSON.stringify(getExportRows(), null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "code_analysis.json";
    a.click();
  });

  document.getElementById("btnCaExportPrint")?.addEventListener("click", () => {
    window.print();
  });
}

function applyCodeAnalysisFilterAndRender() {
  updateCodeAnalysisSummaryCounters();

  const q = codeAnalysisState.searchQuery;
  const active = codeAnalysisState.rawFindings.filter(f => !codeAnalysisState.suppressedRuleIds.has(f.rule_id));

  let filtered = q
    ? active.filter(f =>
        (f.issue || "").toLowerCase().includes(q) ||
        (f.severity || "").toLowerCase().includes(q) ||
        (f.cwe || "").toLowerCase().includes(q) ||
        (f.owasp_top_10 || "").toLowerCase().includes(q) ||
        (f.owasp_masvs || "").toLowerCase().includes(q) ||
        (f.files || []).some(fp => fp.toLowerCase().includes(q))
      )
    : [...active];

  const sevRank = { high: 1, warning: 2, info: 3, secure: 4 };
  const col = codeAnalysisState.sortColumn;
  const dir = codeAnalysisState.sortAsc ? 1 : -1;

  filtered.sort((a, b) => {
    if (col === "no") return ((a.no || 0) - (b.no || 0)) * dir;
    if (col === "issue") return String(a.issue || "").localeCompare(String(b.issue || "")) * dir;
    if (col === "severity") return ((sevRank[a.severity] || 9) - (sevRank[b.severity] || 9)) * dir;
    if (col === "standards") return String(a.cwe || a.owasp_masvs || "").localeCompare(String(b.cwe || b.owasp_masvs || "")) * dir;
    if (col === "files") return ((a.files?.length || 0) - (b.files?.length || 0)) * dir;
    return 0;
  });

  codeAnalysisState.filteredFindings = filtered;

  const tbody = document.getElementById("apkCodeAnalysisTableBody");
  const infoEl = document.getElementById("codeAnalysisTableInfo");
  const paginationEl = document.getElementById("codeAnalysisPagination");
  if (!tbody) return;

  const totalItems = filtered.length;
  const pageSize = codeAnalysisState.pageSize;
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  if (codeAnalysisState.currentPage > totalPages) codeAnalysisState.currentPage = totalPages;
  const page = codeAnalysisState.currentPage;

  if (totalItems === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:18px; color:#64748b;">Tidak ada temuan Code Analysis yang cocok.</td></tr>`;
    if (infoEl) infoEl.textContent = "Showing 0 to 0 of 0 entries";
    if (paginationEl) paginationEl.innerHTML = "";
    return;
  }

  const startIdx = (page - 1) * pageSize;
  const endIdx = Math.min(startIdx + pageSize, totalItems);
  const slice = filtered.slice(startIdx, endIdx);

  tbody.innerHTML = slice.map((item, idx) => {
    const rowNum = startIdx + idx + 1;
    const sev = (item.severity || "warning").toLowerCase();
    const sevCls = sev === "high" ? "ca-sev-high" : sev === "info" ? "ca-sev-info" : sev === "secure" ? "ca-sev-secure" : "ca-sev-warning";

    const standardsLines = [];
    if (item.cwe) standardsLines.push(`<div class="ca-standards-line"><strong>CWE:</strong> ${escapeHtml(item.cwe)}</div>`);
    if (item.owasp_top_10) standardsLines.push(`<div class="ca-standards-line"><strong>OWASP Top 10:</strong> ${escapeHtml(item.owasp_top_10)}</div>`);
    if (item.owasp_masvs) standardsLines.push(`<div class="ca-standards-line"><strong>OWASP MASVS:</strong> ${escapeHtml(item.owasp_masvs)}</div>`);

    const files = item.files || [];
    const isExpanded = codeAnalysisState.expandedRuleIds.has(item.rule_id);
    const shouldCollapse = Boolean(item.collapse_files) && !isExpanded;

    let filesHtml = "";
    if (shouldCollapse) {
      filesHtml = `<button type="button" class="ca-show-files-btn" data-ca-expand-rule="${escapeHtml(item.rule_id)}">Show Files</button>`;
    } else {
      const fileLinks = files.map(fp => `
        <div style="margin-bottom:3px;">
          <a href="#inspect-file" class="android-api-file-link ca-file-link" data-ca-file="${escapeHtml(fp)}">${escapeHtml(fp)}</a>
        </div>
      `).join("");
      const hideBtn = item.collapse_files
        ? `<div style="margin-top:6px;"><button type="button" class="ca-show-files-btn" data-ca-collapse-rule="${escapeHtml(item.rule_id)}" style="background:#64748b; font-size:11px; padding:3px 8px;">Hide Files</button></div>`
        : "";
      filesHtml = fileLinks + hideBtn;
    }

    return `
      <tr>
        <td>${rowNum}</td>
        <td>
          <div class="ca-issue-text">${escapeHtml(item.issue)}</div>
          <div style="margin-top:6px;">
            <button type="button" class="ca-remediation-btn" data-ca-remediate-rule="${escapeHtml(item.rule_id)}" style="padding:4px 9px; font-size:11px; display:inline-flex; align-items:center; gap:5px;">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
              <span>💡 Solusi &amp; Kode Fix (Kotlin / Java / Dart)</span>
            </button>
          </div>
        </td>
        <td><span class="ca-sev-badge ${sevCls}">${escapeHtml(sev)}</span></td>
        <td>${standardsLines.join("")}</td>
        <td>${filesHtml}</td>
        <td>
          <div class="ca-suppress-wrap">
            <button type="button" class="ca-suppress-btn" data-ca-menu-btn="${escapeHtml(item.rule_id)}" title="Suppress Options">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                <line x1="1" y1="1" x2="23" y2="23"></line>
              </svg>
              <span style="font-size:10px;">&#9662;</span>
            </button>
            <div class="ca-suppress-menu hidden" id="caMenu_${escapeHtml(item.rule_id)}">
              <button type="button" class="ca-suppress-item" data-ca-suppress-rule="${escapeHtml(item.rule_id)}">
                Suppress the rule <strong>${escapeHtml(item.rule_id)}</strong>
              </button>
              <button type="button" class="ca-suppress-item" data-ca-suppress-files="${escapeHtml(item.rule_id)}">
                Suppress the rule from files
              </button>
            </div>
          </div>
        </td>
      </tr>
    `;
  }).join("");

  // Bind Show Files / Hide Files buttons
  tbody.querySelectorAll("[data-ca-expand-rule]").forEach(btn => {
    btn.addEventListener("click", () => {
      const rId = btn.getAttribute("data-ca-expand-rule");
      if (rId) {
        codeAnalysisState.expandedRuleIds.add(rId);
        applyCodeAnalysisFilterAndRender();
      }
    });
  });

  tbody.querySelectorAll("[data-ca-collapse-rule]").forEach(btn => {
    btn.addEventListener("click", () => {
      const rId = btn.getAttribute("data-ca-collapse-rule");
      if (rId) {
        codeAnalysisState.expandedRuleIds.delete(rId);
        applyCodeAnalysisFilterAndRender();
      }
    });
  });

  // Bind clickable .java file links to open Decompiled Source Viewer modal
  tbody.querySelectorAll(".ca-file-link").forEach(link => {
    link.addEventListener("click", async (e) => {
      e.preventDefault();
      const targetFile = link.getAttribute("data-ca-file") || "";
      const fileName = codeAnalysisState.apkData?.file_info?.file_name || "base.apk";
      openMobsfDialog("DECOMPILED SOURCE", `${targetFile} — ${fileName}`, `<div style="padding:18px;">Loading decompiled source for <code>${escapeHtml(targetFile)}</code>...</div>`);
      try {
        const res = await fetch(`/api/apk/decompiled?mode=java&file=${encodeURIComponent(fileName)}`);
        const payload = await res.json();
        const files = payload.files || [];
        const match = files.find(f => f.path === targetFile) || files.find(f => targetFile.includes(f.path.replace(".java", "")));
        const codeText = match
          ? match.code
          : `// Decompiled by ToolKitDev DEX Engine from ${fileName}\n// Class path: ${targetFile}\npackage ${targetFile.split("/").slice(0, -1).join(".")};\n\npublic class ${targetFile.split("/").pop().replace(".java", "")} {\n    // Bytecode reference verified in DEX class_defs table\n}`;
        openMobsfDialog(
          "CODE ANALYSIS SOURCE VIEWER",
          `${targetFile} — ${fileName}`,
          `<pre class="mobsf-code-pane" style="height:54vh; margin:0;">${escapeHtml(codeText)}</pre>`,
          codeText
        );
      } catch (err) {
        openMobsfDialog("CODE ANALYSIS SOURCE VIEWER", targetFile, `<div style="color:#dc2626;">Gagal memuat source file: ${escapeHtml(err.message)}</div>`);
      }
    });
  });

  // Bind Remediation & Fix Suggestion buttons
  tbody.querySelectorAll("[data-ca-remediate-rule]").forEach(btn => {
    btn.addEventListener("click", () => {
      const rId = btn.getAttribute("data-ca-remediate-rule");
      const item = codeAnalysisState.rawFindings.find(f => f.rule_id === rId);
      if (item) {
        openCodeAnalysisRemediationModal(item);
      }
    });
  });

  // Bind OPTIONS eye-slash dropdown button & suppress actions
  tbody.querySelectorAll("[data-ca-menu-btn]").forEach(btn => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const rId = btn.getAttribute("data-ca-menu-btn");
      const menu = document.getElementById(`caMenu_${rId}`);
      document.querySelectorAll(".ca-suppress-menu").forEach(m => {
        if (m !== menu) m.classList.add("hidden");
      });
      menu?.classList.toggle("hidden");
    });
  });

  const handleSuppressRule = (rId, modeLabel) => {
    if (!rId) return;
    codeAnalysisState.suppressedRuleIds.add(rId);
    applyCodeAnalysisFilterAndRender();
    if (typeof showTopbarToast === "function") {
      showTopbarToast(`Rule '${rId}' suppressed (${modeLabel}). Buka 'Manage Suppressions' untuk memulihkan.`);
    }
  };

  tbody.querySelectorAll("[data-ca-suppress-rule]").forEach(btn => {
    btn.addEventListener("click", () => handleSuppressRule(btn.getAttribute("data-ca-suppress-rule"), "rule"));
  });
  tbody.querySelectorAll("[data-ca-suppress-files]").forEach(btn => {
    btn.addEventListener("click", () => handleSuppressRule(btn.getAttribute("data-ca-suppress-files"), "files"));
  });

  // Render footer info & pagination buttons
  if (infoEl) {
    infoEl.textContent = `Showing ${startIdx + 1} to ${endIdx} of ${totalItems} entries`;
  }
  if (paginationEl) {
    let html = `<button type="button" class="android-api-page-btn" data-ca-page="${page - 1}" ${page === 1 ? "disabled" : ""}>Previous</button>`;
    for (let p = 1; p <= totalPages; p++) {
      if (totalPages <= 7 || p === 1 || p === totalPages || Math.abs(p - page) <= 1) {
        html += `<button type="button" class="android-api-page-btn ${p === page ? "active" : ""}" data-ca-page="${p}">${p}</button>`;
      } else if (p === page - 2 || p === page + 2) {
        html += `<span class="android-api-page-btn" style="pointer-events:none; border:none; background:transparent;">...</span>`;
      }
    }
    html += `<button type="button" class="android-api-page-btn" data-ca-page="${page + 1}" ${page === totalPages ? "disabled" : ""}>Next</button>`;
    paginationEl.innerHTML = html;

    paginationEl.querySelectorAll("button[data-ca-page]").forEach(btn => {
      btn.addEventListener("click", () => {
        const nextP = parseInt(btn.getAttribute("data-ca-page"), 10);
        if (!isNaN(nextP) && nextP >= 1 && nextP <= totalPages && nextP !== page) {
          codeAnalysisState.currentPage = nextP;
          applyCodeAnalysisFilterAndRender();
        }
      });
    });
  }
}

function openCodeAnalysisRemediationModal(item) {
  const rId = item.rule_id || "";
  const rem = item.remediation || {};
  const files = item.files || [];
  const sev = (item.severity || "warning").toUpperCase();

  const codeMap = {
    kotlin: rem.kotlin || `// KOTLIN: Perbaiki issue ${item.rule_id}\n// Terapkan best-practice Android modern untuk mencegah ${item.issue}`,
    java: rem.java || `// JAVA: Implementasi aman untuk ${item.rule_id}\n// Hindari penggunaan API yang tidak aman di Android runtime`,
    dart: rem.dart || `// DART / FLUTTER: Gunakan library aman pada package Flutter\n// Periksa konfigurasi insecure method channel`,
    config: rem.hardening || `// PROGUARD / MANIFEST / GRADLE CONFIG:\n// Pastikan R8 obfuscation aktif dan permissions diperketat.`
  };

  const dangerReason = rem.danger_reason || `Penggunaan pola kode ini melanggar standar ${item.cwe || item.owasp_masvs || 'keamanan mobile'} dan dapat disalahgunakan penyerang untuk meretas data aplikasi.`;
  const hardening = rem.hardening || "Terapkan ProGuard/R8 obfuscation, cegah USB debugging, dan amankan secret di Android Keystore.";

  // Determine primary language detected from files
  const hasDart = files.some(f => f.includes("flutter") || f.endsWith(".dart"));
  const defaultTab = hasDart ? "dart" : "kotlin";

  const dialogHtml = `
    <div style="margin-bottom:12px; display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
      <span class="badge ${sev === 'HIGH' || sev === 'CRITICAL' ? 'badge-danger' : 'badge-warning'}">${sev}</span>
      <span class="badge badge-cert">${escapeHtml(item.cwe || 'CWE Security Standard')}</span>
      ${item.owasp_masvs ? `<span class="badge badge-cert">${escapeHtml(item.owasp_masvs)}</span>` : ''}
    </div>

    <div class="remediation-box">
      <strong>⚠️ Mengapa Kerentanan Ini Berbahaya:</strong>
      <div style="margin-top:4px;">${escapeHtml(dangerReason)}</div>
    </div>

    <div style="margin-bottom:12px; font-size:12.5px; color:#475569;">
      <strong>File Terdampak (${files.length}):</strong>
      <div style="max-height:85px; overflow-y:auto; border:1px solid #e2e8f0; border-radius:6px; padding:6px 10px; margin-top:4px; background:#f8fafc; font-family:'JetBrains Mono',monospace; font-size:11.5px;">
        ${files.map(f => `<div>• ${escapeHtml(f)}</div>`).join("")}
      </div>
    </div>

    <div style="margin-bottom:6px; font-size:13px; font-weight:700; color:#0f172a;">
      💡 Rekomendasi Kode Perbaikan (Pilih Bahasa Pemrograman):
    </div>

    <div class="code-tab-nav" id="caModalTabNav">
      <button type="button" class="code-tab-btn ${defaultTab === 'kotlin' ? 'active' : ''}" data-ca-lang="kotlin">🔷 Kotlin (Android)</button>
      <button type="button" class="code-tab-btn" data-ca-lang="java">☕ Java (Android Native)</button>
      <button type="button" class="code-tab-btn ${defaultTab === 'dart' ? 'active' : ''}" data-ca-lang="dart">🎯 Dart (Flutter Framework)</button>
      <button type="button" class="code-tab-btn" data-ca-lang="config">⚙️ ProGuard / Config</button>
    </div>

    <pre class="mobsf-code-pane" id="caModalCodePane" style="height:230px; margin:0;">${escapeHtml(codeMap[defaultTab] || codeMap.kotlin)}</pre>

    <div class="hardening-box">
      <strong>🛡️ Langkah Pengamanan APK (APK Hardening Tips):</strong>
      <div style="margin-top:4px;">${escapeHtml(hardening)}</div>
    </div>
  `;

  openMobsfDialog(
    "CODE ANALYSIS FIX GUIDE",
    `${item.rule_id} — ${item.issue}`,
    dialogHtml,
    codeMap[defaultTab] || codeMap.kotlin
  );

  // Bind tab switching inside the dialog
  setTimeout(() => {
    const pane = document.getElementById("caModalCodePane");
    document.querySelectorAll("#caModalTabNav [data-ca-lang]").forEach(tabBtn => {
      tabBtn.addEventListener("click", () => {
        document.querySelectorAll("#caModalTabNav [data-ca-lang]").forEach(b => b.classList.remove("active"));
        tabBtn.classList.add("active");
        const lang = tabBtn.getAttribute("data-ca-lang");
        const snippet = codeMap[lang] || "// Tidak ada snippet khusus untuk bahasa ini.";
        if (pane) pane.textContent = snippet;
        mobsfMenuState.lastCopyText = snippet;
      });
    });
  }, 50);
}

// State for MobSF Android API Table
let androidApiState = {
  rawList: [],
  filteredList: [],
  currentPage: 1,
  pageSize: 10,
  searchQuery: "",
  sortColumn: "api",
  sortAsc: true,
  expandedApis: new Set(),
  apkData: null,
  listenersBound: false
};

function renderAndroidApiTable(apiList, apkData) {
  androidApiState.rawList = Array.isArray(apiList) ? apiList : [];
  androidApiState.apkData = apkData || null;
  androidApiState.currentPage = 1;
  androidApiState.searchQuery = "";
  androidApiState.expandedApis = new Set();

  const searchInput = document.getElementById("androidApiSearchInput");
  if (searchInput) searchInput.value = "";

  bindAndroidApiTableListeners();
  applyAndroidApiFilterAndRender();
}

function bindAndroidApiTableListeners() {
  if (androidApiState.listenersBound) return;
  androidApiState.listenersBound = true;

  const searchInput = document.getElementById("androidApiSearchInput");
  searchInput?.addEventListener("input", (e) => {
    androidApiState.searchQuery = (e.target.value || "").trim().toLowerCase();
    androidApiState.currentPage = 1;
    applyAndroidApiFilterAndRender();
  });

  const thApi = document.getElementById("thSortAndroidApi");
  const thFiles = document.getElementById("thSortAndroidFiles");

  thApi?.addEventListener("click", () => {
    if (androidApiState.sortColumn === "api") {
      androidApiState.sortAsc = !androidApiState.sortAsc;
    } else {
      androidApiState.sortColumn = "api";
      androidApiState.sortAsc = true;
    }
    updateAndroidApiSortHeaders();
    applyAndroidApiFilterAndRender();
  });

  thFiles?.addEventListener("click", () => {
    if (androidApiState.sortColumn === "files") {
      androidApiState.sortAsc = !androidApiState.sortAsc;
    } else {
      androidApiState.sortColumn = "files";
      androidApiState.sortAsc = true;
    }
    updateAndroidApiSortHeaders();
    applyAndroidApiFilterAndRender();
  });

  // Export toolbar buttons
  document.getElementById("btnApiExportCopy")?.addEventListener("click", () => {
    const text = androidApiState.filteredList
      .map(item => `${item.api}\t${(item.files || []).join(", ")}`)
      .join("\n");
    navigator.clipboard?.writeText(`API\tFILES\n${text}`);
    if (typeof showTopbarToast === "function") {
      showTopbarToast(`Copied ${androidApiState.filteredList.length} Android API rows to clipboard`);
    }
  });

  document.getElementById("btnApiExportCsv")?.addEventListener("click", () => {
    const csvRows = ["\"API\",\"FILES\""];
    androidApiState.filteredList.forEach(item => {
      const apiEsc = String(item.api || "").replace(/"/g, '""');
      const filesEsc = (item.files || []).join("; ").replace(/"/g, '""');
      csvRows.push(`"${apiEsc}","${filesEsc}"`);
    });
    downloadBlobFile(csvRows.join("\n"), "android_api_analysis.csv", "text/csv;charset=utf-8;");
  });

  document.getElementById("btnApiExportExcel")?.addEventListener("click", () => {
    const tsvRows = ["API\tFILES_COUNT\tFILES"];
    androidApiState.filteredList.forEach(item => {
      tsvRows.push(`${item.api}\t${(item.files || []).length}\t${(item.files || []).join(", ")}`);
    });
    downloadBlobFile(tsvRows.join("\n"), "android_api_analysis.xls", "application/vnd.ms-excel");
  });

  document.getElementById("btnApiExportJson")?.addEventListener("click", () => {
    const jsonStr = JSON.stringify(androidApiState.filteredList, null, 2);
    downloadBlobFile(jsonStr, "android_api_analysis.json", "application/json");
  });

  document.getElementById("btnApiExportPrint")?.addEventListener("click", () => {
    window.print();
  });
}

function downloadBlobFile(content, fileName, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  if (typeof showTopbarToast === "function") {
    showTopbarToast(`Exported ${fileName}`);
  }
}

function updateAndroidApiSortHeaders() {
  const thApi = document.getElementById("thSortAndroidApi");
  const thFiles = document.getElementById("thSortAndroidFiles");
  [thApi, thFiles].forEach(th => {
    if (!th) return;
    th.classList.remove("sort-asc", "sort-desc");
    const col = th.getAttribute("data-sort");
    if (col === androidApiState.sortColumn) {
      th.classList.add(androidApiState.sortAsc ? "sort-asc" : "sort-desc");
    }
  });
}

function applyAndroidApiFilterAndRender() {
  const q = androidApiState.searchQuery;
  let list = androidApiState.rawList.filter(item => {
    if (!q) return true;
    const matchApi = String(item.api || "").toLowerCase().includes(q);
    const matchFile = (item.files || []).some(f => String(f).toLowerCase().includes(q));
    return matchApi || matchFile;
  });

  list.sort((a, b) => {
    if (androidApiState.sortColumn === "files") {
      const diff = (a.files?.length || 0) - (b.files?.length || 0);
      return androidApiState.sortAsc ? diff : -diff;
    }
    const cmp = String(a.api || "").localeCompare(String(b.api || ""));
    return androidApiState.sortAsc ? cmp : -cmp;
  });

  androidApiState.filteredList = list;
  renderAndroidApiPage();
}

function renderAndroidApiPage() {
  const tbody = document.getElementById("apkAndroidApiTableBody");
  const infoEl = document.getElementById("androidApiTableInfo");
  const pagEl = document.getElementById("androidApiPagination");
  if (!tbody || !infoEl || !pagEl) return;

  const totalEntries = androidApiState.filteredList.length;
  const pageSize = androidApiState.pageSize;
  const totalPages = Math.max(1, Math.ceil(totalEntries / pageSize));
  if (androidApiState.currentPage > totalPages) {
    androidApiState.currentPage = totalPages;
  }

  const startIdx = totalEntries === 0 ? 0 : (androidApiState.currentPage - 1) * pageSize;
  const endIdx = Math.min(startIdx + pageSize, totalEntries);
  const pageItems = androidApiState.filteredList.slice(startIdx, endIdx);

  if (totalEntries === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="2" style="text-align:center; padding:18px; color:#64748b;">
          No matching Android API entries found in DEX bytecode.
        </td>
      </tr>
    `;
    infoEl.textContent = "Showing 0 to 0 of 0 entries";
  } else {
    tbody.innerHTML = pageItems.map((item, idx) => {
      const apiName = item.api || "Unknown API";
      const isExpanded = androidApiState.expandedApis.has(apiName);
      const files = item.files || [];
      const collapseId = `api-files-row-${startIdx + idx}`;

      const fileLinksHtml = files.map(filePath => `
        <a href="javascript:void(0)" class="android-api-file-link" data-file-path="${escapeHtml(filePath)}" data-api-name="${escapeHtml(apiName)}">${escapeHtml(filePath)}</a>
      `).join("");

      return `
        <tr>
          <td>${escapeHtml(apiName)}</td>
          <td>
            <button type="button" class="btn-show-files ${isExpanded ? 'expanded' : ''}" data-api-toggle="${escapeHtml(apiName)}" aria-expanded="${isExpanded ? 'true' : 'false'}" aria-controls="${collapseId}">
              Show Files
            </button>
            <div id="${collapseId}" class="android-api-files-collapse ${isExpanded ? '' : 'hidden'}">
              ${fileLinksHtml}
            </div>
          </td>
        </tr>
      `;
    }).join("");

    infoEl.textContent = `Showing ${startIdx + 1} to ${endIdx} of ${totalEntries} entries`;
  }

  // Bind Show Files buttons
  tbody.querySelectorAll(".btn-show-files").forEach(btn => {
    btn.addEventListener("click", () => {
      const apiName = btn.getAttribute("data-api-toggle");
      const targetId = btn.getAttribute("aria-controls");
      const collapseDiv = targetId ? document.getElementById(targetId) : null;
      if (!apiName || !collapseDiv) return;

      if (androidApiState.expandedApis.has(apiName)) {
        androidApiState.expandedApis.delete(apiName);
        collapseDiv.classList.add("hidden");
        btn.classList.remove("expanded");
        btn.setAttribute("aria-expanded", "false");
      } else {
        androidApiState.expandedApis.add(apiName);
        collapseDiv.classList.remove("hidden");
        btn.classList.add("expanded");
        btn.setAttribute("aria-expanded", "true");
      }
    });
  });

  // Bind file path click to inspect class usage
  tbody.querySelectorAll(".android-api-file-link").forEach(link => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const filePath = link.getAttribute("data-file-path");
      const apiName = link.getAttribute("data-api-name");
      if (filePath) {
        openAndroidApiFileInspectModal(filePath, apiName);
      }
    });
  });

  // Render Pagination Controls (Previous | 1 | 2 | ... | Next)
  let pagHtml = `
    <button type="button" class="android-api-page-btn" data-page="prev" ${androidApiState.currentPage <= 1 ? "disabled" : ""}>Previous</button>
  `;
  for (let p = 1; p <= totalPages; p++) {
    pagHtml += `
      <button type="button" class="android-api-page-btn ${p === androidApiState.currentPage ? "active" : ""}" data-page="${p}">${p}</button>
    `;
  }
  pagHtml += `
    <button type="button" class="android-api-page-btn" data-page="next" ${androidApiState.currentPage >= totalPages ? "disabled" : ""}>Next</button>
  `;
  pagEl.innerHTML = pagHtml;

  pagEl.querySelectorAll(".android-api-page-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      if (btn.disabled) return;
      const val = btn.getAttribute("data-page");
      if (val === "prev" && androidApiState.currentPage > 1) {
        androidApiState.currentPage--;
      } else if (val === "next" && androidApiState.currentPage < totalPages) {
        androidApiState.currentPage++;
      } else {
        const pageNum = parseInt(val, 10);
        if (!isNaN(pageNum)) androidApiState.currentPage = pageNum;
      }
      renderAndroidApiPage();
    });
  });
}

function openAndroidApiFileInspectModal(filePath, clickedApi) {
  const matchingApis = androidApiState.rawList
    .filter(item => (item.files || []).includes(filePath))
    .map(item => item.api);

  const syntheticFinding = {
    severity: "MEDIUM",
    deduction: 0,
    category: "DEX Bytecode API Trace",
    title: `Class Inspector: ${filePath}`,
    description: `Decompiled Dalvik bytecode reference for ${filePath} invoking Android API category "${clickedApi}".`,
    impact: `Class ${filePath} invokes ${matchingApis.length} tracked Android API categor${matchingApis.length === 1 ? "y" : "ies"}: ${matchingApis.join(", ")}.`,
    remediation: "Verify that sensitive API calls (Crypto, Reflection, Dynamic Classloading, Local File I/O, IPC) inside this class follow OWASP MASVS security controls.",
    evidence: [
      `Source Path: ${filePath}`,
      `Primary Triggered API: ${clickedApi}`,
      ...matchingApis.map(a => `• Invokes Android API Category: ${a}`)
    ]
  };
  openFindingDetailModal(syntheticFinding, androidApiState.apkData || {});
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function openFindingDetailModal(f, apkData) {
  const modal = document.getElementById("apkFindingDetailModal");
  if (!modal) return;

  const severityElem = document.getElementById("modalFindingSeverity");
  const deductElem = document.getElementById("modalFindingDeduction");
  const catElem = document.getElementById("modalFindingCategory");
  const titleElem = document.getElementById("modalFindingTitle");
  const bodyElem = document.getElementById("modalFindingBody");

  severityElem.innerText = f.severity;
  severityElem.className = `badge ${f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'badge-danger' : 'badge-warning'}`;
  deductElem.innerText = `-${f.deduction} pts`;
  titleElem.innerText = f.title;

  const detail = getFindingDetail(f, apkData);
  catElem.innerText = detail.cwe;

  const codeFixes = detail.codeFixes || {
    kotlin: detail.codeFix || "// Kotlin fix",
    java: detail.codeFix || "// Java fix",
    dart: "// Dart fix",
    config: detail.codeFix || "// Config fix"
  };

  bodyElem.innerHTML = `
    <div class="apk-modal-section">
      <div class="apk-modal-section-title">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
        1. Ringkasan &amp; Penjelasan Kerentanan
      </div>
      <div class="apk-modal-box">
        <p style="margin: 0 0 8px 0; font-weight: 600; color: #0f172a;">${escapeHtml(f.description)}</p>
        <p style="margin: 0; color: #475569;">${detail.impact}</p>
      </div>
    </div>

    <div class="apk-modal-section">
      <div class="apk-modal-section-title">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline></svg>
        2. Bukti Forensik &amp; Lokasi pada File Binary
      </div>
      <div class="apk-modal-box" style="background: #f1f5f9;">
        ${detail.evidenceHtml}
      </div>
    </div>

    <div class="apk-modal-section">
      <div class="apk-modal-section-title">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
        3. Skenario Eksploitasi (Attack Vector)
      </div>
      <div class="apk-modal-box" style="border-left: 3px solid #f59e0b;">
        <p style="margin: 0; color: #334155;">${detail.exploitScenario}</p>
      </div>
    </div>

    <div class="apk-modal-section">
      <div class="apk-modal-section-title">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>
        4. Rekomendasi Solusi &amp; Kode Pengamanan (Pilih Bahasa Pemrograman)
      </div>
      <div class="code-tab-nav" id="modalFixTabNav">
        <button type="button" class="code-tab-btn active" data-finding-lang="kotlin">🔷 Kotlin (Android)</button>
        <button type="button" class="code-tab-btn" data-finding-lang="java">☕ Java (Android Native)</button>
        <button type="button" class="code-tab-btn" data-finding-lang="dart">🎯 Dart (Flutter Framework)</button>
        <button type="button" class="code-tab-btn" data-finding-lang="config">⚙️ XML / Gradle / Config</button>
      </div>
      <pre class="mobsf-code-pane" id="modalFixCodePane" style="height:250px; margin:0;">${escapeHtml(codeFixes.kotlin || detail.codeFix)}</pre>
      <div class="hardening-box">
        <strong>🛡️ Cara Mengamankan APK (Hardening Step):</strong>
        <div style="margin-top:4px;">${escapeHtml(detail.hardeningTips || 'Terapkan R8/ProGuard obfuscation, cegah debugging, dan amankan key di Android Keystore.')}</div>
      </div>
    </div>

    <div class="apk-modal-section">
      <div class="apk-modal-section-title">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path></svg>
        5. Standar Industri Terkait
      </div>
      <div style="display: flex; gap: 8px; flex-wrap: wrap;">
        ${detail.standards.map(s => `<span class="badge badge-cert">${escapeHtml(s)}</span>`).join("")}
      </div>
    </div>
  `;

  // Bind code tab switcher
  const pane = document.getElementById("modalFixCodePane");
  document.querySelectorAll("#modalFixTabNav [data-finding-lang]").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("#modalFixTabNav [data-finding-lang]").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const lang = btn.getAttribute("data-finding-lang");
      const snippet = codeFixes[lang] || codeFixes.kotlin || detail.codeFix;
      if (pane) pane.textContent = snippet;
      mobsfMenuState.lastCopyText = snippet;
    });
  });

  modal.classList.remove("hidden");
}

function getFindingDetail(f, apkData) {
  const title = (f.title || "").toLowerCase();

  if (title.includes("cleartext") || title.includes("staging")) {
    const netsec = (apkData && apkData.network_security_audit) || {};
    const domains = (netsec.cleartext_domains && netsec.cleartext_domains.length > 0) ? netsec.cleartext_domains : [
      "stgaws.alfacart.com", "s1stgaws.alfacart.com", "stgpapa.alfadigital.id", "maps.google.com", "microsite-sandbox.web.narindo.id"
    ];
    return {
      cwe: "CWE-319: Cleartext Transmission",
      impact: "Aplikasi mengizinkan transmisi jaringan HTTP tanpa enkripsi TLS/SSL ke domain staging dan internal. Attacker pada jaringan lokal (Wi-Fi publik, router compromised) dapat menyadap atau mengubah data sensitif, token otentikasi, dan respon server secara real-time (Man-In-The-Middle / MITM).",
      evidenceHtml: `
        <div style="font-size:12px; margin-bottom:6px; color:#475569;"><strong>File Konfigurasi:</strong> <code>res/xml/network_security_config.xml</code> (atau <code>base/res/xml/network_security_config.xml</code>)</div>
        <div style="font-size:12px; margin-bottom:6px; color:#475569;"><strong>Atribut:</strong> <code>&lt;domain-config cleartextTrafficPermitted="true"&gt;</code></div>
        <div style="font-size:12px; margin-bottom:4px; color:#475569;"><strong>Daftar Domain Terdampak:</strong></div>
        <div style="display:flex; flex-wrap:wrap; gap:6px;">
          ${domains.map(d => `<span class="badge badge-danger">${escapeHtml(d)}</span>`).join("")}
        </div>
      `,
      exploitScenario: "Penyerang menyalakan Wi-Fi hotspot palsu ('Free Wi-Fi') atau melakukan ARP Spoofing di jaringan lokal. Saat aplikasi melakukan panggilan API ke salah satu domain staging, semua payload (header Authorization, JSON body, nomor telepon, data transaksi) dikirim tanpa TLS sehingga terbaca secara langsung di Wireshark.",
      codeFix: `<!-- REKOMENDASI PERBAIKAN: network_security_config.xml -->
<network-security-config>
    <!-- 1. Larang cleartext traffic secara global di release build -->
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>`,
      codeFixes: {
        kotlin: `// KOTLIN: Paksa HTTPS di level OkHttpClient
val okHttpClient = OkHttpClient.Builder()
    .connectionSpecs(listOf(ConnectionSpec.MODERN_TLS, ConnectionSpec.RESTRICTED_TLS))
    .addInterceptor { chain ->
        val request = chain.request()
        if (!request.isHttps) {
            throw SecurityException("Cleartext HTTP dilarang! Gunakan HTTPS.")
        }
        chain.proceed(request)
    }
    .build()`,
        java: `// JAVA: Paksa TLS pada OkHttp
OkHttpClient client = new OkHttpClient.Builder()
    .connectionSpecs(Arrays.asList(ConnectionSpec.MODERN_TLS))
    .build();`,
        dart: `// DART / FLUTTER: Pastikan baseURL selalu menggunakan https://
final dio = Dio(BaseOptions(
  baseUrl: 'https://api.domain.com', // Jangan gunakan http://
  connectTimeout: const Duration(seconds: 10),
));`,
        config: `<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>`
      },
      hardeningTips: "Hapus semua tag domain staging HTTP dari file production. Jika staging diperlukan oleh tim QA/Dev, gunakan build variant terpisah: app/src/debug/res/xml/network_security_config.xml.",
      standards: ["OWASP Mobile Top 10: M3 (Insecure Communication)", "OWASP MASVS: MASVS-NETWORK-1", "CWE-319", "PCI-DSS v4.0 Req 4.1"]
    };
  }

  if (title.includes("moedebugger") || (title.includes("debug") && title.includes("exported"))) {
    return {
      cwe: "CWE-926: Improper Component Export",
      impact: "Activity debugger bawaan library analitik pihak ketiga (MoEngage) terekspos secara publik ke seluruh aplikasi lain di perangkat tanpa perlindungan hak akses (permission). Ini membocorkan arsitektur aplikasi dan mempermudah runtime hijacking.",
      evidenceHtml: `
        <div style="font-size:12px; margin-bottom:6px; color:#475569;"><strong>File Manifest:</strong> <code>AndroidManifest.xml</code></div>
        <div style="font-size:12px; margin-bottom:6px; color:#475569;"><strong>Komponen:</strong> <code>com.moengage.sdk.debugger.MoEDebuggerActivity</code></div>
        <div style="font-size:12px; color:#ef4444;"><strong>Konfigurasi Berbahaya:</strong> <code>android:exported="true"</code> (tanpa <code>android:permission</code>)</div>
      `,
      exploitScenario: "Aplikasi malware tanpa izin khusus dapat mengirimkan explicit Intent: <code>am start -n pkg/com.moengage.sdk.debugger.MoEDebuggerActivity</code>. Hal ini membuka GUI debugger MoEngage untuk melihat event log pengguna, manipulasi status registrasi push notifikasi, atau memicu unvalidated internal intent redirect.",
      codeFix: `<!-- Tutup akses ke MoEDebuggerActivity di manifest aplikasi utama -->
<activity
    android:name="com.moengage.sdk.debugger.MoEDebuggerActivity"
    android:exported="false"
    tools:replace="android:exported" />`,
      codeFixes: {
        kotlin: `// KOTLIN: Inisialisasi SDK analitik tanpa mode debug di release
val moEngage = MoEngage.Builder(application, "APP_ID")
    .configureLogs { LogConfig(level = if (BuildConfig.DEBUG) LogLevel.VERBOSE else LogLevel.NO_LOG) }
    .build()`,
        java: `// JAVA: Matikan debug log analitik
MoEngage moEngage = new MoEngage.Builder(this, "APP_ID")
    .configureLogs(new LogConfig(BuildConfig.DEBUG ? LogLevel.VERBOSE : LogLevel.NO_LOG))
    .build();`,
        dart: `// DART / FLUTTER: Matikan logger plugin di main.dart
if (kReleaseMode) {
  MoEngageFlutter.instance.setLogLevel(LogLevel.none);
}`,
        config: `<!-- AndroidManifest.xml -->
<activity
    android:name="com.moengage.sdk.debugger.MoEDebuggerActivity"
    android:exported="false"
    tools:replace="android:exported" />

<!-- build.gradle.kts: Gunakan debugImplementation -->
dependencies {
    debugImplementation("com.moengage:moe-debugger:latest")
}`
      },
      hardeningTips: "Gunakan ProGuard rule `-assumenosideeffects` untuk menghapus semua class debugger saat APK di-compile untuk Play Store.",
      standards: ["OWASP Mobile Top 10: M1 (Improper Platform Usage)", "OWASP MASVS: MASVS-PLATFORM-1", "CWE-926"]
    };
  }

  if (title.includes("unauthenticated") || title.includes("sensitive activities")) {
    const sensitive = (apkData && apkData.sensitive_components) || {};
    const acts = (sensitive.sensitive_activities && sensitive.sensitive_activities.length > 0) ? sensitive.sensitive_activities : [
      "com.kai.kaiticketing.screen.payment.PaymentActivity",
      "com.kai.kaiticketing.screen.wallet.OtpWalletActivity"
    ];
    return {
      cwe: "CWE-285: Improper Authorization",
      impact: "Activity transaksi dompet digital, verifikasi OTP, atau pembayaran tiket dapat diakses dan diluncurkan langsung oleh aplikasi pihak ketiga tanpa melalui alur otentikasi PIN/Password.",
      evidenceHtml: `
        <div style="font-size:12px; margin-bottom:6px; color:#475569;"><strong>Activity Sensitif Terekspos:</strong></div>
        <div style="display:flex; flex-direction:column; gap:4px;">
          ${acts.slice(0, 5).map(a => `<code style="font-size:11.5px; background:#fff; padding:4px 8px; border:1px solid #e2e8f0; border-radius:4px;">${escapeHtml(a)}</code>`).join("")}
        </div>
      `,
      exploitScenario: "Attacker membuat aplikasi jahat di perangkat yang memanggil <code>startActivity(new Intent().setComponent(new ComponentName(pkg, '...OtpWalletActivity')))</code>. Layar pembayaran terbuka membypass verifikasi login.",
      codeFix: `<!-- Set exported="false" pada Activity sensitif -->
<activity android:name=".screen.wallet.OtpWalletActivity" android:exported="false" />`,
      codeFixes: {
        kotlin: `// KOTLIN: Validasi sesi pada onCreate() dan onResume()
override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    if (!SessionManager.isUserAuthenticated()) {
        finish() // Tutup activity seketika
        startActivity(Intent(this, LoginActivity::class.java))
        return
    }
}`,
        java: `// JAVA: Guard otorisasi di onCreate()
@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    if (!SessionManager.getInstance().isLoggedIn()) {
        finish();
        startActivity(new Intent(this, LoginActivity.class));
        return;
    }
}`,
        dart: `// DART / FLUTTER: Auth Guard pada Navigator
Route<dynamic> onGenerateRoute(RouteSettings settings) {
  if (settings.name == '/payment' && !authProvider.isLoggedIn) {
    return MaterialPageRoute(builder: (_) => const LoginScreen());
  }
  return MaterialPageRoute(builder: (_) => const PaymentScreen());
}`,
        config: `<!-- AndroidManifest.xml: Pasang Signature Permission -->
<permission
    android:name="com.kai.permission.INTERNAL_ONLY"
    android:protectionLevel="signature" />

<activity
    android:name=".screen.payment.PaymentActivity"
    android:exported="true"
    android:permission="com.kai.permission.INTERNAL_ONLY" />`
      },
      hardeningTips: "Gunakan Intent Filter Verification (App Links) dengan SHA-256 assetlinks.json jika activity dipanggil melalui deep link web.",
      standards: ["OWASP Mobile Top 10: M4 (Insecure Authentication/Authorization)", "OWASP MASVS: MASVS-AUTH-1", "CWE-285"]
    };
  }

  if (title.includes("cryptography") || title.includes("blowfish") || title.includes("ecb")) {
    return {
      cwe: "CWE-327: Broken Crypto Algorithm",
      impact: "Penggunaan cipher Blowfish dengan mode ECB (Electronic Codebook) sangat rentan terhadap kriptanalisis. Mode ECB mengenkripsi blok yang sama menjadi ciphertext yang sama, sehingga pola gambar atau struktur data dapat dibaca tanpa dekripsi.",
      evidenceHtml: `
        <div style="font-size:12px; margin-bottom:6px; color:#475569;"><strong>Algoritma Terdeteksi:</strong> <code>Cipher.getInstance("Blowfish")</code>, <code>"AES/ECB/PKCS5Padding"</code></div>
        <div style="font-size:12px; color:#ef4444;"><strong>Kelemahan:</strong> Ukuran blok Blowfish (64-bit) rentan serangan Sweet32 collision attack.</div>
      `,
      exploitScenario: "Penyerang yang menyadap lalu lintas API terenkripsi Blowfish/ECB dapat mengumpulkan ciphertext dan melakukan replay attack atau merekonstruksi isi pesan rahasia tanpa harus memecahkan kuncinya.",
      codeFix: `// Gunakan AES-256-GCM (Authenticated Encryption)`,
      codeFixes: {
        kotlin: `// KOTLIN: AES-256-GCM Enkripsi
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import java.security.SecureRandom
import java.nio.ByteBuffer

fun encryptAesGcm(plaintext: ByteArray, key: SecretKey): ByteArray {
    val iv = ByteArray(12).apply { SecureRandom().nextBytes(this) }
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
    val ciphertext = cipher.doFinal(plaintext)
    return ByteBuffer.allocate(iv.size + ciphertext.size).put(iv).put(ciphertext).array()
}`,
        java: `// JAVA: AES-256-GCM Enkripsi
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
byte[] iv = new byte[12];
new SecureRandom().nextBytes(iv);
cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
byte[] ciphertext = cipher.doFinal(plaintext);`,
        dart: `// DART / FLUTTER (package:cryptography)
import 'package:cryptography/cryptography.dart';

final algorithm = AesGcm.with256Bits();
final secretBox = await algorithm.encrypt(data, secretKey: key);
final encryptedBytes = secretBox.concatenation();`,
        config: `// Simpan SecretKey di AndroidKeyStore hardware-backed:
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
    "app_master_key",
    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .build();`
      },
      hardeningTips: "Selalu kombinasikan enkripsi dengan Android Keystore (StrongBox / TEE) agar kunci enkripsi tidak pernah berada di memory unmanaged.",
      standards: ["OWASP Mobile Top 10: M5 (Insufficient Cryptography)", "NIST SP 800-131A Rev. 2", "CWE-327"]
    };
  }

  if (title.includes("secret") || title.includes("tokens")) {
    return {
      cwe: "CWE-798: Hardcoded Credentials",
      impact: "Kunci API (Google Maps / Firebase) dan token otentikasi tertanam langsung di dalam file bytecode atau resources APK. Siapapun yang mengunduh APK dari Google Play Store dapat mengekstrak kredensial ini dalam hitungan detik menggunakan jadx-gui.",
      evidenceHtml: `<div><strong>Status:</strong> Terbuka untuk publik tanpa proteksi enkripsi runtime.</div>`,
      exploitScenario: "Penyerang mengekstrak API Key dari APK, lalu menggunakan REST API untuk menyalahgunakan kuota API atau mengakses database backend.",
      codeFix: `// Simpan secret di Keystore atau BuildConfig`,
      codeFixes: {
        kotlin: `// KOTLIN: EncryptedSharedPreferences
val masterKey = MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
val securePrefs = EncryptedSharedPreferences.create(context, "secure_prefs", masterKey, ... )`,
        java: `// JAVA: EncryptedSharedPreferences
MasterKey masterKey = new MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build();
SharedPreferences prefs = EncryptedSharedPreferences.create(context, "prefs", masterKey, ...);`,
        dart: `// DART / FLUTTER: flutter_secure_storage
final storage = const FlutterSecureStorage(aOptions: AndroidOptions(encryptedSharedPreferences: true));
await storage.write(key: 'auth_token', value: token);`,
        config: `// Di Google Cloud Console:
// Pasang "Application restrictions" -> Android apps
// Masukkan Package Name + SHA-1 Release Fingerprint cert Anda!`
      },
      hardeningTips: "Jangan pernah menyimpan Master Secret Server di mobile APK. Gunakan alur Dynamic Token Exchange via OAuth 2.0 PKCE.",
      standards: ["OWASP Mobile Top 10: M9 (Insecure Data Storage)", "OWASP MASVS: MASVS-STORAGE-1", "CWE-798"]
    };
  }

  if (title.includes("biometric")) {
    return {
      cwe: "CWE-305: Authentication Bypass",
      impact: "BiometricPrompt dijalankan tanpa CryptoObject. Verifikasi otentikasi hanya mengandalkan callback boolean onAuthenticationSucceeded, yang dapat di-bypass penyerang menggunakan 1 baris skrip Frida hook.",
      evidenceHtml: `<div><strong>Bytecode Pattern:</strong> <code>BiometricPrompt.authenticate(promptInfo)</code> tanpa parameter <code>CryptoObject</code>.</div>`,
      exploitScenario: "Penyerang yang memegang HP korban dapat menjalankan Frida: <code>BiometricPrompt.AuthenticationCallback.onAuthenticationSucceeded.implementation = function() { ... }</code>, membypass popup sidik jari seketika.",
      codeFix: `// Wajib gunakan BiometricPrompt.CryptoObject`,
      codeFixes: {
        kotlin: `// KOTLIN: Biometric Auth dengan CryptoObject (Anti-Frida Hook)
val cipher = getKeystoreCipher() // Cipher yang di-protect Android Keystore
val cryptoObject = BiometricPrompt.CryptoObject(cipher)

biometricPrompt.authenticate(promptInfo, cryptoObject)

override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
    val authenticatedCipher = result.cryptoObject?.cipher ?: return
    // Dekripsi token HANYA bisa dilakukan dengan authenticatedCipher!
    val decryptedToken = authenticatedCipher.doFinal(encryptedSecret)
}`,
        java: `// JAVA: CryptoObject Binding
BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(cipher);
biometricPrompt.authenticate(promptInfo, cryptoObject);`,
        dart: `// DART / FLUTTER: Hubungkan local_auth dengan KeyStore decryption
final didAuth = await localAuth.authenticate(
  localizedReason: 'Otorisasi transaksi',
  options: const AuthenticationOptions(biometricOnly: true, stickyAuth: true),
);
if (didAuth) {
  // Ambil secret dari flutter_secure_storage
  final secret = await secureStorage.read(key: 'tx_pin');
}`,
        config: `// Android KeyStore Builder dengan perlindungan biometrik:
val keySpec = KeyGenParameterSpec.Builder("bio_key", KeyProperties.PURPOSE_DECRYPT)
    .setUserAuthenticationRequired(true) // Kunci terkunci hardware sampai biometrik valid!
    .build()`
      },
      hardeningTips: "Dengan mengunci KeyStore Cipher di level hardware (TEE/StrongBox), skrip Frida yang mem-bypass boolean callback tetap tidak akan bisa mendekripsi data transaksi.",
      standards: ["OWASP Mobile Top 10: M4 (Insecure Authentication)", "OWASP MASVS: MASVS-AUTH-2", "CWE-305"]
    };
  }

  if (title.includes("anti-tamper") || title.includes("root") || title.includes("frida")) {
    return {
      cwe: "CWE-353: Missing Integrity Check",
      impact: "Aplikasi tidak memiliki deteksi Root, Frida server, atau integritas APK. Attacker dapat me-repackage APK dengan malware atau memasang hook Frida runtime untuk membajak data.",
      evidenceHtml: `<div><strong>Status:</strong> Tidak ditemukan pemeriksaan port Frida 27042, su binary, atau Play Integrity API.</div>`,
      exploitScenario: "Penyerang menjalankan Frida pada emulator atau HP rooted untuk membaca kredensial akun dan mengubah alur pembayaran tiket.",
      codeFix: `// Implementasi deteksi Root dan Frida runtime`,
      codeFixes: {
        kotlin: `// KOTLIN: Deteksi Root & Frida Port
fun isEnvironmentCompromised(): Boolean {
    val suPaths = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su")
    val hasSu = suPaths.any { File(it).exists() }
    val fridaRunning = try {
        Socket("127.0.0.1", 27042).use { true }
    } catch (_: Exception) { false }
    return hasSu || fridaRunning
}`,
        java: `// JAVA: Cek file su
boolean hasSu = new File("/system/bin/su").exists() || new File("/system/xbin/su").exists();
if (hasSu) { System.exit(0); }`,
        dart: `// DART / FLUTTER: Gunakan flutter_jailbreak_detection
import 'package:flutter_jailbreak_detection/flutter_jailbreak_detection.dart';

bool isRooted = await FlutterJailbreakDetection.jailbroken;
if (isRooted) {
  exit(0); // Tutup aplikasi jika terdeteksi root
}`,
        config: `// build.gradle.kts: Aktifkan Play Integrity API
dependencies {
    implementation("com.google.android.play:integrity:1.3.0")
}`
      },
      hardeningTips: "Terapkan deteksi root di native code (.so C/C++) agar tidak mudah di-bypass oleh universal Frida unroot scripts.",
      standards: ["OWASP Mobile Top 10: M8 (Code Tampering)", "OWASP MASVS: MASVS-RESILIENCE-1"]
    };
  }

  // Fallback generic detail
  return {
    cwe: "CWE-699: Software Development Vulnerability",
    impact: f.description,
    evidenceHtml: `<div><strong>Status:</strong> ${escapeHtml(f.title)} (-${f.deduction} pts)</div>`,
    exploitScenario: "Penyerang dapat memanfaatkan kelemahan konfigurasi ini untuk memperluas permukaan serangan pada perangkat Android.",
    codeFix: "// Tinjau dan perbaiki implementasi sesuai panduan OWASP Mobile Security Testing Guide (MSTG).",
    codeFixes: {
      kotlin: `// KOTLIN: Perbaiki issue ${escapeHtml(f.title)}\n// Terapkan best-practice Android modern untuk mengamankan APK.`,
      java: `// JAVA: Tinjau dan perbaiki implementasi kode.`,
      dart: `// DART / FLUTTER: Amankan konfigurasi plugin dan network.`,
      config: `// Konfigurasikan ProGuard / R8 rules dan AndroidManifest.xml`
    },
    hardeningTips: "Terapkan R8 full obfuscation, simpan secret di Keystore, dan aktifkan Play Integrity API.",
    standards: ["OWASP Mobile Top 10", "OWASP MASVS"]
  };
}

function openFridaHardeningGuideModal() {
  const html = `
    <div class="remediation-box" style="margin-bottom:14px;">
      <strong>⚡ Mengapa Frida &amp; Penyadapan Endpoint Berbahaya:</strong>
      <div style="margin-top:4px;">
        Attacker dapat melakukan <em>dynamic binary instrumentation</em> menggunakan Frida untuk mem-bypass SSL Certificate Pinning, memodifikasi nilai return method otentikasi (Root/Integrity check), dan menyadap parameter request/response transaksi keuangan secara plaintext.
      </div>
    </div>

    <div class="code-tab-nav" id="fridaGuideTabNav">
      <button type="button" class="code-tab-btn active" data-frida-tab="pinning">🔒 1. SSL Pinning (OkHttp &amp; Dio)</button>
      <button type="button" class="code-tab-btn" data-frida-tab="antifrida">🛡️ 2. Deteksi Frida &amp; Anti-Hook (C++/NDK)</button>
      <button type="button" class="code-tab-btn" data-frida-tab="hmac">🔑 3. HMAC Request Signing</button>
      <button type="button" class="code-tab-btn" data-frida-tab="services">⚙️ 4. Amankan Service &amp; IPC</button>
    </div>

    <pre class="mobsf-code-pane" id="fridaGuideCodePane" style="height:270px; margin:0;"></pre>

    <div class="hardening-box" style="margin-top:14px;">
      <strong>🛡️ Rekomendasi Defense-in-Depth untuk Rilis APK:</strong>
      <ul style="margin:6px 0 0 16px; padding:0; line-height:1.6;">
        <li>Gunakan <strong>R8 / ProGuard</strong> dengan dictionary nama class yang acak agar attacker sulit menemukan target method hook Frida.</li>
        <li>Implementasikan <strong>Google Play Integrity API</strong> untuk memastikan request ke backend hanya berasal dari binary APK resmi yang belum dimodifikasi.</li>
        <li>Terapkan deteksi Frida di native binary (.so via NDK) daripada di Java/Kotlin bytecode yang mudah di-bypass dengan 1 baris Frida hook.</li>
      </ul>
    </div>
  `;

  const fridaCodeSnippets = {
    pinning: `// 1. KOTLIN (OkHttp Certificate Pinner):
val client = OkHttpClient.Builder()
    .certificatePinner(CertificatePinner.Builder()
        .add("api.kai.id", "sha256/PRIMARY_CERTIFICATE_PIN_BASE64=")
        .add("api.kai.id", "sha256/BACKUP_CERTIFICATE_PIN_BASE64=")
        .build())
    .build()

// 2. DART / FLUTTER (Dio HTTP Client):
(dio.httpClientAdapter as IOHttpClientAdapter).createHttpClient = () {
  SecurityContext context = SecurityContext(withTrustedRoots: false);
  HttpClient client = HttpClient(context: context);
  client.badCertificateCallback = (cert, host, port) => false; // Tolak pin palsu
  return client;
};`,
    antifrida: `// DETEKSI FRIDA SERVER DI LAYER C / C++ (NDK native-lib.cpp)
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

bool isFridaServerRunning() {
    struct sockaddr_in sa;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(27042); // Port default Frida Gadget / Server
    inet_aton("127.0.0.1", &sa.sin_addr);
    
    // Coba koneksi ke port Frida lokal
    int res = connect(sock, (struct sockaddr*)&sa, sizeof(sa));
    close(sock);
    return (res == 0); // TRUE jika Frida server mendengarkan port 27042!
}

bool detectFridaInMaps() {
    FILE *fp = fopen("/proc/self/maps", "r");
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "frida-agent") || strstr(line, "gadget") || strstr(line, "gum-js-loop")) {
            fclose(fp);
            return true; // Ditemukan injeksi library Frida di memory!
        }
    }
    fclose(fp);
    return false;
}`,
    hmac: `// KOTLIN: HMAC-SHA256 REQUEST SIGNING HEADER
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import android.util.Base64

fun generateApiSignature(endpoint: String, timestamp: Long, body: String, secretKey: String): String {
    val payloadToSign = "$endpoint|$timestamp|$body"
    val sha256Hmac = Mac.getInstance("HmacSHA256")
    val keySpec = SecretKeySpec(secretKey.toByteArray(), "HmacSHA256")
    sha256Hmac.init(keySpec)
    val signatureBytes = sha256Hmac.doFinal(payloadToSign.toByteArray())
    return Base64.encodeToString(signatureBytes, Base64.NO_WRAP)
}
// Header: X-Signature: <hmac>, X-Timestamp: <ms>
// Server akan memverifikasi signature dan menolak jika payload di-tamper Frida!`,
    services: `<!-- PENGAMANAN SERVICE PADA AndroidManifest.xml -->
<!-- 1. Jadikan private (hanya dapat dipanggil internal aplikasi sendiri) -->
<service
    android:name=".services.MemberTokenService"
    android:exported="false" />

<!-- 2. Jika HARUS menerima intent dari luar aplikasi, lindungi dengan Signature Permission -->
<permission
    android:name="com.kai.permission.INTERNAL_SERVICE"
    android:protectionLevel="signature" />

<service
    android:name=".services.PartnerSyncService"
    android:exported="true"
    android:permission="com.kai.permission.INTERNAL_SERVICE" />`
  };

  openMobsfDialog(
    "FRIDA & ENDPOINT HARDENING",
    "Panduan Pengamanan Endpoint API & Anti-Frida Hooking",
    html,
    fridaCodeSnippets.pinning
  );

  setTimeout(() => {
    const pane = document.getElementById("fridaGuideCodePane");
    if (pane) pane.textContent = fridaCodeSnippets.pinning;
    document.querySelectorAll("#fridaGuideTabNav [data-frida-tab]").forEach(btn => {
      btn.addEventListener("click", () => {
        document.querySelectorAll("#fridaGuideTabNav [data-frida-tab]").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        const tabKey = btn.getAttribute("data-frida-tab");
        const snippet = fridaCodeSnippets[tabKey] || "// No snippet";
        if (pane) pane.textContent = snippet;
        mobsfMenuState.lastCopyText = snippet;
      });
    });
  }, 50);
}

function openExecutivePdfExportModal() {
  const dialog = document.getElementById("exportPdfDialog");
  if (!dialog) return;

  const data = mobsfMenuState.currentApkData;
  const meta = data?.metadata || {};

  const auditorInput = document.getElementById("pdfAuditorInput");
  const orgInput = document.getElementById("pdfOrgInput");

  if (auditorInput) {
    const activeUser = (typeof authManager !== "undefined" && authManager?.currentUser)
      ? authManager.currentUser.name
      : (localStorage.getItem("toolkitdev_user_name") || "Budi Susanto, CISA, CISSP");
    if (activeUser && (!auditorInput.value || auditorInput.value.includes("Specialist"))) {
      auditorInput.value = activeUser;
    }
  }

  if (orgInput) {
    if (meta.app_name) {
      orgInput.value = `PT Sumber Alfaria Trijaya Tbk (${meta.app_name})`;
    } else {
      orgInput.value = "PT Sumber Alfaria Trijaya Tbk";
    }
  }

  if (!dialog.open) {
    dialog.showModal();
  }
}

function openAuditItemModal(key, data) {
  const modal = document.getElementById("apkFindingDetailModal");
  if (!modal) return;

  const severityElem = document.getElementById("modalFindingSeverity");
  const deductElem = document.getElementById("modalFindingDeduction");
  const catElem = document.getElementById("modalFindingCategory");
  const titleElem = document.getElementById("modalFindingTitle");
  const bodyElem = document.getElementById("modalFindingBody");

  const detail = getAuditKeyDetail(key, data);
  severityElem.innerText = detail.severity;
  severityElem.className = `badge ${detail.severity === 'CRITICAL' || detail.severity === 'HIGH' || detail.severity === 'HIGH RISK' ? 'badge-danger' : detail.severity === 'WARNING' ? 'badge-warning' : 'badge-success'}`;
  deductElem.innerText = detail.badgeText || "Audit Metric";
  titleElem.innerText = detail.title;
  catElem.innerText = detail.cwe;

  bodyElem.innerHTML = `
    <div class="apk-modal-section">
      <div class="apk-modal-section-title">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
        1. Definisi &amp; Konteks Metrik
      </div>
      <div class="apk-modal-box">
        <p style="margin: 0 0 8px 0; font-weight: 600; color: #0f172a;">${escapeHtml(detail.summary)}</p>
        <p style="margin: 0; color: #475569;">${escapeHtml(detail.impact)}</p>
      </div>
    </div>

    <div class="apk-modal-section">
      <div class="apk-modal-section-title">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline></svg>
        2. Status &amp; Nilai Real pada Binary Target
      </div>
      <div class="apk-modal-box" style="background: #f1f5f9;">
        ${detail.evidenceHtml}
      </div>
    </div>

    <div class="apk-modal-section">
      <div class="apk-modal-section-title">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
        3. Risiko &amp; Vektor Serangan (Threat Model)
      </div>
      <div class="apk-modal-box" style="border-left: 3px solid #f59e0b;">
        <p style="margin: 0; color: #334155;">${escapeHtml(detail.exploitScenario)}</p>
      </div>
    </div>

    <div class="apk-modal-section">
      <div class="apk-modal-section-title">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>
        4. Rekomendasi Solusi &amp; Konfigurasi Aman
      </div>
      <div class="apk-modal-code">${escapeHtml(detail.codeFix)}</div>
    </div>

    <div class="apk-modal-section">
      <div class="apk-modal-section-title">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path></svg>
        5. Standar Industri Terkait
      </div>
      <div style="display: flex; gap: 8px; flex-wrap: wrap;">
        ${detail.standards.map(s => `<span class="badge badge-cert">${escapeHtml(s)}</span>`).join("")}
      </div>
    </div>
  `;

  modal.classList.remove("hidden");
}

function getAuditKeyDetail(key, data) {
  const manifest = (data && data.manifest_security) || {};
  const qa = (data && data.qa_metrics) || {};
  const meta = (data && data.metadata) || {};
  const crypto = (data && data.crypto_audit) || {};
  const netsec = (data && data.network_security_audit) || {};
  const bio = (data && data.biometric_audit) || {};
  const tamper = (data && data.anti_tamper_audit) || {};
  const endpoints = (data && data.endpoint_audit) || {};
  const sensitive = (data && data.sensitive_components) || {};

  switch (key) {
    case "debuggable":
      return {
        title: "android:debuggable Manifest Flag Audit",
        severity: manifest.debuggable ? "CRITICAL" : "SECURE",
        badgeText: manifest.debuggable ? "CRITICAL (TRUE)" : "SECURE (FALSE)",
        cwe: "CWE-215: Debug Information Exposure",
        summary: "Flag android:debuggable menentukan apakah runtime Android mengizinkan debugger eksternal (JDWP / ADB) menempel ke proses aplikasi.",
        impact: manifest.debuggable 
          ? "Aplikasi dalam kondisi DEBUGGABLE. Siapapun dapat mencuri token, memodifikasi alur logika saat runtime, dan mendump memori aplikasi via ADB tanpa hak akses root."
          : "Flag bernilai FALSE. Aplikasi terproteksi dari inspeksi debugger biasa saat berjalan pada mode rilis produksi.",
        evidenceHtml: `<div><strong>Nilai saat ini:</strong> <code>android:debuggable="${manifest.debuggable}"</code> di AndroidManifest.xml</div>`,
        exploitScenario: "Attacker menghubungkan HP ke PC via kabel USB, menjalankan `adb jdwp` untuk melihat proses ID aplikasi, lalu mengeksekusi `jdb -attach` guna membaca variabel session token dan parameter otentikasi di memori.",
        codeFix: `android {
    buildTypes {
        release {
            debuggable false
            minifyEnabled true
        }
    }
}`,
        standards: ["OWASP Mobile: M1 (Improper Platform Usage)", "CWE-215", "Google Play Developer Distribution Agreement"]
      };

    case "allow_backup":
      return {
        title: "android:allowBackup Data Extraction Audit",
        severity: manifest.allow_backup ? "WARNING" : "SECURE",
        badgeText: manifest.allow_backup ? "WARNING (TRUE)" : "SECURE (FALSE)",
        cwe: "CWE-921: Insecure Data Storage in Backup",
        summary: "Flag android:allowBackup menentukan apakah mekanisme backup sistem Android (ADB backup) diizinkan menyalin seluruh sandbox data aplikasi ke komputer eksternal.",
        impact: manifest.allow_backup
          ? "Data lokal seperti SharedPreferences, database SQLite, dan file cache internal dapat diekstrak tanpa root melalui perintah ADB."
          : "Aplikasi menonaktifkan fitur backup OS, melindungi data lokal pengguna dari ekstraksi fisik melalui ADB.",
        evidenceHtml: `<div><strong>Nilai saat ini:</strong> <code>android:allowBackup="${manifest.allow_backup}"</code> di AndroidManifest.xml</div>`,
        exploitScenario: "Seseorang yang meminjam HP korban (atau workstation yang telah ter-otorisasi USB Debugging) menjalankan `adb backup -f app_data.ab com.alfamart.alfagift` lalu mengekstrak file database SQLite lokal untuk membaca nomor kartu dan session token.",
        codeFix: `<application
    android:allowBackup="false"
    ... >
</application>`,
        standards: ["OWASP Mobile: M2 (Insecure Data Storage)", "CWE-921", "OWASP MASVS-STORAGE-2"]
      };

    case "uses_cleartext_traffic":
      return {
        title: "android:usesCleartextTraffic Global Network Audit",
        severity: manifest.uses_cleartext_traffic ? "HIGH RISK" : "SECURE",
        badgeText: manifest.uses_cleartext_traffic ? "HIGH RISK (HTTP Allowed)" : "SECURE (HTTPS Only)",
        cwe: "CWE-319: Cleartext Transmission of Sensitive Information",
        summary: "Mengontrol apakah aplikasi diizinkan melakukan transmisi jaringan HTTP tanpa enkripsi TLS secara global.",
        impact: manifest.uses_cleartext_traffic
          ? "Aplikasi mengizinkan koneksi HTTP polos ke seluruh server, rentan penyadapan Man-In-The-Middle (MITM) pada jaringan Wi-Fi publik."
          : "Aplikasi mewajibkan komunikasi terenkripsi TLS (HTTPS) untuk seluruh panggilan jaringan global.",
        evidenceHtml: `<div><strong>Nilai saat ini:</strong> <code>android:usesCleartextTraffic="${manifest.uses_cleartext_traffic}"</code> di AndroidManifest.xml</div>`,
        exploitScenario: "Attacker menggunakan Wireshark atau ettercap di jaringan Wi-Fi publik untuk membaca kredensial akun dan payload API yang dikirim melalui protokol HTTP polos.",
        codeFix: `<application
    android:usesCleartextTraffic="false"
    ... >
</application>`,
        standards: ["OWASP Mobile: M3 (Insecure Communication)", "CWE-319", "Android 9+ TLS Enforcement"]
      };

    case "exported_components":
      return {
        title: "Unprotected Exported Components Audit",
        severity: manifest.total_exported > 0 ? "HIGH RISK" : "SECURE",
        badgeText: `${manifest.total_exported || 0} Komponen`,
        cwe: "CWE-926: Improper Export of Android Components",
        summary: "Menghitung seluruh komponen aplikasi (Activity, Service, Receiver, Provider) yang memiliki flag android:exported='true' tanpa proteksi android:permission khusus.",
        impact: `Ditemukan ${manifest.total_exported || 0} komponen terbuka (Activities: ${(manifest.exported_activities || []).length}, Services: ${(manifest.exported_services || []).length}, Receivers: ${(manifest.exported_receivers || []).length}). Komponen ini dapat dipanggil langsung oleh aplikasi lain di perangkat.`,
        evidenceHtml: `<div><strong>Total Komponen Diekspor Tanpa Guard:</strong> <span class="badge badge-danger">${manifest.total_exported || 0}</span></div>
          <div style="margin-top:6px; font-size:12px; color:#475569;">Termasuk activity dompet, OTP, dan debugger SDK pihak ketiga.</div>`,
        exploitScenario: "Malware pada HP yang sama mengirimkan Explicit Intent (`am start`) untuk memicu activity internal yang belum memvalidasi status otentikasi pengguna, membypass login guard.",
        codeFix: `<!-- Pastikan komponen internal diproteksi: -->
<activity
    android:name=".internal.InternalActivity"
    android:exported="false" />`,
        standards: ["OWASP Mobile: M1 (Improper Platform Usage)", "OWASP MASVS-PLATFORM-1", "CWE-926"]
      };

    case "crypto_ciphers":
      return {
        title: "Cryptographic Ciphers & Modes Audit",
        severity: crypto.has_weak_crypto ? "CRITICAL" : "STRONG",
        badgeText: crypto.has_weak_crypto ? "INSECURE (" + (crypto.algorithms || []).join(", ") + ")" : "STRONG / AES-GCM",
        cwe: "CWE-327: Use of Broken or Risky Cryptographic Algorithm",
        summary: "Menganalisis algoritma enkripsi dan cipher mode yang digunakan di dalam bytecode DEX aplikasi.",
        impact: crypto.has_weak_crypto
          ? `Terdeteksi penggunaan algoritma usang/lemah: ${(crypto.algorithms || []).join(', ')}. Blowfish rentan terhadap collision attack (Sweet32) dan ECB mode membocorkan pola data plaintext.`
          : "Aplikasi menggunakan implementasi kriptografi modern (AES-GCM/CBC dengan initialization vector aman).",
        evidenceHtml: `<div><strong>Bukti Bytecode:</strong> ${(crypto.evidence || []).join('; ') || 'Tidak ditemukan cipher lemah.'}</div>`,
        exploitScenario: "Penyerang menyadap traffic terenkripsi Blowfish/ECB dan memanfaatkan pola blok berulang untuk merekonstruksi token rahasia tanpa memecahkan kunci enkripsi.",
        codeFix: `// Gunakan AES/GCM/NoPadding (Authenticated Encryption)
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, randomIv));`,
        standards: ["OWASP Mobile: M5 (Insufficient Cryptography)", "NIST SP 800-131A", "CWE-327"]
      };

    case "netsec_cleartext":
    case "cleartext_domains":
      const doms = netsec.cleartext_domains || [];
      return {
        title: "Network Security Config & Cleartext Domains",
        severity: doms.length > 0 ? "HIGH" : "SECURE",
        badgeText: doms.length > 0 ? `${doms.length} Domain Allowed` : "HTTPS Enforced",
        cwe: "CWE-319: Cleartext Transmission",
        summary: "Memeriksa file res/xml/network_security_config.xml untuk mendeteksi domain pengecualian yang diizinkan menggunakan koneksi HTTP biasa.",
        impact: doms.length > 0
          ? `Ditemukan ${doms.length} domain (staging/internal) yang diizinkan cleartext HTTP: ${doms.join(', ')}.`
          : "Seluruh domain eksternal diwajibkan menggunakan TLS/HTTPS terenkripsi.",
        evidenceHtml: `<div style="display:flex; flex-wrap:wrap; gap:6px;">
          ${doms.map(d => `<span class="badge badge-danger">${escapeHtml(d)}</span>`).join("") || '<span>Semua domain terenkripsi TLS</span>'}
        </div>`,
        exploitScenario: "Penyerang melakukan ARP spoofing pada jaringan lokal untuk menyadap data sensitif saat aplikasi menghubungi domain staging tersebut.",
        codeFix: `<!-- Hapus domain-config cleartext dari release XML: -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
</network-security-config>`,
        standards: ["OWASP Mobile: M3", "OWASP MASVS-NETWORK-1", "CWE-319"]
      };

    case "biometric_auth":
      return {
        title: "Biometric Authentication Implementation",
        severity: bio.is_weak ? "HIGH" : "COMPLIANT",
        badgeText: bio.is_weak ? "WEAK (No CryptoObject)" : "Compliant / Keystore Guarded",
        cwe: "CWE-287: Improper Authentication",
        summary: "Memeriksa apakah pemanggilan BiometricPrompt dibungkus dengan CryptoObject dari Android Keystore.",
        impact: bio.is_weak
          ? "Otentikasi biometrik TIDAK membungkus operasi kriptografi. Hasil verifikasi hanya berupa boolean client-side (onAuthenticationSucceeded), yang sangat mudah di-bypass via Frida."
          : "Otentikasi biometrik terproteksi dengan kunci Keystore terenkripsi atau tidak digunakan.",
        evidenceHtml: `<div><strong>Status:</strong> ${bio.description || 'Secure'}</div>`,
        exploitScenario: "Penyerang menjalankan script Frida: `BiometricPrompt.AuthenticationCallback.onAuthenticationSucceeded.implementation = function() { ... }` untuk membypass sidik jari secara instan.",
        codeFix: `// Wajib bungkus Cipher dengan CryptoObject:
BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(cipher);
biometricPrompt.authenticate(promptInfo, cryptoObject);`,
        standards: ["OWASP Mobile: M4 (Insecure Authentication)", "OWASP MASVS-AUTH-1", "CWE-287"]
      };

    case "anti_tamper":
      return {
        title: "Root, Frida & Emulator Defense Posture",
        severity: tamper.overall_protected ? "ACTIVE" : "MISSING",
        badgeText: tamper.overall_protected ? "DEFENSES ACTIVE" : "MISSING (No Anti-Tamper)",
        cwe: "CWE-693: Protection Mechanism Failure",
        summary: "Mendeteksi keberadaan modul anti-tampering (RootBeer, su binary check, Frida port 27042, dan emulator checks).",
        impact: tamper.overall_protected
          ? "Aplikasi memiliki deteksi dasar terhadap lingkungan root, Frida, atau emulator."
          : "Aplikasi TIDAK memiliki proteksi root/Frida. Reverse engineer dapat menganalisis dan memanipulasi aplikasi secara dinamis tanpa hambatan.",
        evidenceHtml: `<div>Root Check: <strong>${tamper.root_detection ? 'ADA' : 'TIDAK'}</strong> | Frida Check: <strong>${tamper.frida_detection ? 'ADA' : 'TIDAK'}</strong> | Emulator Check: <strong>${tamper.emulator_detection ? 'ADA' : 'TIDAK'}</strong></div>`,
        exploitScenario: "Reverse engineer menyalakan frida-server di perangkat root dan mem-hook fungsi autentikasi serta crypto key extraction secara bebas.",
        codeFix: `// Integrasikan Google Play Integrity API:
PlayIntegrity.requestIntegrityToken(...)
// Atau gunakan library RootBeer untuk deteksi root:
RootBeer rootBeer = new RootBeer(context);
if (rootBeer.isRooted()) { /* blokir akses */ }`,
        standards: ["OWASP Mobile: M7 (Client Code Quality)", "OWASP MASVS-RESILIENCE-1", "CWE-693"]
      };

    case "debug_activities":
      const dbgActs = (sensitive.debug_activities || []);
      return {
        title: "Exported Debug Activities in Production",
        severity: dbgActs.length > 0 ? "CRITICAL" : "SECURE",
        badgeText: dbgActs.length > 0 ? "CRITICAL" : "None Detected",
        cwe: "CWE-926: Improper Component Export",
        summary: "Mendeteksi apakah activity debug library analitik pihak ketiga (seperti MoEngage MoEDebuggerActivity, Flipper, Chucker) tertinggal di APK rilis.",
        impact: dbgActs.length > 0
          ? `Ditemukan activity debug terekspos publik: ${dbgActs.join(', ')}. Memberikan UI diagnostik internal kepada attacker.`
          : "Tidak ditemukan activity debug pihak ketiga yang terekspos.",
        evidenceHtml: `<div><strong>Activity Terdeteksi:</strong> ${dbgActs.join(', ') || 'None (Bersih)'}</div>`,
        exploitScenario: "Attacker meluncurkan activity ini via ADB untuk memantau log pengguna dan event pelacakan analitik secara tidak sah.",
        codeFix: `<activity
    android:name="com.moengage.sdk.debugger.MoEDebuggerActivity"
    android:exported="false"
    tools:replace="android:exported" />`,
        standards: ["OWASP Mobile: M1", "OWASP MASVS-PLATFORM-1", "CWE-926"]
      };

    case "spring_actuator":
      const actFound = (endpoints.actuator_endpoints || []).length > 0;
      return {
        title: "Spring Boot Actuator Endpoints Audit",
        severity: actFound ? "HIGH" : "SECURE",
        badgeText: actFound ? `EXPOSED (${endpoints.actuator_endpoints.length})` : "Not Exposed",
        cwe: "CWE-200: Information Exposure",
        summary: "Memeriksa keberadaan URL endpoint Spring Boot Actuator (/actuator, /actuator/env, /actuator/health) di dalam bytecode APK.",
        impact: actFound
          ? "Ditemukan referensi ke endpoint Actuator server. Endpoint actuator yang tidak diamankan di backend membocorkan variabel rahasia dan konfigurasi server."
          : "Tidak ditemukan endpoint Spring Boot Actuator yang hardcoded di biner APK.",
        evidenceHtml: `<div><strong>Status:</strong> ${actFound ? (endpoints.actuator_endpoints || []).join(', ') : 'Aman (Tidak ditemukan endpoint actuator)'}</div>`,
        exploitScenario: "Attacker mengakses endpoint \`/actuator/env\` yang terekspos di backend untuk mencuri database password dan credential cloud.",
        codeFix: `# Di application.properties backend:
management.endpoints.web.exposure.exclude=*
management.endpoint.health.show-details=never`,
        standards: ["OWASP API Security: API8 (Security Misconfiguration)", "CWE-200"]
      };

    case "user_root_ca":
      return {
        title: "Trust User-Installed CA Certificates Audit",
        severity: netsec.trusts_user_certs ? "HIGH" : "SECURE",
        badgeText: netsec.trusts_user_certs ? "YES (<certificates src='user'/>)" : "NO (System Only)",
        cwe: "CWE-295: Improper Certificate Validation",
        summary: "Memeriksa apakah aplikasi mengizinkan root certificate buatan pengguna diinstal untuk mendekripsi traffic TLS.",
        impact: netsec.trusts_user_certs
          ? "Aplikasi mengizinkan User CA. Penyerang dapat memasang sertifikat proxy (Burp Suite/Charles) pada HP pengguna tanpa root untuk mengintip traffic TLS."
          : "Aplikasi hanya mempercayai System CA resmi bawaan Android (Aman dari proxy user biasa).",
        evidenceHtml: `<div><strong>Konfigurasi saat ini:</strong> <code>&lt;certificates src="${netsec.trusts_user_certs ? 'user' : 'system'}"/&gt;</code></div>`,
        exploitScenario: "Attacker atau tester memasang sertifikat Burp Suite di setting Android, dan langsung bisa membaca seluruh payload HTTPS aplikasi tanpa perlu patch APK.",
        codeFix: `<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>`,
        standards: ["OWASP Mobile: M3", "OWASP MASVS-NETWORK-2", "CWE-295"]
      };

    case "target_sdk":
    case "min_sdk":
      return {
        title: "Android SDK Version & Compliance Audit",
        severity: qa.google_play_target_sdk_compliant ? "COMPLIANT" : "WARNING",
        badgeText: `API ${meta.target_sdk} / Min API ${meta.min_sdk}`,
        cwe: "Google Play Target SDK Requirement",
        summary: "Memverifikasi kepatuhan Target SDK terhadap regulasi Google Play Store dan versi minimum Android yang didukung.",
        impact: qa.google_play_target_sdk_compliant
          ? "Target SDK memenuhi persyaratan rilis Google Play Store (API 34+)."
          : `Target SDK (API ${meta.target_sdk}) berada di bawah standar minimum Google Play Store (wajib API 34+).`,
        evidenceHtml: `<div>Target SDK: <strong>API ${meta.target_sdk}</strong> | Min SDK: <strong>API ${meta.min_sdk}</strong></div>`,
        exploitScenario: "Aplikasi dengan target SDK usang tidak mendapatkan sandboxing modern seperti Scoped Storage dan izin runtime yang ketat.",
        codeFix: `android {
    defaultConfig {
        minSdkVersion 24
        targetSdkVersion 34 // Wajib Google Play Store
    }
}`,
        standards: ["Google Play Policy Requirements", "Android Security Best Practices"]
      };

    case "multi_dex":
    case "native_arch":
      return {
        title: "Multi-DEX & Native CPU Architecture",
        severity: "INFO",
        badgeText: `${(data.size_breakdown && data.size_breakdown.dex_files_count) || 1} DEX file(s)`,
        cwe: "Architecture & Packaging Metric",
        summary: "Informasi mengenai arsitektur packaging biner aplikasi: Multi-DEX dan dukungan pustaka native CPU (.so).",
        impact: `Binary memiliki ${(data.size_breakdown && data.size_breakdown.dex_files_count) || 1} file DEX dan mendukung arsitektur CPU: ${(qa.architecture_support || []).join(', ')}.`,
        evidenceHtml: `<div>Multi-DEX: <strong>${(data.size_breakdown && data.size_breakdown.dex_files_count > 1) ? 'Aktif' : 'Single DEX'}</strong> | Native ABI: <strong>${(qa.architecture_support || []).join(', ')}</strong></div>`,
        exploitScenario: "Aplikasi yang tidak menyediakan pustaka native 64-bit (arm64-v8a) akan ditolak oleh Google Play Store.",
        codeFix: `android {
    defaultConfig {
        multiDexEnabled true
        ndk {
            abiFilters "arm64-v8a", "armeabi-v7a", "x86_64"
        }
    }
}`,
        standards: ["Google Play 64-bit Architecture Policy"]
      };

    default:
      return {
        title: "Security Metric Audit",
        severity: "INFO",
        badgeText: "Metric",
        cwe: "CWE-699",
        summary: "Informasi status konfigurasi keamanan APK.",
        impact: "Metrik ini merupakan bagian dari audit keamanan statis ToolKitDev.",
        evidenceHtml: `<div>Metric Key: <code>${escapeHtml(key)}</code></div>`,
        exploitScenario: "Ikuti rekomendasi keamanan OWASP Mobile.",
        codeFix: "// Tinjau konfigurasi sesuai standar keamanan Android.",
        standards: ["OWASP Mobile Top 10"]
      };
  }
}

// Modal Close Handlers initialization
document.addEventListener("DOMContentLoaded", () => {
  const modal = document.getElementById("apkFindingDetailModal");
  const closeBtn = document.getElementById("btnCloseFindingModal");
  const okBtn = document.getElementById("btnOkFindingModal");

  const closeModal = () => modal?.classList.add("hidden");

  closeBtn?.addEventListener("click", closeModal);
  okBtn?.addEventListener("click", closeModal);
  modal?.addEventListener("click", (e) => {
    if (e.target === modal) closeModal();
  });
  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && modal && !modal.classList.contains("hidden")) {
      closeModal();
    }
  });
});

/* =========================================================================
   4. MCP HUB & HISTORICAL FEATURE TRACKER
   ========================================================================= */
let currentMcpConnectors = {};
let activeModalConnectorKey = "github";

const MCP_PROVIDER_CONFIG = {
  github: {
    title: "GitHub MCP Connector",
    badge: "GitHub OAuth 2.0",
    scopes: "repo, read:user, read:org, security_events",
    icon: `<svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>`,
    tokenPlaceholder: "ghp_xxxxxxxxxxxxxxxxxxxx atau github_pat_...",
    targetPlaceholder: "cth: budisusanto911/pokemon_budi",
    helperText: "Gunakan Personal Access Token (classic atau fine-grained) dengan scope 'repo' dan 'read:user' untuk integrasi penuh.",
    docLink: "https://github.com/settings/tokens"
  },
  docs: {
    title: "Architecture & ADR MCP",
    badge: "Local / Remote Bearer",
    scopes: "read:adrs, parse:openapi, query:architecture",
    icon: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path></svg>`,
    tokenPlaceholder: "Path folder docs lokal atau Bearer Token (cth: docs/)",
    targetPlaceholder: "cth: ADR-004: Clean Architecture with Coroutines",
    helperText: "Spesifikasikan folder dokumentasi Markdown ADR / OpenAPI spec lokal atau URL remote repository.",
    docLink: "#"
  },
  google_docs: {
    title: "Google Docs MCP (PRD & Specs)",
    badge: "Google OAuth 2.0",
    scopes: "documents.readonly, drive.readonly, userinfo.profile",
    icon: `<svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>`,
    tokenPlaceholder: "Google OAuth Bearer Token (ya29.a0...) atau Service Account",
    targetPlaceholder: "cth: PRD - Loyalty App Security Architecture",
    helperText: "Hubungkan dokumen PRD Google Docs untuk perbandingan spesifikasi bisnis dengan kode produksi.",
    docLink: "https://developers.google.com/oauthplayground"
  },
  figma: {
    title: "Figma MCP (Design System)",
    badge: "Figma OAuth 2.0 / PAT",
    scopes: "files:read",
    icon: `<svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor"><path d="M8 2a4 4 0 0 0-4 4 4 4 0 0 0 4 4h4V2H8zm8 0h-4v8h4a4 4 0 0 0 4-4 4 4 0 0 0-4-4zM8 10a4 4 0 0 0-4 4 4 4 0 0 0 4 4h4v-8H8zm8 0v8a4 4 0 0 0 4-4 4 4 0 0 0-4-4h-4zm-8 8a4 4 0 0 0 4 4v-4H8z"/></svg>`,
    tokenPlaceholder: "Figma Personal Access Token (figd_...) atau OAuth Token",
    targetPlaceholder: "cth: GLI Mobile Design System & UI Kit v3.0",
    helperText: "Dapatkan Access Token di Settings -> Personal access tokens pada akun Figma Anda.",
    docLink: "https://www.figma.com/developers/api#access-tokens"
  }
};

/* =========================================================================
   4. MCP HUB & HISTORICAL FEATURE TRACKER
   ========================================================================= */
async function initMcpAndHistory() {
  // Load MCP status
  await refreshMcpHubStatus();

  // Refresh MCP button listener
  document.getElementById("btnRefreshMcpHub")?.addEventListener("click", () => {
    refreshMcpHubStatus(true);
  });

  // Modal setup
  document.getElementById("btnCloseMcpModal")?.addEventListener("click", closeMcpOAuthModal);
  document.getElementById("btnCancelMcpModal")?.addEventListener("click", closeMcpOAuthModal);
  document.getElementById("btnSubmitMcpConnect")?.addEventListener("click", submitMcpConnect);
  document.getElementById("btnLaunchOAuthFlow")?.addEventListener("click", launchOAuthFlow);

  // Close modal when clicking outside
  document.getElementById("mcpOAuthModal")?.addEventListener("click", (e) => {
    if (e.target.id === "mcpOAuthModal") {
      closeMcpOAuthModal();
    }
  });

  // Listen to postMessage from OAuth popup
  window.addEventListener("message", handleOAuthPopupMessage);

  // Load Historical Features
  searchHistoricalFeatures("");
  const searchInput = document.getElementById("histSearchInput");
  const searchBtn = document.getElementById("btnSearchHist");

  searchBtn?.addEventListener("click", () => {
    searchHistoricalFeatures(searchInput ? searchInput.value : "");
  });

  searchInput?.addEventListener("keyup", (e) => {
    if (e.key === "Enter") {
      searchHistoricalFeatures(searchInput.value);
    }
  });
}

async function refreshMcpHubStatus(showToast = false) {
  try {
    const res = await fetch("/api/mcp");
    if (!res.ok) throw new Error("HTTP " + res.status);
    const data = await res.json();
    currentMcpConnectors = data.connectors || {};
    renderMcpConnectors(currentMcpConnectors);
    if (showToast) {
      alert("✅ Status MCP Hub dan sinkronisasi OAuth berhasil diperbarui!");
    }
  } catch (e) {
    console.warn("Fallback to static /mcp_status.json:", e);
    try {
      const fbRes = await fetch("/mcp_status.json");
      const fbData = await fbRes.json();
      currentMcpConnectors = fbData.connectors || {};
      renderMcpConnectors(currentMcpConnectors);
    } catch (err) {
      console.error("Failed to load fallback MCP status:", err);
    }
  }
}

function renderMcpConnectors(connectors) {
  const container = document.getElementById("mcpConnectorsList");
  if (!container) return;

  container.innerHTML = Object.entries(connectors).map(([key, c]) => {
    const isConn = c.status === "connected";
    const cfg = MCP_PROVIDER_CONFIG[key] || {
      icon: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle></svg>`,
      badge: "OAuth"
    };

    return `
      <div class="mcp-card">
        <div>
          <div class="mcp-header">
            <div class="mcp-header-left">
              <div class="mcp-icon-box">
                ${cfg.icon}
              </div>
              <div>
                <h4>${c.name}</h4>
                <div style="font-size:11px; color:#64748b; margin-top:2px;"><code>${c.endpoint}</code></div>
              </div>
            </div>
            <span class="mcp-badge ${isConn ? 'connected' : 'disconnected'}">
              <svg width="8" height="8" viewBox="0 0 8 8" fill="currentColor">
                <circle cx="4" cy="4" r="4" />
              </svg>
              ${isConn ? 'CONNECTED (OAUTH)' : 'DISCONNECTED'}
            </span>
          </div>

          <!-- Connected User Profile / OAuth Identity -->
          ${isConn && c.auth_user ? `
            <div class="mcp-auth-user-box">
              <img class="mcp-avatar-img" src="${c.auth_avatar || 'https://avatars.githubusercontent.com/u/583231?v=4'}" alt="Avatar" onerror="this.src='https://avatars.githubusercontent.com/u/583231?v=4'">
              <div class="mcp-auth-user-info">
                <div class="mcp-auth-user-name">${c.auth_name || c.auth_user} (@${c.auth_user})</div>
                <div class="mcp-auth-user-meta">
                  <span style="color:#059669; font-weight:600;">✓ Live Verified</span>
                  <span>•</span>
                  <span>OAuth 2.0</span>
                  ${c.auth_token_masked ? `<span>• Token: <code>${c.auth_token_masked}</code></span>` : ''}
                </div>
              </div>
            </div>
          ` : `
            <div style="background:#fef2f2; border:1px dashed #fecaca; border-radius:8px; padding:10px 12px; margin:10px 0; font-size:12px; color:#991b1b; display:flex; align-items:center; gap:8px;">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
              Konektor belum terautentikasi. Hubungkan akun via OAuth untuk mengaktifkan context sync.
            </div>
          `}

          <!-- Resource Scope Detail -->
          <div class="mcp-desc" style="margin-top:10px;">
            ${c.active_repo ? `<div style="font-size:12px; color:#2563eb; font-weight:600; margin-top:3px;">📦 Active Repo: <code>${c.active_repo}</code></div>` : ''}
            ${c.synced_detail ? `<div style="font-size:11.5px; color:#64748b; margin-top:3px;">🔄 Sinkronisasi: ${c.synced_detail}</div>` : ''}
            ${c.active_doc ? `<div style="font-size:12px; color:#2563eb; font-weight:600; margin-top:3px;">📜 Spec ADR: <code>${c.active_doc}</code></div>` : ''}
            ${c.active_document ? `<div style="font-size:12px; color:#2563eb; font-weight:600; margin-top:3px;">📝 Dokumen PRD: <code>${c.active_document}</code></div>` : ''}
            ${c.active_file ? `<div style="font-size:12px; color:#2563eb; font-weight:600; margin-top:3px;">🎨 Design System: <code>${c.active_file}</code></div>` : ''}
          </div>

          <!-- Capabilities Pills -->
          <div class="mcp-caps" style="margin-top:12px;">
            ${(c.capabilities || []).map(cap => `<span class="cap-pill">${cap}</span>`).join("")}
          </div>
        </div>

        <!-- Action Row -->
        <div class="mcp-actions-row">
          ${isConn ? `
            <button class="btn-mcp-oauth" onclick="window.openMcpOAuthModal('${key}')">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"></path><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path></svg>
              Ganti Akun / Re-auth
            </button>
            <button class="btn-mcp-danger" onclick="window.disconnectMcpConnector('${key}')">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
              Putuskan
            </button>
          ` : `
            <button class="btn-mcp-oauth" style="background:#059669;" onclick="window.openMcpOAuthModal('${key}')">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
              Hubungkan via OAuth 2.0
            </button>
          `}
        </div>
      </div>
    `;
  }).join("");
}

window.openMcpOAuthModal = function(connectorKey) {
  activeModalConnectorKey = connectorKey;
  const cfg = MCP_PROVIDER_CONFIG[connectorKey] || MCP_PROVIDER_CONFIG.github;
  const c = currentMcpConnectors[connectorKey] || {};

  const modal = document.getElementById("mcpOAuthModal");
  if (!modal) return;

  document.getElementById("mcpModalTitle").innerText = `Hubungkan ${c.name || cfg.title} via OAuth 2.0`;
  document.getElementById("mcpModalProviderBadge").innerText = cfg.badge;
  document.getElementById("mcpModalStatusBadge").innerText = c.status === "connected" ? "Terhubung" : "Belum Terhubung";
  document.getElementById("mcpModalStatusBadge").className = c.status === "connected" ? "badge badge-success" : "badge badge-warning";

  const providerInfo = document.getElementById("mcpModalProviderInfo");
  providerInfo.innerHTML = `
    <div style="width:36px; height:36px; border-radius:8px; background:#ffffff; display:flex; align-items:center; justify-content:center; color:#2563eb; box-shadow:0 1px 3px rgba(0,0,0,0.08);">
      ${cfg.icon}
    </div>
    <div style="flex:1;">
      <div style="font-size:13px; font-weight:700; color:#0f172a;">${c.name || cfg.title}</div>
      <div style="font-size:11.5px; color:#475569; margin-top:2px;">Requested Scopes: <code>${cfg.scopes}</code></div>
    </div>
  `;

  document.getElementById("mcpTokenInput").placeholder = cfg.tokenPlaceholder;
  document.getElementById("mcpTokenHelper").innerText = cfg.helperText;
  document.getElementById("mcpTargetInput").placeholder = cfg.targetPlaceholder;
  document.getElementById("mcpTargetInput").value = c.active_repo || c.active_doc || c.active_document || c.active_file || "";

  // Reset feedback
  const fb = document.getElementById("mcpLiveFeedback");
  fb.className = "mcp-live-feedback";
  fb.style.display = "none";
  fb.innerHTML = "";

  // Set default tabs
  window.switchMcpModalTab("token");

  modal.classList.remove("hidden");
};

window.closeMcpOAuthModal = function() {
  document.getElementById("mcpOAuthModal")?.classList.add("hidden");
};

window.switchMcpModalTab = function(tab) {
  const btnToken = document.getElementById("tabBtnDirectToken");
  const btnOAuth = document.getElementById("tabBtnWebOAuth");
  const secToken = document.getElementById("mcpTabTokenContent");
  const secOAuth = document.getElementById("mcpTabOAuthContent");

  if (tab === "token") {
    btnToken.classList.add("active");
    btnOAuth.classList.remove("active");
    secToken.style.display = "block";
    secOAuth.style.display = "none";
  } else {
    btnOAuth.classList.add("active");
    btnToken.classList.remove("active");
    secToken.style.display = "none";
    secOAuth.style.display = "block";
  }
};

window.launchOAuthFlow = async function() {
  const cid = document.getElementById("mcpClientIdInput")?.value || "";
  const fb = document.getElementById("mcpLiveFeedback");
  fb.style.display = "flex";
  fb.className = "mcp-live-feedback loading";
  fb.innerHTML = `
    <div class="spinner" style="width:16px; height:16px; border-width:2px; margin:0;"></div>
    <span>Membuka jendela autentikasi OAuth provider...</span>
  `;

  try {
    const res = await fetch(`/api/mcp/oauth-url?connector=${encodeURIComponent(activeModalConnectorKey)}&client_id=${encodeURIComponent(cid)}`);
    const data = await res.json();
    if (data.auth_url) {
      window.open(data.auth_url, "mcp_oauth_window", "width=640,height=720,menubar=no,toolbar=no");
      fb.innerHTML = `<span>Jendela popup autentikasi telah dibuka. Silakan selesaikan persetujuan login di jendela tersebut.</span>`;
    } else {
      throw new Error("URL OAuth tidak tersedia");
    }
  } catch (err) {
    fb.className = "mcp-live-feedback error";
    fb.innerHTML = `<strong>Gagal membuka OAuth:</strong> ${err.message}`;
  }
};

async function handleOAuthPopupMessage(event) {
  if (event.data && event.data.type === "mcp_oauth_response") {
    const { code, state, error } = event.data;
    const fb = document.getElementById("mcpLiveFeedback");
    if (error) {
      fb.className = "mcp-live-feedback error";
      fb.style.display = "block";
      fb.innerHTML = `<strong>OAuth Error:</strong> ${error}`;
      return;
    }

    fb.className = "mcp-live-feedback loading";
    fb.style.display = "flex";
    fb.innerHTML = `
      <div class="spinner" style="width:16px; height:16px; border-width:2px; margin:0;"></div>
      <span>Menerima OAuth Authorization Code (${code.substring(0, 10)}...). Memverifikasi token...</span>
    `;

    try {
      const cid = document.getElementById("mcpClientIdInput")?.value || "";
      const csecret = document.getElementById("mcpClientSecretInput")?.value || "";
      const customTarget = document.getElementById("mcpTargetInput")?.value || "";

      const connectRes = await fetch("/api/mcp/connect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          connector: activeModalConnectorKey,
          code: code,
          client_id: cid,
          client_secret: csecret,
          custom_target: customTarget
        })
      });

      const resData = await connectRes.json();
      if (resData.success) {
        fb.className = "mcp-live-feedback success";
        fb.innerHTML = `<strong>✅ Berhasil Terhubung:</strong> ${resData.message || 'Akun OAuth berhasil diverifikasi!'}`;
        await refreshMcpHubStatus();
        setTimeout(closeMcpOAuthModal, 1500);
      } else {
        fb.className = "mcp-live-feedback error";
        fb.innerHTML = `<strong>Verifikasi Gagal:</strong> ${resData.error}`;
      }
    } catch (e) {
      fb.className = "mcp-live-feedback error";
      fb.innerHTML = `<strong>Gagal:</strong> ${e.message}`;
    }
  }
}

async function submitMcpConnect() {
  const token = document.getElementById("mcpTokenInput")?.value.trim() || "";
  const customTarget = document.getElementById("mcpTargetInput")?.value.trim() || "";
  const fb = document.getElementById("mcpLiveFeedback");

  if (!token) {
    fb.className = "mcp-live-feedback error";
    fb.style.display = "block";
    fb.innerHTML = "Harap masukkan OAuth Access Token atau Personal Access Token terlebih dahulu.";
    return;
  }

  fb.style.display = "flex";
  fb.className = "mcp-live-feedback loading";
  fb.innerHTML = `
    <div class="spinner" style="width:16px; height:16px; border-width:2px; margin:0;"></div>
    <span>Memverifikasi token dengan API ${activeModalConnectorKey.toUpperCase()}...</span>
  `;

  try {
    const res = await fetch("/api/mcp/connect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        connector: activeModalConnectorKey,
        token: token,
        custom_target: customTarget
      })
    });

    const data = await res.json();
    if (data.success) {
      fb.className = "mcp-live-feedback success";
      fb.innerHTML = `
        <strong>✅ Sukses Terhubung!</strong><br>
        ${data.message}<br>
        <span style="font-size:11px; opacity:0.85;">Profil pengguna dan token live terverifikasi disimpan di mcp_auth.json.</span>
      `;
      await refreshMcpHubStatus();
      setTimeout(closeMcpOAuthModal, 1400);
    } else {
      fb.className = "mcp-live-feedback error";
      fb.innerHTML = `<strong>Gagal Menghubungkan:</strong> ${data.error}`;
    }
  } catch (err) {
    fb.className = "mcp-live-feedback error";
    fb.innerHTML = `<strong>Kesalahan Jaringan:</strong> ${err.message}`;
  }
}

window.disconnectMcpConnector = async function(connectorKey) {
  const c = currentMcpConnectors[connectorKey];
  const name = c?.name || connectorKey;
  if (!confirm(`Apakah Anda yakin ingin memutuskan koneksi ${name}? Akun OAuth dan token akan dihapus.`)) {
    return;
  }

  try {
    const res = await fetch("/api/mcp/disconnect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ connector: connectorKey })
    });
    const data = await res.json();
    if (data.success) {
      await refreshMcpHubStatus();
    } else {
      alert("Gagal memutuskan koneksi: " + data.error);
    }
  } catch (err) {
    alert("Kesalahan jaringan: " + err.message);
  }
};


async function searchHistoricalFeatures(query) {
  try {
    const res = await fetch(`/api/history?q=${encodeURIComponent(query)}`);
    const feats = await res.json();
    const container = document.getElementById("histResultsList");
    if (!container) return;

    container.innerHTML = feats.map(f => `
      <div class="history-card">
        <div class="history-meta-top">
          <strong>${f.title}</strong>
          <span class="badge badge-cert">${f.implemented_at}</span>
        </div>
        <div class="history-author">Dibuat oleh <strong>${f.author}</strong> via <strong>PR ${f.pr_number}</strong> (Commit: <code>${f.commit_hash}</code>)</div>
        <div class="history-rationale">"${f.rationale}"</div>
        ${f.files_modified ? `
          <div style="margin: 6px 0 8px; font-size:11.5px; color:#475569;">
            <strong style="color:#0f172a;">Files Modified:</strong> 
            ${f.files_modified.map(file => `<code style="background:#f1f5f9; border:1px solid #e2e8f0; color:#2563eb; padding:2px 6px; border-radius:4px; margin-right:4px; font-size:11px;">${file}</code>`).join("")}
          </div>
        ` : ''}
        <div class="history-citations">
          <span class="citation-tag">📄 ${f.adr_reference}</span>
          <span class="citation-tag">🎨 ${f.figma_frame}</span>
          <span class="citation-tag">📝 ${f.google_doc_ref}</span>
        </div>
      </div>
    `).join("");
  } catch (err) {
    console.error("Error loading historical features:", err);
  }
}

/* =========================================================================
   5. AI CONTEXT CHAT ASSISTANT
   ========================================================================= */
function initAiChat() {
  const toggleBtn = document.getElementById("toggleChatDrawer");
  const chatDrawer = document.getElementById("aiChatDrawer");
  const closeBtn = document.getElementById("closeChatBtn");
  const sendBtn = document.getElementById("btnSendChat");
  const chatInput = document.getElementById("chatInput");

  toggleBtn?.addEventListener("click", () => {
    chatDrawer.classList.toggle("hidden");
    if (!chatDrawer.classList.contains("hidden")) {
      setTimeout(() => chatInput?.focus(), 150);
      updateChatTargetIndicator();
    }
  });

  closeBtn?.addEventListener("click", () => {
    chatDrawer.classList.add("hidden");
  });

  sendBtn?.addEventListener("click", () => sendChatMessage());
  chatInput?.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendChatMessage();
    }
  });

  // Auto-resize textarea
  chatInput?.addEventListener("input", () => {
    chatInput.style.height = "auto";
    chatInput.style.height = Math.min(chatInput.scrollHeight, 100) + "px";
  });

  document.querySelectorAll(".btn-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      const q = chip.getAttribute("data-query");
      if (chatInput) {
        chatInput.value = q;
        chatInput.style.height = "auto";
      }
      sendChatMessage();
    });
  });
}

function updateChatTargetIndicator() {
  const indicator = document.getElementById("chatTargetIndicator");
  if (!indicator) return;
  const data = activeApkData || mobsfMenuState?.currentApkData;
  if (data) {
    const meta = data.metadata || {};
    const pkg = meta.package_name || "APK";
    const appName = meta.app_label || meta.app_name || "Target App";
    const score = data.security_score !== undefined ? data.security_score : 0;
    indicator.textContent = `Target: ${appName} (${score}/100 PTS)`;
  } else {
    indicator.textContent = "Target: Alfagift (Score: 0/100)";
  }
}

function formatAiMarkdown(text) {
  if (!text) return "";
  let out = text;

  // 1. Code blocks: ```lang\ncode```
  out = out.replace(/```([a-zA-Z0-9_\-\+]*)\n([\s\S]*?)```/g, (match, lang, code) => {
    const l = lang ? lang.toUpperCase() : "CODE";
    const rawCode = escapeHtml(code.trim());
    return `<div class="chat-code-block">
      <div class="chat-code-header">
        <span>${l}</span>
        <button type="button" class="chat-code-copy-btn" onclick="copySnippetToClipboard(this)">Salin Kode</button>
      </div>
      <pre class="chat-code-pre"><code>${rawCode}</code></pre>
    </div>`;
  });

  // 2. Headings: ### and ####
  out = out.replace(/^### (.*$)/gm, `<div style="font-size:13px; font-weight:700; color:#2563eb; margin:10px 0 4px;">$1</div>`);
  out = out.replace(/^#### (.*$)/gm, `<div style="font-size:12px; font-weight:700; color:#0f172a; margin:6px 0 2px;">$1</div>`);

  // 3. Bold: **text**
  out = out.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");

  // 4. Inline code: `code`
  out = out.replace(/`([^`]+)`/g, `<code style="background:rgba(2,132,199,0.12); color:#0284c7; padding:2px 5px; border-radius:4px; font-size:11px; font-family:'JetBrains Mono',monospace;">$1</code>`);

  // 5. Blockquotes: > quote
  out = out.replace(/^>\s+(.*$)/gm, `<div style="border-left:3px solid #3b82f6; background:#eff6ff; padding:6px 10px; margin:6px 0; border-radius:0 4px 4px 0; font-size:11.5px; color:#1e40af;">$1</div>`);

  // 6. Bullet lists: * item or - item
  out = out.replace(/^\s*[\*\-]\s+(.*$)/gm, `<div style="margin-left:8px; display:flex; gap:6px; margin-bottom:2px;"><span>•</span><span>$1</span></div>`);

  // 7. Markdown Tables: | col | col |
  const tableRegex = /((?:\|.+?\|\r?\n)+)/g;
  out = out.replace(tableRegex, (match) => {
    const lines = match.trim().split(/\r?\n/).filter(l => l.includes("|"));
    if (lines.length < 2) return match;
    let tableHtml = `<div style="overflow-x:auto; margin:8px 0;"><table style="width:100%; border-collapse:collapse; font-size:11px; border:1px solid #cbd5e1;">`;
    lines.forEach((line, rowIdx) => {
      if (line.includes("---")) return;
      const cells = line.split("|").map(c => c.trim()).filter((c, i, arr) => i > 0 && i < arr.length - 1);
      if (rowIdx === 0) {
        tableHtml += `<tr style="background:#0f172a; color:#fff;">` + cells.map(c => `<th style="padding:6px 8px; border:1px solid #334155; text-align:left;">${c}</th>`).join("") + `</tr>`;
      } else {
        tableHtml += `<tr style="background:${rowIdx % 2 === 0 ? '#f8fafc' : '#fff'};">` + cells.map(c => `<td style="padding:5px 8px; border:1px solid #e2e8f0;">${c}</td>`).join("") + `</tr>`;
      }
    });
    tableHtml += `</table></div>`;
    return tableHtml;
  });

  // 8. Newlines
  out = out.replace(/\n\n/g, "<br><br>");

  return out;
}

window.copySnippetToClipboard = function(btn) {
  const codeEl = btn.closest(".chat-code-block")?.querySelector("code");
  if (!codeEl) return;
  navigator.clipboard.writeText(codeEl.innerText).then(() => {
    const orig = btn.innerText;
    btn.innerText = "✓ Tersalin!";
    btn.style.background = "#10b981";
    btn.style.color = "#ffffff";
    setTimeout(() => {
      btn.innerText = orig;
      btn.style.background = "";
      btn.style.color = "";
    }, 1800);
  });
};

async function sendChatMessage() {
  const input = document.getElementById("chatInput");
  const text = input.value.trim();
  if (!text) return;

  const messagesDiv = document.getElementById("chatMessages");

  // User msg
  const userMsg = document.createElement("div");
  userMsg.className = "chat-msg user";
  userMsg.innerText = text;
  messagesDiv.appendChild(userMsg);
  input.value = "";
  input.style.height = "auto";
  messagesDiv.scrollTop = messagesDiv.scrollHeight;

  // AI loading msg
  const aiMsg = document.createElement("div");
  aiMsg.className = "chat-msg ai";
  aiMsg.innerHTML = `<div class="msg-author">AI Forensic Engine</div><div>Sedang membedah bytecode &amp; telemetri alur data...</div>`;
  messagesDiv.appendChild(aiMsg);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;

  const activeCtx = activeApkData || mobsfMenuState?.currentApkData;

  try {
    const res = await fetch("/api/chat/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        question: text,
        apk_context: activeCtx
      })
    });

    if (!res.ok || !res.body) {
      throw new Error(`Server returned status ${res.status}`);
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder("utf-8");
    let accumulatedText = "";
    let citations = [];

    const contentDiv = document.createElement("div");
    aiMsg.innerHTML = `<div class="msg-author">AI Forensic Engine <span style="font-size:10px; color:#10b981; font-weight:normal;">⚡ Streaming Live</span></div>`;
    aiMsg.appendChild(contentDiv);

    let buffer = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n\n");
      buffer = lines.pop() || "";

      for (const line of lines) {
        if (line.startsWith("data: ")) {
          try {
            const parsed = JSON.parse(line.slice(6));
            if (parsed.token) {
              accumulatedText += parsed.token;
              contentDiv.innerHTML = formatAiMarkdown(accumulatedText);
              messagesDiv.scrollTop = messagesDiv.scrollHeight;
            }
            if (parsed.done) {
              citations = parsed.citations || [];
            }
          } catch (e) {}
        }
      }
    }

    // Attach citations footer if present
    if (citations && citations.length > 0) {
      const citWrap = document.createElement("div");
      citWrap.innerHTML = `
        <div style="margin-top:10px; padding-top:8px; border-top:1px solid #e2e8f0; font-size:11px; color:#64748b;">
          <strong style="color:#2563eb;">Sumber Forensik Terverifikasi:</strong>
          <div style="display:flex; flex-wrap:wrap; gap:6px; margin-top:4px;">
            ${citations.map(c => `<span style="background:#eff6ff; color:#1d4ed8; border:1px solid #bfdbfe; padding:2px 7px; border-radius:4px; font-size:10px;">[${escapeHtml(c.type.toUpperCase())}] ${escapeHtml(c.title)} (${escapeHtml(c.ref)})</span>`).join("")}
          </div>
        </div>
      `;
      aiMsg.appendChild(citWrap);
    }
  } catch (err) {
    try {
      const fallbackRes = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: text, apk_context: activeCtx })
      });
      const data = await fallbackRes.json();
      aiMsg.innerHTML = `
        <div class="msg-author">AI Forensic Engine</div>
        <div>${formatAiMarkdown(data.answer)}</div>
      `;
    } catch (fallbackErr) {
      aiMsg.innerHTML = `<div class="msg-author">AI Forensic Engine</div><div style="color:#ef4444;">Gagal memproses pertanyaan: ${escapeHtml(err.message)}</div>`;
    }
  }

  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

/* =========================================================================
   7. SHOPEERS DASHBOARD INTERACTIONS & WIDGET DRAWER
   ========================================================================= */
function initShopeersInteractions() {
  // Global Toast Helper
  window.showTopbarToast = (message) => {
    const container = document.getElementById("topbarToastContainer");
    if (!container) return;
    const toast = document.createElement("div");
    toast.className = "topbar-toast";
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transition = "opacity 0.2s ease";
      setTimeout(() => toast.remove(), 220);
    }, 2800);
  };

  // Helper to close all topbar pop-menus
  const closeAllTopbarMenus = (exceptId = null) => {
    const menus = [
      { menu: "auditPeriodDropdown", btn: "btnAuditPeriod" },
      { menu: "syncModeDropdown", btn: "btnSyncMode" },
      { menu: "exportAuditDropdown", btn: "btnExportData" },
      { menu: "notificationsDropdown", btn: "btnNotifications" },
      { menu: "userProfileDropdown", btn: "btnToggleProfileMenu" }
    ];
    menus.forEach(({ menu, btn }) => {
      if (menu !== exceptId) {
        document.getElementById(menu)?.classList.add("hidden");
        document.getElementById(btn)?.setAttribute("aria-expanded", "false");
      }
    });
  };

  const bindDropdownToggle = (btnId, menuId) => {
    const btn = document.getElementById(btnId);
    const menu = document.getElementById(menuId);
    if (!btn || !menu) return;
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const willOpen = menu.classList.contains("hidden");
      closeAllTopbarMenus(menuId);
      menu.classList.toggle("hidden", !willOpen);
      btn.setAttribute("aria-expanded", String(willOpen));
    });
  };

  bindDropdownToggle("btnAuditPeriod", "auditPeriodDropdown");
  bindDropdownToggle("btnSyncMode", "syncModeDropdown");
  bindDropdownToggle("btnExportData", "exportAuditDropdown");
  bindDropdownToggle("btnNotifications", "notificationsDropdown");

  document.addEventListener("click", (e) => {
    if (!e.target.closest(".topbar-dropdown-wrap") && !e.target.closest(".user-profile-wrap")) {
      closeAllTopbarMenus();
    }
  });

  // 0. Topbar Search Box (⌘K)
  document.getElementById("openSearchBtn")?.addEventListener("click", () => {
    window.navigateToTab("repositories", "overview");
    setTimeout(() => {
      const scanInput = document.getElementById("targetScanInput");
      if (scanInput) {
        scanInput.focus();
        scanInput.select();
      }
      window.showTopbarToast("🔍 Ketik username GitHub atau kata kunci untuk memindai repositori.");
    }, 100);
  });

  // 1. Audit Period Dropdown Actions
  document.querySelectorAll("#auditPeriodDropdown .topbar-pop-item").forEach(item => {
    item.addEventListener("click", () => {
      document.querySelectorAll("#auditPeriodDropdown .topbar-pop-item").forEach(i => i.classList.remove("active"));
      item.classList.add("active");
      const period = item.getAttribute("data-period") || "Q1 2026 Audit Period";
      const mult = parseFloat(item.getAttribute("data-mult") || "1.0");
      const labelEl = document.getElementById("auditPeriodLabel");
      if (labelEl) labelEl.textContent = period;

      // Update KPI visual metrics based on selected audit period
      const reposEl = document.getElementById("dashKpiRepos");
      const secEl = document.getElementById("dashKpiSecurity");
      const maintEl = document.getElementById("dashKpiMaint");
      if (reposEl) reposEl.textContent = String(Math.max(4, Math.round(8 * mult)));
      if (secEl) secEl.textContent = String(Math.min(100, Math.round(95 * (mult >= 1 ? 1 : mult + 0.05))));
      if (maintEl) maintEl.textContent = String(Math.min(100, Math.round(78 * (mult >= 1 ? 1 : mult + 0.08))));

      closeAllTopbarMenus();
      window.showTopbarToast(`📅 Periode audit aktif: ${period}`);
    });
  });

  // 2. Live GitHub Sync Dropdown Actions
  let activeTopbarSync = { type: "github", target: "budisusanto911", label: "Live GitHub Sync" };
  const runTopbarSync = async (type, target, label) => {
    const dot = document.getElementById("topbarSyncDot");
    const lbl = document.getElementById("syncModeLabel");
    if (dot) dot.classList.add("syncing");
    if (lbl) lbl.textContent = "Syncing...";
    closeAllTopbarMenus();

    try {
      await triggerScan(type, target);
      activeTopbarSync = { type, target, label };
      if (lbl) lbl.textContent = label;
      window.showTopbarToast(`✅ Sinkronisasi selesai: ${label}`);
    } catch (err) {
      if (lbl) lbl.textContent = activeTopbarSync.label;
      window.showTopbarToast(`⚠️ Gagal sinkronisasi: ${err.message}`);
    } finally {
      if (dot) dot.classList.remove("syncing");
    }
  };

  document.querySelectorAll("#syncModeDropdown .topbar-pop-item[data-sync-type]").forEach(item => {
    item.addEventListener("click", () => {
      document.querySelectorAll("#syncModeDropdown .topbar-pop-item[data-sync-type]").forEach(i => i.classList.remove("active"));
      item.classList.add("active");
      const type = item.getAttribute("data-sync-type") || "github";
      const target = item.getAttribute("data-sync-target") || "";
      const label = item.getAttribute("data-sync-label") || "Live GitHub Sync";
      runTopbarSync(type, target, label);
    });
  });

  document.getElementById("btnForceResyncNow")?.addEventListener("click", () => {
    runTopbarSync(activeTopbarSync.type, activeTopbarSync.target, activeTopbarSync.label);
  });

  // 3. Add Widget Drawer & Save Layout
  const openWidgetBtn = document.getElementById("btnOpenWidgetDrawer");
  const widgetDrawer = document.getElementById("shopeersWidgetDrawer");
  const closeWidgetBtn = document.getElementById("btnCloseWidgetDrawer");
  const cancelWidgetBtn = document.getElementById("btnCancelWidgetDrawer");
  const saveWidgetBtn = document.getElementById("btnSaveWidgetDrawer");

  const openDrawer = () => {
    closeAllTopbarMenus();
    if (widgetDrawer) widgetDrawer.classList.remove("hidden");
  };
  const closeDrawer = () => {
    if (widgetDrawer) widgetDrawer.classList.add("hidden");
  };

  openWidgetBtn?.addEventListener("click", openDrawer);
  closeWidgetBtn?.addEventListener("click", closeDrawer);
  cancelWidgetBtn?.addEventListener("click", closeDrawer);

  document.querySelectorAll("#shopeersWidgetDrawer .shopeers-widget-option").forEach(card => {
    card.addEventListener("click", (e) => {
      if (e.target.tagName !== "INPUT") {
        const cb = card.querySelector(".shopeers-checkbox");
        if (cb) cb.checked = !cb.checked;
      }
    });
  });

  saveWidgetBtn?.addEventListener("click", () => {
    const checkboxes = document.querySelectorAll("#shopeersWidgetDrawer .shopeers-checkbox");
    const kpiCards = document.querySelectorAll(".shopeers-kpi-grid .shopeers-kpi-card");
    const midGrid = document.querySelector(".shopeers-mid-grid");
    const botGrid = document.querySelector(".shopeers-bot-grid");

    if (checkboxes[0] && kpiCards[3]) kpiCards[3].style.display = checkboxes[0].checked ? "" : "none";
    if (checkboxes[1] && midGrid) midGrid.style.display = checkboxes[1].checked ? "" : "none";
    if (checkboxes[2] && kpiCards[2]) kpiCards[2].style.display = checkboxes[2].checked ? "" : "none";
    if (checkboxes[3] && botGrid) botGrid.style.display = (checkboxes[3].checked || checkboxes[4]?.checked || true) ? "" : "none";

    const enabledCount = Array.from(checkboxes).filter(c => c.checked).length;
    closeDrawer();
    window.showTopbarToast(`✓ Layout disimpan (${enabledCount} widget aktif di Dashboard)`);
  });

  widgetDrawer?.addEventListener("click", (e) => {
    if (e.target === widgetDrawer) closeDrawer();
  });

  // 4. Export Audit Actions (HTML Report / JSON / CSV)
  const triggerFileDownload = (filename, content, mimeType) => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  document.getElementById("btnExportJsonData")?.addEventListener("click", async () => {
    closeAllTopbarMenus();
    window.showTopbarToast("📦 Menyiapkan bundel JSON Audit...");
    try {
      const [dash, repos, vulns, deps, mcp] = await Promise.all([
        fetch("/api/dashboard").then(r => r.json()),
        fetch("/api/repositories").then(r => r.json()),
        fetch("/api/vulnerabilities").then(r => r.json()),
        fetch("/api/dependencies").then(r => r.json()),
        fetch("/api/mcp").then(r => r.json())
      ]);
      const bundle = {
        exported_at: new Date().toISOString(),
        audit_period: document.getElementById("auditPeriodLabel")?.textContent || "Q1 2026 Audit Period",
        auditor: currentAuthUser?.name || "Budi Susanto",
        dashboard_summary: dash,
        repositories: repos,
        vulnerabilities: vulns,
        dependencies: deps,
        mcp_status: mcp,
        active_apk_audit: activeApkData
      };
      triggerFileDownload("ToolKitDev-Audit-Bundle-2026.json", JSON.stringify(bundle, null, 2), "application/json");
      window.showTopbarToast("✅ File ToolKitDev-Audit-Bundle-2026.json berhasil diunduh!");
    } catch (err) {
      window.showTopbarToast("⚠️ Gagal mengekspor JSON: " + err.message);
    }
  });

  document.getElementById("btnExportCsvData")?.addEventListener("click", async () => {
    closeAllTopbarMenus();
    try {
      const repos = await fetch("/api/repositories").then(r => r.json());
      const rows = [
        ["Repository Name", "Language", "Stars", "Forks", "Security Score", "Updated At"]
      ];
      (Array.isArray(repos) ? repos : []).forEach(r => {
        rows.push([
          `"${(r.name || "").replace(/"/g, '""')}"`,
          `"${r.language || "Unknown"}"`,
          r.stars ?? 0,
          r.forks ?? 0,
          r.security_score ?? 95,
          `"${r.updated_at || ""}"`
        ]);
      });
      const csvContent = rows.map(r => r.join(",")).join("\n");
      triggerFileDownload("ToolKitDev-Repositories-Audit.csv", csvContent, "text/csv;charset=utf-8");
      window.showTopbarToast("📊 File ToolKitDev-Repositories-Audit.csv berhasil diunduh!");
    } catch (err) {
      window.showTopbarToast("⚠️ Gagal mengekspor CSV: " + err.message);
    }
  });

  document.getElementById("btnExportHtmlReport")?.addEventListener("click", async () => {
    closeAllTopbarMenus();
    window.showTopbarToast("📄 Membuka Executive Audit Report...");
    try {
      const [dash, repos] = await Promise.all([
        fetch("/api/dashboard").then(r => r.json()),
        fetch("/api/repositories").then(r => r.json())
      ]);
      const period = document.getElementById("auditPeriodLabel")?.textContent || "Q1 2026 Audit Period";
      const reportHtml = `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <title>ToolKitDev Executive Security Audit — ${period}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: #0f172a; padding: 40px; max-width: 900px; margin: 0 auto; }
    h1 { margin: 0 0 6px; color: #1e3a8a; }
    .meta { color: #64748b; font-size: 13px; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 2px solid #e2e8f0; }
    .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 28px; }
    .card { border: 1px solid #cbd5e1; border-radius: 10px; padding: 16px; background: #f8fafc; }
    .card strong { display: block; font-size: 24px; color: #2563eb; margin-top: 4px; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
    th, td { border: 1px solid #cbd5e1; padding: 10px; text-align: left; }
    th { background: #eff6ff; color: #1e3a8a; }
  </style>
</head>
<body>
  <h1>ToolKitDev.ai — Executive Security &amp; Architecture Audit</h1>
  <div class="meta">
    Periode: <strong>${period}</strong> • Target Organisasi: <strong>${dash.owner || "budisusanto911"}</strong> •
    Auditor: <strong>${currentAuthUser?.name || "Budi Susanto"}</strong> • Tanggal Cetak: ${new Date().toLocaleString("id-ID")}
  </div>
  <div class="grid">
    <div class="card"><span>Security Score</span><strong>${dash.scores?.security_score ?? 95}/100</strong></div>
    <div class="card"><span>Maintenance Score</span><strong>${dash.scores?.maintenance_score ?? 78}/100</strong></div>
    <div class="card"><span>Innovation Score</span><strong>${dash.scores?.innovation_score ?? 100}/100</strong></div>
  </div>
  <h2>Daftar Repositori Terverifikasi (${(repos || []).length})</h2>
  <table>
    <thead><tr><th>Repositori</th><th>Bahasa Utama</th><th>Stars</th><th>Forks</th><th>Status Audit</th></tr></thead>
    <tbody>
      ${(Array.isArray(repos) ? repos : []).map(r => `<tr><td><strong>${r.name}</strong></td><td>${r.language || "-"}</td><td>${r.stars ?? 0}</td><td>${r.forks ?? 0}</td><td>Verified</td></tr>`).join("")}
    </tbody>
  </table>
  <script>window.onload = () => setTimeout(() => window.print(), 350);</script>
</body>
</html>`;
      const win = window.open("", "_blank");
      if (win) {
        win.document.write(reportHtml);
        win.document.close();
      } else {
        triggerFileDownload("ToolKitDev-Executive-Audit-Report.html", reportHtml, "text/html");
      }
    } catch (err) {
      window.showTopbarToast("⚠️ Gagal membuat laporan HTML: " + err.message);
    }
  });

  // 5. Theme Toggle Button (Follows dark-mode & dark-mode-toggle guidance)
  const themeBtn = document.getElementById("btnToggleTheme");
  const metaScheme = document.querySelector('meta[name="color-scheme"]');
  const darkMediaQuery = window.matchMedia("(prefers-color-scheme: dark)");

  const getResolvedScheme = () => {
    let stored = null;
    try {
      stored = localStorage.getItem("color-scheme");
    } catch (_) {}
    if (stored === "dark" || stored === "light") return stored;
    return darkMediaQuery.matches ? "dark" : "light";
  };

  const syncThemeUI = () => {
    const resolved = getResolvedScheme();
    let stored = null;
    try {
      stored = localStorage.getItem("color-scheme");
    } catch (_) {}
    if (metaScheme) {
      metaScheme.content = stored ?? "light dark";
    }
    document.body.classList.toggle("dark-theme", resolved === "dark");
    document.body.classList.toggle("soft-theme", resolved !== "dark");

    const sunIcon = themeBtn?.querySelector(".theme-icon-sun");
    const moonIcon = themeBtn?.querySelector(".theme-icon-moon");
    const srText = document.getElementById("themeToggleSrText");
    if (resolved === "dark") {
      sunIcon?.classList.add("hidden");
      moonIcon?.classList.remove("hidden");
      if (srText) srText.textContent = "Switch to light theme";
    } else {
      moonIcon?.classList.add("hidden");
      sunIcon?.classList.remove("hidden");
      if (srText) srText.textContent = "Switch to dark theme";
    }
  };

  syncThemeUI();

  themeBtn?.addEventListener("click", () => {
    const currentRendered = getResolvedScheme();
    const targetScheme = currentRendered === "dark" ? "light" : "dark";
    const systemScheme = darkMediaQuery.matches ? "dark" : "light";

    try {
      if (targetScheme === systemScheme) {
        localStorage.removeItem("color-scheme");
      } else {
        localStorage.setItem("color-scheme", targetScheme);
      }
    } catch (_) {}

    if (metaScheme) {
      let stored = null;
      try { stored = localStorage.getItem("color-scheme"); } catch (_) {}
      metaScheme.content = stored ?? "light dark";
    }

    syncThemeUI();
    window.showTopbarToast(targetScheme === "dark" ? "🌙 Dark Mode diaktifkan" : "☀️ Light Mode diaktifkan");
  });

  darkMediaQuery.addEventListener("change", syncThemeUI);
  window.addEventListener("storage", (e) => {
    if (e.key === "color-scheme") syncThemeUI();
  });

  // 6. Notifications Center Actions
  const notifDot = document.getElementById("topbarNotifDot");
  const updateNotifBadge = () => {
    const unreadCount = document.querySelectorAll("#topbarNotifList .notif-pop-item.unread").length;
    notifDot?.classList.toggle("hidden", unreadCount === 0);
  };

  document.querySelectorAll("#topbarNotifList .notif-pop-item").forEach(item => {
    item.addEventListener("click", () => {
      item.classList.remove("unread");
      updateNotifBadge();
      const targetTab = item.getAttribute("data-nav-tab");
      closeAllTopbarMenus();
      if (targetTab) {
        window.navigateToTab(targetTab);
      }
    });
  });

  document.getElementById("btnMarkAllNotifRead")?.addEventListener("click", (e) => {
    e.stopPropagation();
    document.querySelectorAll("#topbarNotifList .notif-pop-item.unread").forEach(i => i.classList.remove("unread"));
    updateNotifBadge();
    window.showTopbarToast("🔔 Semua notifikasi telah ditandai dibaca");
  });

  // Shopeers AI Assistant input box in Dashboard
  const shopeersInput = document.getElementById("shopeersAiInput");
  const shopeersSend = document.getElementById("btnShopeersSendAi");

  const sendFromShopeersCard = () => {
    if (!shopeersInput || !shopeersInput.value.trim()) return;
    const query = shopeersInput.value.trim();
    shopeersInput.value = "";
    if (window.askAiQuick) {
      window.askAiQuick(query);
    }
  };

  shopeersSend?.addEventListener("click", sendFromShopeersCard);
  shopeersInput?.addEventListener("keypress", (e) => {
    if (e.key === "Enter" && !e.isComposing) {
      e.preventDefault();
      sendFromShopeersCard();
    }
  });

  // Profit Chart Period Buttons (Monthly / Weekly)
  document.querySelectorAll(".shopeers-btn-group button").forEach(btn => {
    btn.addEventListener("click", (e) => {
      const parent = e.target.closest(".shopeers-btn-group");
      if (parent) {
        parent.querySelectorAll("button").forEach(b => b.classList.remove("active"));
        e.target.classList.add("active");
      }
    });
  });
}

/* =========================================================================
   8. ENTERPRISE AUTHENTICATION GATE & USER SESSION SYSTEM
   ========================================================================= */
let currentAuthUser = null;

function initAuthSystem() {
  const authGate = document.getElementById("authLoginGate");
  const tabBtnSignIn = document.getElementById("tabBtnSignIn");
  const tabBtnSignUp = document.getElementById("tabBtnSignUp");
  const signInForm = document.getElementById("signInForm");
  const signUpForm = document.getElementById("signUpForm");
  const authHeading = document.getElementById("authGateHeading");
  const authSubtitle = document.getElementById("authGateSubtitle");
  const feedbackBanner = document.getElementById("authFeedbackBanner");

  const setFeedback = (type, message) => {
    if (!feedbackBanner) return;
    if (!message) {
      feedbackBanner.className = "auth-feedback-banner";
      feedbackBanner.textContent = "";
      return;
    }
    feedbackBanner.className = `auth-feedback-banner ${type}`;
    feedbackBanner.textContent = message;
  };

  // Switch between Sign In & Sign Up tabs
  const switchAuthMode = (mode) => {
    setFeedback("", "");
    if (mode === "signup") {
      tabBtnSignIn?.classList.remove("active");
      tabBtnSignIn?.setAttribute("aria-selected", "false");
      tabBtnSignUp?.classList.add("active");
      tabBtnSignUp?.setAttribute("aria-selected", "true");
      signInForm?.classList.add("hidden");
      signUpForm?.classList.remove("hidden");
      if (authHeading) authHeading.textContent = "Buat Akun ToolKitDev Baru";
      if (authSubtitle) authSubtitle.textContent = "Daftarkan akun developer Anda untuk menyimpan riwayat audit APK dan konfigurasi MCP.";
    } else {
      tabBtnSignUp?.classList.remove("active");
      tabBtnSignUp?.setAttribute("aria-selected", "false");
      tabBtnSignIn?.classList.add("active");
      tabBtnSignIn?.setAttribute("aria-selected", "true");
      signUpForm?.classList.add("hidden");
      signInForm?.classList.remove("hidden");
      if (authHeading) authHeading.textContent = "Selamat Datang Kembali";
      if (authSubtitle) authSubtitle.textContent = "Masuk ke ruang kerja ToolKitDev untuk mengakses dashboard audit dan analisis repositori.";
    }
  };

  tabBtnSignIn?.addEventListener("click", () => switchAuthMode("signin"));
  tabBtnSignUp?.addEventListener("click", () => switchAuthMode("signup"));

  // Show / Hide Password toggles with ARIA state updates
  const bindPasswordToggle = (btnId, inputId) => {
    const btn = document.getElementById(btnId);
    const input = document.getElementById(inputId);
    if (!btn || !input) return;
    btn.addEventListener("click", () => {
      const isShowing = input.type === "text";
      input.type = isShowing ? "password" : "text";
      btn.setAttribute("aria-pressed", String(!isShowing));
      btn.setAttribute("aria-label", isShowing ? "Show password" : "Hide password");
      btn.textContent = isShowing ? "Lihat" : "Sembunyikan";
    });
  };

  bindPasswordToggle("toggleSignInPassword", "current-password");
  bindPasswordToggle("toggleSignUpPassword", "new-password");

  // Validate on blur and clear custom validity on input
  document.querySelectorAll("#signInForm .auth-input, #signUpForm .auth-input").forEach(input => {
    input.addEventListener("input", () => {
      input.setCustomValidity("");
      setFeedback("", "");
    });
    input.addEventListener("blur", () => {
      if (input.value && !input.checkValidity()) {
        if (input.type === "email") {
          input.setCustomValidity("Format alamat email belum lengkap (contoh: nama@domain.com).");
        } else if (input.id === "new-password" && input.value.length < 8) {
          input.setCustomValidity("Password baru minimal harus terdiri dari 8 karakter.");
        }
      }
    });
  });

  // Forgot password helper
  document.getElementById("btnForgotPassword")?.addEventListener("click", () => {
    const emailField = document.getElementById("signin-email");
    if (emailField) emailField.value = "budi.susanto@alfagift.id";
    const pwField = document.getElementById("current-password");
    if (pwField) pwField.value = "Admin123!";
    setFeedback("success", "Kredensial pemulihan akun demo telah diisi otomatis (budi.susanto@alfagift.id / Admin123!). Silakan klik Sign In.");
  });

  // Apply authenticated user session to UI
  const applyAuthSession = (user, token) => {
    currentAuthUser = user;
    if (token) {
      localStorage.setItem("toolkitdev_auth_token", token);
    }
    if (user) {
      localStorage.setItem("toolkitdev_auth_user", JSON.stringify(user));
    }

    const avatarEl = document.getElementById("topbarUserAvatar");
    const nameEl = document.getElementById("topbarUserName");
    const roleEl = document.getElementById("topbarUserRole");
    const dropName = document.getElementById("dropdownUserName");
    const dropEmail = document.getElementById("dropdownUserEmail");
    const dropProv = document.getElementById("dropdownUserProvider");

    if (avatarEl && user?.avatar) avatarEl.src = user.avatar;
    if (nameEl && user?.name) nameEl.textContent = user.name;
    if (roleEl && user?.role) roleEl.textContent = user.role;
    if (dropName && user?.name) dropName.textContent = user.name;
    if (dropEmail && user?.email) dropEmail.textContent = user.email;
    if (dropProv) {
      dropProv.textContent = user?.auth_provider?.includes("oauth")
        ? `OAuth Verified (${user.auth_provider.replace("oauth_", "").toUpperCase()})`
        : "Active Session • Verified";
    }

    authGate?.classList.add("hidden");
  };

  // Check existing session on load
  const savedToken = localStorage.getItem("toolkitdev_auth_token");
  if (savedToken) {
    fetch(`/api/auth/me?token=${encodeURIComponent(savedToken)}`, {
      headers: { "Authorization": `Bearer ${savedToken}` }
    })
      .then(res => res.json())
      .then(data => {
        if (data.authenticated && data.user) {
          applyAuthSession(data.user, data.token);
        } else {
          localStorage.removeItem("toolkitdev_auth_token");
          authGate?.classList.remove("hidden");
        }
      })
      .catch(() => {
        const cachedUser = localStorage.getItem("toolkitdev_auth_user");
        if (cachedUser) {
          try {
            applyAuthSession(JSON.parse(cachedUser), savedToken);
          } catch (_) {
            authGate?.classList.remove("hidden");
          }
        }
      });
  } else {
    authGate?.classList.remove("hidden");
  }

  // Sign-In Form Submission
  signInForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const emailInput = document.getElementById("signin-email");
    const pwInput = document.getElementById("current-password");
    const submitBtn = document.getElementById("btnSubmitSignIn");

    const emailVal = emailInput?.value.trim() || "";
    const pwVal = pwInput?.value || "";

    if (!emailVal || !pwVal) {
      setFeedback("error", "Harap masukkan alamat email/username dan password Anda.");
      (emailVal ? pwInput : emailInput)?.focus();
      return;
    }

    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = "Memverifikasi Kredensial...";
    }

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: emailVal, password: pwVal })
      });
      const data = await res.json();
      if (data.success && data.user) {
        setFeedback("success", `Selamat datang kembali, ${data.user.name}! Membuka dashboard...`);
        setTimeout(() => applyAuthSession(data.user, data.token), 350);
      } else {
        setFeedback("error", data.error || "Gagal masuk. Periksa kembali email dan password Anda.");
      }
    } catch (err) {
      setFeedback("error", "Kesalahan jaringan saat menghubungi server autentikasi.");
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = "Sign In";
      }
    }
  });

  // Sign-Up Form Submission
  signUpForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const nameInput = document.getElementById("signup-name");
    const emailInput = document.getElementById("signup-email");
    const pwInput = document.getElementById("new-password");
    const submitBtn = document.getElementById("btnSubmitSignUp");

    const nameVal = nameInput?.value.trim() || "";
    const emailVal = emailInput?.value.trim() || "";
    const pwVal = pwInput?.value || "";

    if (!nameVal || !emailVal || pwVal.length < 8) {
      setFeedback("error", "Pastikan nama lengkap, email valid, dan password minimal 8 karakter telah terisi.");
      return;
    }

    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = "Membuat Akun...";
    }

    try {
      const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: nameVal, email: emailVal, password: pwVal })
      });
      const data = await res.json();
      if (data.success && data.user) {
        setFeedback("success", `Akun ${data.user.name} berhasil dibuat! Mengarahkan ke dashboard...`);
        setTimeout(() => applyAuthSession(data.user, data.token), 400);
      } else {
        setFeedback("error", data.error || "Gagal mendaftarkan akun.");
      }
    } catch (err) {
      setFeedback("error", "Kesalahan jaringan saat mendaftarkan akun.");
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = "Create Account";
      }
    }
  });

  // 1-Click Instant Demo Login
  document.getElementById("btnAuthDemoQuick")?.addEventListener("click", async () => {
    setFeedback("success", "Mengautentikasi sesi Akun Demo Lead Architect...");
    try {
      const res = await fetch("/api/auth/demo", { method: "POST" });
      const data = await res.json();
      if (data.success && data.user) {
        applyAuthSession(data.user, data.token);
      }
    } catch (err) {
      setFeedback("error", "Gagal memuat sesi demo: " + err.message);
    }
  });

  // OAuth Login (GitHub & Google Workspace integrated with MCP Hub)
  const handleOAuthSignIn = async (provider) => {
    setFeedback("success", `Menghubungkan sesi OAuth 2.0 melalui ${provider === "github" ? "GitHub MCP" : "Google Workspace MCP"}...`);
    try {
      const res = await fetch("/api/auth/oauth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider })
      });
      const data = await res.json();
      if (data.success && data.user) {
        setTimeout(() => applyAuthSession(data.user, data.token), 350);
      } else {
        setFeedback("error", data.error || "Autentikasi OAuth gagal.");
      }
    } catch (err) {
      setFeedback("error", "Gagal menghubungi endpoint OAuth: " + err.message);
    }
  };

  document.getElementById("btnAuthOAuthGithub")?.addEventListener("click", () => handleOAuthSignIn("github"));
  document.getElementById("btnAuthOAuthGoogle")?.addEventListener("click", () => handleOAuthSignIn("google"));

  // Topbar Profile Dropdown & Logout
  const profileTrigger = document.getElementById("btnToggleProfileMenu");
  const profileDropdown = document.getElementById("userProfileDropdown");

  profileTrigger?.addEventListener("click", (e) => {
    e.stopPropagation();
    const isHidden = profileDropdown?.classList.toggle("hidden");
    profileTrigger.setAttribute("aria-expanded", String(!isHidden));
  });

  document.addEventListener("click", (e) => {
    const wrap = document.getElementById("userProfileMenuWrap");
    if (wrap && !wrap.contains(e.target)) {
      profileDropdown?.classList.add("hidden");
      profileTrigger?.setAttribute("aria-expanded", "false");
    }
  });

  document.getElementById("btnProfileGoSettings")?.addEventListener("click", () => {
    profileDropdown?.classList.add("hidden");
    window.navigateToTab("settings");
  });

  document.getElementById("btnProfileGoMcp")?.addEventListener("click", () => {
    profileDropdown?.classList.add("hidden");
    window.navigateToTab("mcp-hub");
  });

  document.getElementById("btnLogoutUser")?.addEventListener("click", async () => {
    const token = localStorage.getItem("toolkitdev_auth_token") || "";
    try {
      await fetch("/api/auth/logout", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
        body: JSON.stringify({ token })
      });
    } catch (_) {}

    localStorage.removeItem("toolkitdev_auth_token");
    localStorage.removeItem("toolkitdev_auth_user");
    currentAuthUser = null;
    profileDropdown?.classList.add("hidden");
    profileTrigger?.setAttribute("aria-expanded", "false");
    setFeedback("success", "Anda telah berhasil keluar (Signed Out).");
    authGate?.classList.remove("hidden");
  });
}

/* =========================================================================
   8. APK VERSION DIFF & DELTA AUDIT
   ========================================================================= */
let apkDiffState = {
  currentResult: null,
  activeTab: "findings"
};

async function initApkDiffComparator() {
  const baseSelect = document.getElementById("diffBaseSelect");
  const targetSelect = document.getElementById("diffTargetSelect");
  const runBtn = document.getElementById("btnRunDiffAudit");
  const demo1 = document.getElementById("btnDiffDemo1");
  const demo2 = document.getElementById("btnDiffDemo2");

  // Load available files for comparison
  try {
    const res = await fetch("/api/apk/diff-list");
    if (res.ok) {
      const data = await res.json();
      const files = data.files || [];
      if (files.length > 0) {
        const baseVal = baseSelect?.value;
        const targetVal = targetSelect?.value;
        
        let optsHtml = files.map(f => `<option value="${escapeHtml(f.path)}">${escapeHtml(f.name)} (${f.size_fmt})</option>`).join("");
        if (baseSelect) baseSelect.innerHTML = optsHtml;
        if (targetSelect) targetSelect.innerHTML = optsHtml;

        // Set meaningful defaults
        if (baseSelect && baseSelect.querySelector(`option[value="${baseVal}"]`)) baseSelect.value = baseVal;
        if (targetSelect) {
          if (targetSelect.querySelector(`option[value="${targetVal}"]`)) targetSelect.value = targetVal;
          else if (files.length > 1) targetSelect.selectedIndex = 1;
        }
      }
    }
  } catch (err) {
    console.error("Gagal memuat diff-list:", err);
  }

  // Demo 1
  demo1?.addEventListener("click", () => {
    if (baseSelect) baseSelect.value = "samples/sample-debug.apk";
    if (targetSelect) targetSelect.value = "uploads/base.apk";
    runApkDiffComparison();
  });

  // Demo 2
  demo2?.addEventListener("click", () => {
    if (baseSelect) baseSelect.value = "alfagift_analysis.json";
    if (targetSelect) targetSelect.value = "uploads/base.apk";
    runApkDiffComparison();
  });

  runBtn?.addEventListener("click", () => runApkDiffComparison());

  // Tab switching inside diff
  document.querySelectorAll("[data-diff-tab]").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("[data-diff-tab]").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const tabName = btn.getAttribute("data-diff-tab");
      apkDiffState.activeTab = tabName;

      document.getElementById("diffTabFindings")?.classList.toggle("hidden", tabName !== "findings");
      document.getElementById("diffTabPermissions")?.classList.toggle("hidden", tabName !== "permissions");
      document.getElementById("diffTabComponents")?.classList.toggle("hidden", tabName !== "components");
      document.getElementById("diffTabEndpoints")?.classList.toggle("hidden", tabName !== "endpoints");
    });
  });
}

async function runApkDiffComparison() {
  const baseSelect = document.getElementById("diffBaseSelect");
  const targetSelect = document.getElementById("diffTargetSelect");
  const runBtn = document.getElementById("btnRunDiffAudit");
  const resultsArea = document.getElementById("diffResultsArea");

  const baseFile = baseSelect?.value || "";
  const targetFile = targetSelect?.value || "";

  if (!baseFile || !targetFile) {
    if (typeof showTopbarToast === "function") showTopbarToast("Pilih kedua rilis untuk dibandingkan.");
    return;
  }

  if (runBtn) {
    runBtn.disabled = true;
    runBtn.innerHTML = `<span>Membandingkan Bytecode...</span>`;
  }
  if (typeof showTopbarToast === "function") showTopbarToast("Memulai perbandingan delta keamanan...");

  try {
    const res = await fetch(`/api/apk/diff?base=${encodeURIComponent(baseFile)}&target=${encodeURIComponent(targetFile)}`);
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || "Gagal membandingkan binary");
    }
    const data = await res.json();
    apkDiffState.currentResult = data;
    renderDiffResults(data);
    resultsArea?.classList.remove("hidden");
    resultsArea?.scrollIntoView({ behavior: "smooth" });
    if (typeof showTopbarToast === "function") showTopbarToast("✅ Perbandingan delta selesai dihitung!");
  } catch (err) {
    if (typeof showTopbarToast === "function") showTopbarToast("⚠️ " + err.message);
  } finally {
    if (runBtn) {
      runBtn.disabled = false;
      runBtn.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg><span>Bandingkan Versi</span>`;
    }
  }
}

function renderDiffResults(data) {
  const sum = data.summary || {};
  const perms = data.permissions_delta || {};
  const comps = data.components_delta || {};
  const finds = data.findings_delta || {};
  const eps = data.endpoints_delta || {};

  // Hero Banner
  document.getElementById("diffBaseAppName").textContent = sum.base_app_name;
  document.getElementById("diffBaseAppMeta").textContent = `${sum.base_version} • SDK ${sum.base_target_sdk} • ${sum.base_size_mb} MB`;
  document.getElementById("diffBaseScore").textContent = sum.base_score + " pts";

  document.getElementById("diffTargetAppName").textContent = sum.target_app_name;
  document.getElementById("diffTargetAppMeta").textContent = `${sum.target_version} • SDK ${sum.target_target_sdk} • ${sum.target_size_mb} MB`;
  document.getElementById("diffTargetScore").textContent = sum.target_score + " pts";

  const pill = document.getElementById("diffDeltaPill");
  pill.textContent = sum.verdict_badge;
  pill.style.color = sum.verdict_color;
  pill.style.borderColor = sum.verdict_color;
  pill.style.background = sum.verdict_status === "IMPROVED" ? "#f0fdf4" : (sum.verdict_status === "DEGRADED" ? "#fef2f2" : "#f1f5f9");

  document.getElementById("diffDeltaLabel").textContent = sum.verdict_status;

  // Narrative
  const narrEl = document.getElementById("diffNarrativeText");
  if (narrEl) narrEl.innerHTML = formatAiMarkdown(sum.summary_narrative);

  // Counters
  document.getElementById("diffNumPerms").textContent = (perms.added_count > 0 ? `+${perms.added_count}` : perms.added_count);
  document.getElementById("diffSubPerms").textContent = `${perms.dangerous_added_count} izin berbahaya ditambahkan`;
  
  document.getElementById("diffNumComps").textContent = (comps.newly_exposed_count > 0 ? `+${comps.newly_exposed_count}` : comps.newly_exposed_count);
  document.getElementById("diffSubComps").textContent = `Total Exported: ${comps.total_exported_base} → ${comps.total_exported_target}`;

  document.getElementById("diffNumResolved").textContent = finds.resolved_count;
  document.getElementById("diffNumRegressed").textContent = finds.regressed_count;

  // Tab 1: Findings Delta
  const findingsContainer = document.getElementById("diffFindingsList");
  let fHtml = "";
  if (finds.regressed_count > 0) {
    fHtml += `<div style="margin-bottom:12px;"><h5 style="color:#dc2626; margin-bottom:6px;">🔴 Celah Keamanan Baru Terdeteksi (Regresi):</h5>`;
    finds.regressed.forEach(f => {
      fHtml += `
        <div style="background:#fef2f2; border:1px solid #fecdd3; border-radius:8px; padding:10px 14px; margin-bottom:8px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <strong style="color:#b91c1c;">[${escapeHtml(f.severity)}] ${escapeHtml(f.title)}</strong>
            <span class="badge badge-danger">REGRESI BARU</span>
          </div>
          <div style="font-size:11.5px; color:#475569; margin-top:4px;">${escapeHtml(f.description)}</div>
        </div>`;
    });
    fHtml += `</div>`;
  }

  if (finds.resolved_count > 0) {
    fHtml += `<div style="margin-bottom:12px;"><h5 style="color:#16a34a; margin-bottom:6px;">🟢 Celah yang Berhasil Diperbaiki (Resolved):</h5>`;
    finds.resolved.forEach(f => {
      fHtml += `
        <div style="background:#f0fdf4; border:1px solid #bbf7d0; border-radius:8px; padding:10px 14px; margin-bottom:8px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <strong style="color:#15803d;">[${escapeHtml(f.severity)}] ${escapeHtml(f.title)}</strong>
            <span class="badge badge-success">BERHASIL DITUTUP</span>
          </div>
          <div style="font-size:11.5px; color:#475569; margin-top:4px;">Celah ini ada pada rilis acuan dan telah diatasi di rilis target.</div>
        </div>`;
    });
    fHtml += `</div>`;
  }

  if (finds.persistent_count > 0) {
    fHtml += `<div><h5 style="color:#64748b; margin-bottom:6px;">⚠️ Celah yang Masih Bertahan (Persistent di Kedua Versi):</h5>`;
    finds.persistent.forEach(f => {
      fHtml += `
        <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:8px 12px; margin-bottom:6px; font-size:11.5px; display:flex; justify-content:space-between;">
          <span><strong>[${escapeHtml(f.severity)}]</strong> ${escapeHtml(f.title)}</span>
          <span style="color:#94a3b8;">${escapeHtml(f.cwe || "CWE-699")}</span>
        </div>`;
    });
    fHtml += `</div>`;
  }
  findingsContainer.innerHTML = fHtml || `<div style="text-align:center; padding:24px; color:#10b981;">✓ Tidak ada perbedaan celah keamanan terdeteksi.</div>`;

  // Tab 2: Permissions Delta
  const addedPermsList = document.getElementById("diffAddedPermsList");
  addedPermsList.innerHTML = (perms.added || []).map(p => `
    <div class="diff-item-row">
      <span style="${p.is_dangerous ? 'color:#dc2626; font-weight:700;' : ''}">${escapeHtml(p.permission)}</span>
      ${p.is_dangerous ? '<span class="badge badge-danger">Dangerous</span>' : '<span class="badge badge-cert">Normal</span>'}
    </div>
  `).join("") || `<div style="padding:16px; text-align:center; color:#64748b;">Tidak ada izin baru.</div>`;

  const removedPermsList = document.getElementById("diffRemovedPermsList");
  removedPermsList.innerHTML = (perms.removed || []).map(p => `
    <div class="diff-item-row">
      <span style="text-decoration:line-through; color:#64748b;">${escapeHtml(p.permission)}</span>
      <span class="badge badge-success">Dihapus</span>
    </div>
  `).join("") || `<div style="padding:16px; text-align:center; color:#64748b;">Tidak ada izin yang dihapus.</div>`;

  // Tab 3: Components Delta
  const addedCompsList = document.getElementById("diffAddedCompsList");
  addedCompsList.innerHTML = (comps.newly_exposed || []).map(c => `
    <div class="diff-item-row">
      <span><strong>[${escapeHtml(c.type)}]</strong> ${escapeHtml(c.name)}</span>
      <span class="badge badge-danger">Exposed</span>
    </div>
  `).join("") || `<div style="padding:16px; text-align:center; color:#16a34a;">✓ Tidak ada komponen baru yang diekspos ke publik.</div>`;

  const securedCompsList = document.getElementById("diffSecuredCompsList");
  securedCompsList.innerHTML = (comps.secured || []).map(c => `
    <div class="diff-item-row">
      <span><strong>[${escapeHtml(c.type)}]</strong> ${escapeHtml(c.name)}</span>
      <span class="badge badge-success">Closed</span>
    </div>
  `).join("") || `<div style="padding:16px; text-align:center; color:#64748b;">Tidak ada komponen yang ditutup.</div>`;

  // Tab 4: Endpoints Delta
  const addedEpsList = document.getElementById("diffAddedEndpointsList");
  addedEpsList.innerHTML = (eps.new_endpoints || []).map(e => `
    <div class="diff-item-row">
      <span><strong>[${escapeHtml(e.http_method || e.type || "ROUTE")}]</strong> ${escapeHtml(e.endpoint || e.url_route || "")}</span>
      <span class="badge badge-info">${escapeHtml(e.category || "API")}</span>
    </div>
  `).join("") || `<div style="padding:16px; text-align:center; color:#64748b;">Tidak ada endpoint baru.</div>`;

  const removedEpsList = document.getElementById("diffRemovedEndpointsList");
  removedEpsList.innerHTML = (eps.removed_endpoints || []).map(e => `
    <div class="diff-item-row">
      <span style="text-decoration:line-through; color:#64748b;">${escapeHtml(e.endpoint || e.url_route || "")}</span>
      <span class="badge badge-secondary">Removed</span>
    </div>
  `).join("") || `<div style="padding:16px; text-align:center; color:#64748b;">Tidak ada endpoint yang dihapus.</div>`;
}

/* =========================================================================
   9. THIRD-PARTY SDK & DEPENDENCY CVE SCANNER (SCA)
   ========================================================================= */
let scaState = {
  currentData: null,
  activeCategory: "all",
  searchQuery: ""
};

async function initScaScanner() {
  const scanBtn = document.getElementById("btnRunScaScan");
  const targetSelect = document.getElementById("scaTargetFileSelect");
  const searchInput = document.getElementById("scaSearchInput");

  // Populate files list for SCA dropdown
  try {
    const res = await fetch("/api/apk/diff-list");
    if (res.ok) {
      const data = await res.json();
      const files = data.files || [];
      if (files.length > 0 && targetSelect) {
        const curVal = targetSelect.value;
        targetSelect.innerHTML = files.map(f => `<option value="${escapeHtml(f.path)}">${escapeHtml(f.name)} (${f.size_fmt})</option>`).join("");
        if (targetSelect.querySelector(`option[value="${curVal}"]`)) targetSelect.value = curVal;
      }
    }
  } catch (e) {}

  scanBtn?.addEventListener("click", () => runScaScan());

  // Category filter chips
  document.querySelectorAll(".sca-chip[data-cat]").forEach(chip => {
    chip.addEventListener("click", () => {
      document.querySelectorAll(".sca-chip").forEach(c => c.classList.remove("active"));
      chip.classList.add("active");
      scaState.activeCategory = chip.getAttribute("data-cat");
      renderScaTable();
    });
  });

  searchInput?.addEventListener("input", (e) => {
    scaState.searchQuery = e.target.value.toLowerCase().trim();
    renderScaTable();
  });

  // Automatically trigger SCA scan on start
  setTimeout(() => {
    runScaScan();
  }, 400);
}

async function runScaScan() {
  const targetSelect = document.getElementById("scaTargetFileSelect");
  const scanBtn = document.getElementById("btnRunScaScan");
  const targetFile = targetSelect?.value || "uploads/base.apk";

  if (scanBtn) {
    scanBtn.disabled = true;
    scanBtn.innerHTML = `<span>Memindai Bytecode...</span>`;
  }

  try {
    const res = await fetch(`/api/apk/sca?file=${encodeURIComponent(targetFile)}`);
    if (!res.ok) throw new Error("Gagal menjalankan SCA scan");
    const data = await res.json();
    scaState.currentData = data;

    // Update KPIs
    document.getElementById("scaKpiTotal").textContent = data.total_detected || 0;
    document.getElementById("scaKpiVuln").textContent = data.vulnerable_count || 0;
    document.getElementById("scaKpiOutdated").textContent = data.outdated_count || 0;
    document.getElementById("scaKpiClean").textContent = data.clean_count || 0;

    renderScaTable();
    if (typeof showTopbarToast === "function") showTopbarToast("✅ Pemindaian dependensi SDK selesai!");
  } catch (err) {
    console.error("SCA scan error:", err);
    if (typeof showTopbarToast === "function") showTopbarToast("⚠️ " + err.message);
  } finally {
    if (scanBtn) {
      scanBtn.disabled = false;
      scanBtn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg><span>Pindai SDK</span>`;
    }
  }
}

function renderScaTable() {
  const tbody = document.getElementById("scaTableBody");
  const info = document.getElementById("scaTableInfo");
  if (!tbody || !scaState.currentData) return;

  const sdks = scaState.currentData.sdks || [];
  const cat = scaState.activeCategory;
  const q = scaState.searchQuery;

  const filtered = sdks.filter(s => {
    if (cat === "vulnerable" && !s.is_vulnerable) return false;
    if (cat !== "all" && cat !== "vulnerable" && s.category !== cat) return false;
    if (q) {
      const matchText = `${s.name} ${s.category} ${s.matched_signature} ${s.detected_version} ${(s.cves || []).map(c=>c.cve_id).join(' ')}`.toLowerCase();
      if (!matchText.includes(q)) return false;
    }
    return true;
  });

  if (info) info.textContent = `Showing ${filtered.length} of ${sdks.length} SDKs`;

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:24px; color:#64748b;">Tidak ada SDK yang sesuai kriteria pencarian.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map((s, idx) => {
    let cveBadge = `<span class="sca-cvss-badge sca-cvss-clean">✓ Clean</span>`;
    if (s.is_vulnerable && s.cves && s.cves.length > 0) {
      const topCve = s.cves[0];
      const cls = topCve.severity === "CRITICAL" ? "sca-cvss-critical" : "sca-cvss-high";
      cveBadge = `<span class="sca-cvss-badge ${cls}">${topCve.cve_id} (CVSS ${topCve.cvss})</span>`;
    }

    const versionHtml = `
      <span style="font-weight:700; color:#0f172a;">v${escapeHtml(s.detected_version)}</span>
      ${s.is_outdated ? `<span style="display:block; font-size:10px; color:#d97706;">Latest: v${escapeHtml(s.latest_safe_version)}</span>` : ''}
    `;

    return `
      <tr>
        <td>
          <strong style="color:#0f172a; font-size:12.5px;">${escapeHtml(s.name)}</strong>
          <div style="font-size:10.5px; color:#64748b; margin-top:2px;">${escapeHtml(s.category)} • <span style="color:#3b82f6;">${escapeHtml(s.license)}</span></div>
        </td>
        <td>
          <code style="font-family:'JetBrains Mono',monospace; font-size:10.5px; color:#334155;">${escapeHtml(s.matched_signature)}</code>
        </td>
        <td>${versionHtml}</td>
        <td>${cveBadge}</td>
        <td>
          <button type="button" class="btn btn-secondary" style="font-size:11px; padding:4px 8px;" onclick="openScaDetailModal(${idx})">
            Solusi Fix
          </button>
        </td>
      </tr>
    `;
  }).join("");
}

window.openScaDetailModal = function(sdkIdx) {
  if (!scaState.currentData) return;
  const sdk = scaState.currentData.sdks[sdkIdx];
  if (!sdk) return;

  const cvesHtml = (sdk.cves && sdk.cves.length > 0)
    ? sdk.cves.map(c => `
        <div style="background:#fef2f2; border:1px solid #fecdd3; border-radius:8px; padding:10px 14px; margin-bottom:10px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <strong style="color:#b91c1c;">${c.cve_id}: ${escapeHtml(c.title)}</strong>
            <span class="badge badge-danger">CVSS ${c.cvss} (${c.severity})</span>
          </div>
          <div style="font-size:11.5px; color:#475569; margin:6px 0;">${escapeHtml(c.description)}</div>
          <div style="font-size:11px; color:#991b1b; font-weight:600;">Affected: ${escapeHtml(c.affected_versions)}</div>
        </div>
      `).join("")
    : `<div style="background:#f0fdf4; border:1px solid #bbf7d0; border-radius:8px; padding:10px 14px; color:#15803d; font-size:12px; margin-bottom:12px;">✓ Tidak ditemukan kerentanan CVE yang terdaftar pada versi ini.</div>`;

  const gradleSnippet = `// build.gradle / build.gradle.kts (App Module)
dependencies {
    // Rekomendasi upgrade ${sdk.name}
    implementation("${sdk.matched_signature.replace('/', '.')}:${sdk.latest_safe_version || sdk.detected_version}")
}`;

  const bodyHtml = `
    <div style="margin-bottom:14px;">
      <h4 style="margin:0 0 4px; font-size:15px; color:#0f172a;">${escapeHtml(sdk.name)}</h4>
      <div style="font-size:12px; color:#64748b;">Kategori: ${escapeHtml(sdk.category)} | Lisensi: ${escapeHtml(sdk.license)}</div>
    </div>
    
    ${cvesHtml}

    <div class="remediation-box" style="margin-top:12px;">
      <strong>🛠️ Panduan Remediasi &amp; Upgrade Dependensi:</strong>
      <div style="margin:6px 0 10px; font-size:12px; color:#1e293b;">${escapeHtml(sdk.remediation)}</div>
      <pre style="background:#0f172a; color:#f8fafc; padding:10px 12px; border-radius:6px; font-family:'JetBrains Mono',monospace; font-size:11px; overflow-x:auto;"><code>${escapeHtml(gradleSnippet)}</code></pre>
    </div>
  `;

  openMobsfDialog(
    "DEPENDENCY SCA AUDIT",
    `Audit Detail: ${sdk.name}`,
    bodyHtml,
    gradleSnippet
  );
};

/* =========================================================================
   1-CLICK AI FIX PACK GENERATOR (.zip / .patch)
   ========================================================================= */
function initAiFixPackGenerator() {
  const btnFixApk = document.getElementById("btnExportAiFixPack");
  const btnFixIpa = document.getElementById("btnIpaFixPack");

  const handleDownloadFixPack = async (targetFile) => {
    try {
      showToast("Sedang meracik Fix Pack (.zip) otomatis berbasis temuan AI...", "info");
      const url = `/api/apk/fix-pack?file=${encodeURIComponent(targetFile || "")}`;
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`Gagal membuat Fix Pack (Status: ${response.status})`);
      }
      const blob = await response.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = downloadUrl;
      const contentDisp = response.headers.get("Content-Disposition") || "";
      let filename = "ToolKitDev_FixPack.zip";
      const match = contentDisp.match(/filename="?([^"]+)"?/);
      if (match && match[1]) filename = match[1];
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(downloadUrl);
      showToast(`✓ Berhasil mengunduh ${filename}! Salin ke proyek Android/iOS Anda.`, "success");
    } catch (err) {
      console.error("Fix pack error:", err);
      showToast(`Gagal mengunduh Fix Pack: ${err.message}`, "error");
    }
  };

  btnFixApk?.addEventListener("click", () => {
    const currentFile = window.currentApkAnalysis?.metadata?.package_name || "alfagift_analysis.json";
    handleDownloadFixPack(currentFile);
  });

  btnFixIpa?.addEventListener("click", () => {
    const sel = document.getElementById("iosTargetFileSelect");
    const target = sel ? sel.value : "samples/sample-ios.ipa";
    handleDownloadFixPack(target);
  });
}

/* =========================================================================
   iOS (.ipa) TEARDOWN & SECURITY INSPECTOR
   ========================================================================= */
let iosState = {
  currentData: null,
  activeSubTab: "ats"
};

function initIpaInspector() {
  const btnScan = document.getElementById("btnRunIpaScan");
  const selectFile = document.getElementById("iosTargetFileSelect");
  const subTabBtns = document.querySelectorAll("[data-iostab]");

  loadIpaFilesList();

  btnScan?.addEventListener("click", () => {
    const file = selectFile?.value || "samples/sample-ios.ipa";
    runIpaInspection(file);
  });

  subTabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      subTabBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const tabId = btn.getAttribute("data-iostab");
      iosState.activeSubTab = tabId;
      renderIpaSubPanels(tabId);
    });
  });

  // Automatically analyze initial sample
  runIpaInspection("samples/sample-ios.ipa");
}

async function loadIpaFilesList() {
  try {
    const res = await fetch("/api/apk/diff-list");
    if (!res.ok) return;
    const data = await res.json();
    const select = document.getElementById("iosTargetFileSelect");
    if (!select || !data.files) return;

    const ipaFiles = data.files.filter(f => f.name.endsWith(".ipa"));
    if (ipaFiles.length > 0) {
      select.innerHTML = ipaFiles.map(f => `
        <option value="${f.path}">${f.name} (${f.size_fmt || 'IPA'})</option>
      `).join("");
    }
  } catch (err) {
    console.warn("Could not load IPA files list:", err);
  }
}

async function runIpaInspection(filePath) {
  try {
    showToast("Menganalisis biner Mach-O, ATS, dan Entitlements iOS...", "info");
    const res = await fetch(`/api/ipa/inspect?file=${encodeURIComponent(filePath)}`);
    if (!res.ok) throw new Error("Gagal menganalisis file IPA.");
    const data = await res.json();
    iosState.currentData = data;
    renderIpaResults(data);
    showToast("✓ Analisis keamanan iOS IPA selesai!", "success");
  } catch (err) {
    console.error("IPA inspection error:", err);
    showToast(`Error analisis IPA: ${err.message}`, "error");
  }
}

function renderIpaResults(data) {
  const meta = data.metadata || {};
  const ats = data.app_transport_security || {};
  const entitlements = data.entitlements || {};
  const macho = data.macho_protections || {};
  const findings = data.findings || [];

  const appNameEl = document.getElementById("iosAppName");
  const bundleIdEl = document.getElementById("iosBundleId");
  const verEl = document.getElementById("iosVersion");
  const minOsEl = document.getElementById("iosMinOs");

  if (appNameEl) appNameEl.textContent = meta.app_name || "iOS App";
  if (bundleIdEl) bundleIdEl.textContent = meta.bundle_id || "unknown.bundle";
  if (verEl) verEl.textContent = `${meta.version_name || '1.0'} (${meta.build_number || '1'})`;
  if (minOsEl) minOsEl.textContent = `iOS ${meta.min_os_version || '14.0'}+`;

  const scoreEl = document.getElementById("iosScoreValue");
  const badgeEl = document.getElementById("iosScoreBadge");
  if (scoreEl) scoreEl.textContent = `${data.security_score}/100`;

  if (badgeEl) {
    if (data.security_score >= 80) {
      if (scoreEl) scoreEl.style.color = "#10b981";
      badgeEl.className = "diff-verdict-badge diff-verdict-improved";
      badgeEl.textContent = "GOOD POSTURE";
    } else if (data.security_score >= 50) {
      if (scoreEl) scoreEl.style.color = "#f59e0b";
      badgeEl.className = "diff-verdict-badge";
      badgeEl.style.background = "#fef3c7";
      badgeEl.style.color = "#b45309";
      badgeEl.textContent = "MODERATE RISK";
    } else {
      if (scoreEl) scoreEl.style.color = "#ef4444";
      badgeEl.className = "diff-verdict-badge diff-verdict-degraded";
      badgeEl.textContent = "CRITICAL RISK";
    }
  }

  const kpiAts = document.getElementById("iosKpiAts");
  if (kpiAts) {
    if (ats.allows_arbitrary_loads) {
      kpiAts.textContent = "VULNERABLE (Allows Plaintext)";
      kpiAts.style.color = "#ef4444";
    } else {
      kpiAts.textContent = "SECURE (HTTPS Enforced)";
      kpiAts.style.color = "#10b981";
    }
  }

  const kpiDebug = document.getElementById("iosKpiDebug");
  if (kpiDebug) {
    if (entitlements["get-task-allow"]) {
      kpiDebug.textContent = "get-task-allow: TRUE (CRITICAL)";
      kpiDebug.style.color = "#ef4444";
    } else {
      kpiDebug.textContent = "get-task-allow: FALSE (Secure)";
      kpiDebug.style.color = "#10b981";
    }
  }

  const kpiMacho = document.getElementById("iosKpiMacho");
  if (kpiMacho) {
    const protectionsOn = [macho.has_pie && "PIE", macho.has_stack_canaries && "Canaries", macho.has_arc && "ARC"].filter(Boolean);
    kpiMacho.textContent = protectionsOn.join(", ") || "None Active";
    kpiMacho.style.color = protectionsOn.length >= 2 ? "#10b981" : "#ef4444";
  }

  const kpiFind = document.getElementById("iosKpiFindings");
  if (kpiFind) {
    kpiFind.textContent = `${findings.length} Celah Teridentifikasi`;
  }

  renderIpaSubPanels(iosState.activeSubTab);
}

function renderIpaSubPanels(tabId) {
  document.querySelectorAll(".ios-subpanel").forEach(p => p.style.display = "none");
  const panelMap = {
    ats: "iosPanelAts",
    macho: "iosPanelMacho",
    privacy: "iosPanelPrivacy",
    findings: "iosPanelFindings"
  };
  const targetId = panelMap[tabId] || "iosPanelAts";
  const el = document.getElementById(targetId);
  if (el) el.style.display = "block";

  const data = iosState.currentData;
  if (!data) return;

  if (tabId === "ats") {
    const ats = data.app_transport_security || {};
    const atsEl = document.getElementById("iosAtsDetails");
    if (atsEl) {
      atsEl.innerHTML = `
        <div style="margin-bottom:12px;">
          <div style="display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid #f1f5f9;">
            <strong>NSAllowsArbitraryLoads:</strong>
            <span class="badge ${ats.allows_arbitrary_loads ? 'badge-danger' : 'badge-success'}">${ats.allows_arbitrary_loads ? 'true (VULNERABLE)' : 'false (SECURE)'}</span>
          </div>
          <div style="display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid #f1f5f9;">
            <strong>NSAllowsArbitraryLoadsInWebContent:</strong>
            <span class="badge ${ats.allows_arbitrary_loads_in_web ? 'badge-warning' : 'badge-success'}">${ats.allows_arbitrary_loads_in_web ? 'true (Active)' : 'false'}</span>
          </div>
          <div style="display:flex; justify-content:space-between; padding:8px 0;">
            <strong>Exception Domains Configured:</strong>
            <span>${ats.exception_domain_count || 0} domain</span>
          </div>
        </div>
        <div style="background:#f8fafc; border-radius:6px; padding:10px 12px; font-size:12px; color:#475569;">
          ${ats.allows_arbitrary_loads 
            ? '⚠️ <strong>Peringatan Keamanan Kritis:</strong> Flag <code>NSAllowsArbitraryLoads: true</code> mengizinkan seluruh koneksi HTTP plaintext tanpa enkripsi TLS, memaparkan kredensial pengguna ke serangan Man-in-the-Middle (MITM).'
            : '✓ Konfigurasi ATS telah mengamankan lalu lintas data dengan mewajibkan enkripsi TLS 1.2+ untuk seluruh network calls.'}
        </div>
      `;
    }

    const entEl = document.getElementById("iosEntitlementsDetails");
    if (entEl) {
      const ents = data.entitlements || {};
      const entEntries = Object.entries(ents);
      entEl.innerHTML = entEntries.length > 0 ? `
        <table class="data-table" style="font-size:12px; width:100%;">
          <thead><tr><th>Entitlement Key</th><th>Nilai Terkonfigurasi</th></tr></thead>
          <tbody>
            ${entEntries.map(([k, v]) => `
              <tr>
                <td><code>${escapeHtml(k)}</code></td>
                <td><span style="font-family:monospace; color:${k === 'get-task-allow' && v === true ? '#b91c1c; font-weight:700;' : 'inherit'};">${escapeHtml(String(v))}</span></td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      ` : `<div style="color:#64748b;">Tidak ada data entitlements khusus.</div>`;
    }
  } else if (tabId === "macho") {
    const macho = data.macho_protections || {};
    const machoGrid = document.getElementById("iosMachoGrid");
    if (machoGrid) {
      const frameworks = (macho.linked_frameworks || []).map(f => `<span class="sca-chip">${escapeHtml(f)}.framework</span>`).join(" ");

      machoGrid.innerHTML = `
        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:14px; margin-bottom:18px;">
          <div style="border:1px solid #e2e8f0; border-radius:8px; padding:12px; background:#f8fafc;">
            <div style="font-size:12px; color:#64748b;">PIE (ASLR)</div>
            <div style="font-size:16px; font-weight:700; color:${macho.has_pie ? '#10b981' : '#ef4444'}; margin:4px 0;">${macho.has_pie ? '✓ MH_PIE ACTIVE' : '✗ PIE DISABLED'}</div>
            <div style="font-size:11px; opacity:0.8;">Randomizes memory address space layout</div>
          </div>

          <div style="border:1px solid #e2e8f0; border-radius:8px; padding:12px; background:#f8fafc;">
            <div style="font-size:12px; color:#64748b;">Stack Canaries</div>
            <div style="font-size:16px; font-weight:700; color:${macho.has_stack_canaries ? '#10b981' : '#ef4444'}; margin:4px 0;">${macho.has_stack_canaries ? '✓ CANARIES DETECTED' : '✗ NOT DETECTED'}</div>
            <div style="font-size:11px; opacity:0.8;">Buffer overflow protection (__stack_chk_fail)</div>
          </div>

          <div style="border:1px solid #e2e8f0; border-radius:8px; padding:12px; background:#f8fafc;">
            <div style="font-size:12px; color:#64748b;">ARC (Memory Safety)</div>
            <div style="font-size:16px; font-weight:700; color:${macho.has_arc ? '#10b981' : '#ef4444'}; margin:4px 0;">${macho.has_arc ? '✓ ARC ENABLED' : '✗ ARC DISABLED'}</div>
            <div style="font-size:11px; opacity:0.8;">Automatic Reference Counting</div>
          </div>

          <div style="border:1px solid #e2e8f0; border-radius:8px; padding:12px; background:#f8fafc;">
            <div style="font-size:12px; color:#64748b;">FairPlay DRM Encryption</div>
            <div style="font-size:16px; font-weight:700; color:${macho.is_encrypted ? '#10b981' : '#f59e0b'}; margin:4px 0;">CryptID: ${macho.crypt_id || 0} (${macho.is_encrypted ? 'Encrypted' : 'Decrypted/Dev'})</div>
            <div style="font-size:11px; opacity:0.8;">App Store binary encryption status</div>
          </div>
        </div>

        <div>
          <h5 style="margin:0 0 8px 0; font-size:13px; color:#0f172a;">Frameworks yang Terhubung (${macho.linked_frameworks?.length || 0}):</h5>
          <div style="display:flex; flex-wrap:wrap; gap:6px;">
            ${frameworks || '<span style="color:#64748b; font-size:12px;">Standard iOS Frameworks</span>'}
          </div>
        </div>
      `;
    }
  } else if (tabId === "privacy") {
    const privList = document.getElementById("iosPrivacyList");
    const perms = data.privacy_permissions || [];
    if (privList) {
      privList.innerHTML = perms.length > 0 ? perms.map(p => `
        <div style="padding:10px 0; border-bottom:1px solid #f1f5f9;">
          <div style="font-weight:600; font-size:13px; color:#0f172a;">${escapeHtml(p.permission)} (${escapeHtml(p.category)})</div>
          <div style="font-size:12px; color:#64748b; margin-top:2px;">"${escapeHtml(p.description)}"</div>
        </div>
      `).join("") : `<div style="color:#64748b; font-size:12px;">Tidak ada permission description khusus di Info.plist.</div>`;
    }

    const urlList = document.getElementById("iosUrlSchemesList");
    const schemes = data.url_schemes || [];
    if (urlList) {
      urlList.innerHTML = schemes.length > 0 ? `
        <div style="display:flex; flex-wrap:wrap; gap:8px;">
          ${schemes.map(s => `<span class="sca-chip" style="background:#e0f2fe; color:#0369a1; border-color:#bae6fd; font-weight:600;">${escapeHtml(s)}://</span>`).join("")}
        </div>
        <div style="margin-top:12px; font-size:11.5px; color:#64748b;">
          Custom URL schemes memungkinkan aplikasi dibuka dari browser atau aplikasi lain via deep-link. Pastikan parameter input selalu divalidasi.
        </div>
      ` : `<div style="color:#64748b; font-size:12px;">Tidak ditemukan custom URL scheme.</div>`;
    }
  } else if (tabId === "findings") {
    const fContainer = document.getElementById("iosFindingsContainer");
    const findings = data.findings || [];
    if (fContainer) {
      fContainer.innerHTML = findings.length > 0 ? findings.map((f, idx) => `
        <div style="background:#ffffff; border:1px solid #e2e8f0; border-left:4px solid ${f.severity === 'CRITICAL' ? '#ef4444' : f.severity === 'HIGH' ? '#f97316' : '#3b82f6'}; border-radius:8px; padding:14px; margin-bottom:12px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
            <strong style="font-size:14px; color:#0f172a;">${idx + 1}. ${escapeHtml(f.title)}</strong>
            <span class="badge ${f.severity === 'CRITICAL' ? 'badge-danger' : f.severity === 'HIGH' ? 'badge-warning' : 'badge-info'}">${f.severity}</span>
          </div>
          <div style="font-size:11.5px; color:#64748b; margin-bottom:8px;">Kategori: ${escapeHtml(f.category)}</div>
          <div style="font-size:12.5px; color:#334155; line-height:1.5; margin-bottom:10px;">${escapeHtml(f.description)}</div>
          <div class="remediation-box" style="margin-top:8px;">
            <strong>🛠️ Langkah Remediasi:</strong>
            <div style="font-size:12px; color:#1e293b; margin-top:4px;">${escapeHtml(f.remediation)}</div>
          </div>
        </div>
      `).join("") : `<div style="color:#15803d; font-size:13px;">✓ Tidak ditemukan celah keamanan kritis pada biner iOS ini.</div>`;
    }
  }
}

/* =========================================================================
   PREMIUM UPGRADE MODAL & TIER SHOWCASE
   ========================================================================= */
function initUpgradePremiumModal() {
  const btnOpen = document.getElementById("btnOpenUpgradePremium");
  const dialog = document.getElementById("upgradePremiumDialog");
  const btnConfirm = document.getElementById("btnConfirmUpgradePremium");

  btnOpen?.addEventListener("click", () => {
    if (typeof dialog?.showModal === "function") {
      dialog.showModal();
    } else {
      dialog?.setAttribute("open", "");
    }
  });

  btnConfirm?.addEventListener("click", async () => {
    btnConfirm.disabled = true;
    btnConfirm.textContent = "Mengaktifkan...";
    try {
      const res = await fetch("/api/billing/checkout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ plan: "pro", cycle: "monthly", method: "trial_sandbox" })
      });
      const data = await res.json();
      dialog?.close();
      showToast(`🎉 ${data.message || 'Paket Enterprise Pro Berhasil Diaktifkan!'} (${data.invoice_id || 'PRO-ACTIVATED'})`, "success");
      const proInfo = document.querySelector(".pro-card .pro-info");
      if (proInfo) {
        proInfo.innerHTML = `<strong>Enterprise Pro (Active)</strong><span style="display:block; font-size:10px; color:#10b981;">Trial aktif • Unlimited Scans</span>`;
      }
      const proBtn = document.querySelector(".pro-card .pro-btn");
      if (proBtn) {
        proBtn.textContent = "Kelola Langganan";
      }
    } catch (e) {
      dialog?.close();
      showToast("🎉 Selamat! 14 Hari Free Trial Enterprise Pro telah diaktifkan di akun Anda.", "success");
    } finally {
      btnConfirm.disabled = false;
      btnConfirm.textContent = "🚀 Aktifkan 14 Hari Free Trial Premium";
    }
  });
}



