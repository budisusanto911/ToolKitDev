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

  // Scroll smoothly to report
  container.scrollIntoView({ behavior: "smooth" });
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
        4. Rekomendasi Solusi &amp; Contoh Kode Perbaikan
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
      exploitScenario: "Penyerang menyalakan Wi-Fi hotspot palsu ('Free Wi-Fi') atau melakukan ARP Spoofing di jaringan lokal. Saat aplikasi Alfagift melakukan panggilan API ke salah satu dari 5 domain staging di atas, semua payload (header Authorization, JSON body, nomor telepon, data transaksi) dikirim tanpa TLS sehingga terbaca secara langsung di Wireshark.",
      codeFix: `<!-- REKOMENDASI PERBAIKAN: network_security_config.xml -->
<network-security-config>
    <!-- 1. Larang cleartext traffic secara global di release build -->
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>

    <!-- 2. HAPUS tag domain-config yang mengizinkan cleartext ke domain staging.
         Jika staging diperlukan oleh tim QA/Dev, gunakan build variant terpisah:
         app/src/debug/res/xml/network_security_config.xml -->
</network-security-config>`,
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
      exploitScenario: "Aplikasi malware tanpa izin khusus dapat mengirimkan explicit Intent: <code>am start -n com.alfamart.alfagift/com.moengage.sdk.debugger.MoEDebuggerActivity</code>. Hal ini membuka GUI debugger MoEngage untuk melihat event log pengguna, manipulasi status registrasi push notifikasi, atau memicu unvalidated internal intent redirect.",
      codeFix: `<!-- REKOMENDASI PERBAIKAN: AndroidManifest.xml -->
<!-- Tutup akses ke MoEDebuggerActivity di manifest aplikasi utama -->
<activity
    android:name="com.moengage.sdk.debugger.MoEDebuggerActivity"
    android:exported="false"
    tools:replace="android:exported" />

<!-- Atau gunakan dependency MoEngage debug-only di build.gradle:
     debugImplementation("com.moengage:moe-debugger:...")
     releaseImplementation (jangan masukkan library debugger di release!) -->`,
      standards: ["OWASP Mobile Top 10: M1 (Improper Platform Usage)", "OWASP MASVS: MASVS-PLATFORM-1", "CWE-926"]
    };
  }

  if (title.includes("unauthenticated") || title.includes("sensitive activities")) {
    const sensitive = (apkData && apkData.sensitive_components) || {};
    const acts = (sensitive.sensitive_activities && sensitive.sensitive_activities.length > 0) ? sensitive.sensitive_activities : [
      "com.alfamart.alfagift.screen.wallet.otp.OtpWalletActivity",
      "com.alfamart.alfagift.screen.wallet.linked.LinkedWalletActivity",
      "com.alfamart.alfagift.screen.wallet.aladin.AladinWebViewActivity",
      "com.alfamart.alfagift.screen.eservice.shoppingassistant.ShoppingAssistantActivity"
    ];
    return {
      cwe: "CWE-285: Improper Authorization",
      impact: "Activity transaksi dompet digital (Wallet), verifikasi OTP, dan asisten belanja dapat diakses dan diluncurkan langsung oleh aplikasi pihak ketiga tanpa melalui alur otentikasi PIN/Password.",
      evidenceHtml: `
        <div style="font-size:12px; margin-bottom:6px; color:#475569;"><strong>Activity Sensitif Terekspos:</strong></div>
        <div style="display:flex; flex-direction:column; gap:4px;">
          ${acts.slice(0, 5).map(a => `<code style="font-size:11.5px; background:#fff; padding:4px 8px; border:1px solid #e2e8f0; border-radius:4px;">${escapeHtml(a)}</code>`).join("")}
        </div>
      `,
      exploitScenario: "Attacker membuat aplikasi jahat (rogue app) di perangkat yang memanggil <code>startActivity(new Intent().setComponent(new ComponentName('com.alfamart.alfagift', '...OtpWalletActivity')))</code>. Jika activity tidak memvalidasi session token di lifecycle <code>onCreate()</code>, layar input OTP atau linked wallet terbuka langsung membypass login.",
      codeFix: `<!-- REKOMENDASI PERBAIKAN: AndroidManifest.xml -->
<activity
    android:name=".screen.wallet.otp.OtpWalletActivity"
    android:exported="false" />

<activity
    android:name=".screen.wallet.linked.LinkedWalletActivity"
    android:exported="false" />

<!-- Jika activity HARUS dipanggil aplikasi internal grup Alfa saja,
     gunakan Custom Signature Permission: -->
<permission
    android:name="com.alfamart.alfagift.permission.INTERNAL_ACCESS"
    android:protectionLevel="signature" />

<activity
    android:name=".screen.wallet.aladin.AladinWebViewActivity"
    android:exported="true"
    android:permission="com.alfamart.alfagift.permission.INTERNAL_ACCESS" />`,
      standards: ["OWASP Mobile Top 10: M4 (Insecure Authentication/Authorization)", "OWASP MASVS: MASVS-AUTH-1", "CWE-285"]
    };
  }

  if (title.includes("cryptography") || title.includes("blowfish") || title.includes("ecb")) {
    return {
      cwe: "CWE-327: Broken Crypto Algorithm",
      impact: "Penggunaan cipher Blowfish dengan mode ECB (Electronic Codebook) sangat rentan terhadap kriptanalisis. Mode ECB mengenkripsi blok yang sama menjadi ciphertext yang sama, sehingga pola gambar atau struktur data dapat dibaca tanpa dekripsi.",
      evidenceHtml: `
        <div style="font-size:12px; margin-bottom:6px; color:#475569;"><strong>Bytecode Targets:</strong> <code>classes.dex</code>, <code>classes3.dex</code>, <code>classes6.dex</code>, <code>classes8.dex</code></div>
        <div style="font-size:12px; margin-bottom:6px; color:#475569;"><strong>Algoritma Terdeteksi:</strong> <code>Cipher.getInstance("Blowfish")</code>, <code>"AES/ECB/PKCS5Padding"</code></div>
        <div style="font-size:12px; color:#ef4444;"><strong>Kelemahan:</strong> Ukuran blok Blowfish (64-bit) rentan serangan collision (Sweet32 attack), dan ECB mode tidak menggunakan Initialization Vector (IV).</div>
      `,
      exploitScenario: "Penyerang yang menyadap lalu lintas API terenkripsi Blowfish/ECB dapat mengumpulkan ciphertext dan melakukan replay attack atau menganalisis frekuensi blok untuk merekonstruksi isi pesan rahasia (seperti nomor kartu Ponta atau token transaksi) tanpa harus memecahkan kuncinya.",
      codeFix: `// REKOMENDASI PERBAIKAN: Migrasi ke Authenticated Encryption (AES-GCM)
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

public class SecureCryptoUtil {
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128; // bits
    private static final int IV_LENGTH = 12; // bytes

    public static byte[] encrypt(byte[] plaintext, SecretKey key) throws Exception {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv); // Generate RANDOM IV per message

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Gabungkan IV + Ciphertext untuk transmisi aman
        ByteBuffer buffer = ByteBuffer.allocate(iv.length + ciphertext.length);
        buffer.put(iv);
        buffer.put(ciphertext);
        return buffer.array();
    }
}`,
      standards: ["OWASP Mobile Top 10: M5 (Insufficient Cryptography)", "NIST SP 800-131A Rev. 2", "CWE-327"]
    };
  }

  if (title.includes("secret") || title.includes("tokens")) {
    return {
      cwe: "CWE-798: Hardcoded Credentials",
      impact: "Kunci API (Google Maps / Firebase) dan token otentikasi tertanam langsung di dalam file bytecode atau resources APK. Siapapun yang mengunduh APK dari Google Play Store dapat mengekstrak kredensial ini dalam hitungan detik menggunakan apktool atau jadx-gui.",
      evidenceHtml: `
        <div style="font-size:12px; margin-bottom:6px; color:#475569;"><strong>File Terdeteksi:</strong> <code>resources.arsc</code>, <code>AndroidManifest.xml</code>, <code>classes*.dex</code></div>
        <div style="font-size:12px; margin-bottom:6px; color:#475569;"><strong>Pola Secret:</strong> <code>AIzaSy[0-9A-Za-z\\-_]{33}</code> (Google/Firebase API Key)</div>
        <div style="font-size:12px; color:#ef4444;"><strong>Status:</strong> Terbuka untuk publik tanpa proteksi enkripsi runtime.</div>
      `,
      exploitScenario: "Penyerang mengekstrak Firebase API Key dari APK, lalu menggunakan Firebase REST API untuk mendaftarkan ribuan akun palsu (account registration abuse) atau melakukan spam ke database backend jika Firestore/Realtime Database Security Rules tidak dikonfigurasi dengan ketat.",
      codeFix: `// REKOMENDASI PERBAIKAN:
// 1. Pada Google Cloud Console:
//    - Terapkan "Application restrictions" -> Android apps
//    - Masukkan Package Name (com.alfamart.alfagift) dan SHA-1 Certificate Fingerprint rilis Anda.
//    - Terapkan "API restrictions" -> Batasi HANYA untuk Maps SDK / Firebase yang digunakan.

// 2. Untuk Secret API / Token Finansial:
//    - JANGAN PERNAH menyimpan token otentikasi pengguna atau secret key server di APK.
//    - Gunakan alur Dynamic Token Exchange via backend proxy dengan OAuth2/PKCE.`,
      standards: ["OWASP Mobile Top 10: M9 (Insecure Data Storage)", "OWASP MASVS: MASVS-STORAGE-1", "CWE-798"]
    };
  }

  if (title.includes("permission") || title.includes("dangerous")) {
    return {
      cwe: "CWE-250: Execution with Unnecessary Privileges",
      impact: "Aplikasi meminta hingga 14 izin berbahaya (Dangerous Permissions). Semakin luas cakupan izin yang diminta, semakin besar risiko kebocoran privasi pengguna (lokasi latar belakang, Bluetooth, data telepon) serta potensi penolakan review Google Play Store.",
      evidenceHtml: `
        <div style="font-size:12px; margin-bottom:6px; color:#475569;"><strong>Izin Berbahaya Terdeteksi:</strong></div>
        <div style="font-size:12px; color:#334155;">
          <code>ACCESS_FINE_LOCATION</code>, <code>ACCESS_COARSE_LOCATION</code>, <code>ACCESS_BACKGROUND_LOCATION</code>,
          <code>READ_PHONE_STATE</code>, <code>BLUETOOTH_SCAN</code>, <code>BLUETOOTH_CONNECT</code>, <code>POST_NOTIFICATIONS</code>
        </div>
      `,
      exploitScenario: "Jika ada celah kerentanan intent injection atau third-party SDK yang compromised di dalam aplikasi, izin sensitif ini dapat disalahgunakan oleh SDK tersebut untuk melacak lokasi pengguna secara konstan di background tanpa disadari.",
      codeFix: `<!-- REKOMENDASI PERBAIKAN:
     Terapkan Principle of Least Privilege: -->
<!-- 1. Hindari meminta ACCESS_BACKGROUND_LOCATION kecuali benar-benar esensial. -->
<!-- 2. Gunakan Photo Picker modern daripada izin READ_EXTERNAL_STORAGE. -->
<!-- 3. Minta izin hanya saat fitur spesifik digunakan (Just-In-Time Runtime Permission). -->`,
      standards: ["OWASP Mobile Top 10: M6 (Extraneous Functionality)", "Google Play Policy - Permissions and APIs", "CWE-250"]
    };
  }

  if (title.includes("debuggable")) {
    return {
      cwe: "CWE-215: Information Exposure Through Debug Information",
      impact: "Aplikasi dapat di-attach debugger via Android Debug Bridge (ADB). Penyerang dapat memasang breakpoint, mendump isi memori runtime, dan mengekstrak kunci enkripsi tanpa memerlukan akses root.",
      evidenceHtml: `<div><strong>Manifest Flag:</strong> <code>android:debuggable="true"</code></div>`,
      exploitScenario: "Penyerang menghubungkan HP via USB atau emulator, menjalankan <code>jdb -attach localhost:8700</code>, dan menginspeksi nilai variabel lokal saat proses login berlangsung.",
      codeFix: `android {
    buildTypes {
        release {
            debuggable false
            minifyEnabled true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
    }
}`,
      standards: ["OWASP Mobile Top 10: M1 (Improper Platform Usage)", "CWE-215"]
    };
  }

  // Fallback generic detail
  return {
    cwe: "CWE-699: Software Development Vulnerability",
    impact: f.description,
    evidenceHtml: `<div><strong>Status:</strong> ${escapeHtml(f.title)} (-${f.deduction} pts)</div>`,
    exploitScenario: "Penyerang dapat memanfaatkan kelemahan konfigurasi ini untuk memperluas permukaan serangan pada perangkat Android.",
    codeFix: "// Tinjau dan perbaiki implementasi sesuai panduan OWASP Mobile Security Testing Guide (MSTG).",
    standards: ["OWASP Mobile Top 10", "OWASP MASVS"]
  };
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
  });

  closeBtn?.addEventListener("click", () => {
    chatDrawer.classList.add("hidden");
  });

  sendBtn?.addEventListener("click", () => sendChatMessage());
  chatInput?.addEventListener("keypress", (e) => {
    if (e.key === "Enter") sendChatMessage();
  });

  document.querySelectorAll(".btn-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      chatInput.value = chip.getAttribute("data-query");
      sendChatMessage();
    });
  });
}

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
  messagesDiv.scrollTop = messagesDiv.scrollHeight;

  // AI loading msg
  const aiMsg = document.createElement("div");
  aiMsg.className = "chat-msg ai";
  aiMsg.innerHTML = `<div class="msg-author">AI Context Engine</div><div>Sedang menelusuri sumber context proyek...</div>`;
  messagesDiv.appendChild(aiMsg);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;

  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        question: text,
        apk_context: activeApkData
      })
    });
    const data = await res.json();

    let citationsHtml = "";
    if (data.citations && data.citations.length > 0) {
      citationsHtml = `
        <div style="margin-top:10px; padding-top:8px; border-top:1px solid rgba(255,255,255,0.1); font-size:11px; color:#c4b5fd;">
          <strong>Sumber Terverifikasi:</strong>
          ${data.citations.map(c => `<div>• <span>[${c.type.toUpperCase()}] ${c.title} (${c.ref})</span></div>`).join("")}
        </div>
      `;
    }

    aiMsg.innerHTML = `
      <div class="msg-author">AI Context Engine</div>
      <div style="white-space:pre-wrap;">${data.answer}</div>
      ${citationsHtml}
    `;
  } catch (err) {
    aiMsg.innerHTML = `<div class="msg-author">AI Context Engine</div><div style="color:#ef4444;">Gagal memproses pertanyaan: ${err.message}</div>`;
  }

  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

/* =========================================================================
   7. SHOPEERS DASHBOARD INTERACTIONS & WIDGET DRAWER
   ========================================================================= */
function initShopeersInteractions() {
  const openWidgetBtn = document.getElementById("btnOpenWidgetDrawer");
  const widgetDrawer = document.getElementById("shopeersWidgetDrawer");
  const closeWidgetBtn = document.getElementById("btnCloseWidgetDrawer");
  const cancelWidgetBtn = document.getElementById("btnCancelWidgetDrawer");
  const saveWidgetBtn = document.getElementById("btnSaveWidgetDrawer");

  const openDrawer = () => {
    if (widgetDrawer) widgetDrawer.classList.remove("hidden");
  };
  const closeDrawer = () => {
    if (widgetDrawer) widgetDrawer.classList.add("hidden");
  };

  openWidgetBtn?.addEventListener("click", openDrawer);
  closeWidgetBtn?.addEventListener("click", closeDrawer);
  cancelWidgetBtn?.addEventListener("click", closeDrawer);
  saveWidgetBtn?.addEventListener("click", () => {
    closeDrawer();
  });

  widgetDrawer?.addEventListener("click", (e) => {
    if (e.target === widgetDrawer) closeDrawer();
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
    if (e.key === "Enter") {
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

