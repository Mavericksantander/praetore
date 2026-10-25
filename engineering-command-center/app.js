(() => {
  "use strict";

  const data = window.PRAETORE_DASHBOARD_DATA;
  if (!data) {
    document.body.innerHTML = '<main><h1>Dashboard data unavailable</h1><p>Run <code>python3 engineering-command-center/refresh_dashboard.py</code> from the repository root.</p></main>';
    return;
  }

  const statusLabels = {
    verified: "Verified scope",
    implemented_unvalidated: "Implemented · needs validation",
    partial: "Partial",
    missing: "Missing",
    blocked: "Blocked",
    unknown: "Unknown",
    needs_validation: "Needs validation",
    in_progress_inferred: "In progress · inferred",
    ready: "Ready to implement",
    not_run: "Not run",
    unavailable: "Unavailable",
    outstanding: "Outstanding",
    passed: "Passed",
    failed: "Failed"
  };
  const statusColors = {
    verified: "#6dd8a3",
    implemented_unvalidated: "#f0bd68",
    partial: "#81b9f4",
    missing: "#ef8585",
    blocked: "#ef8585",
    unknown: "#9aa8b3"
  };
  const byId = (id) => document.getElementById(id);
  const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
  const labelStatus = (status) => statusLabels[status] || String(status || "Unknown").replaceAll("_", " ");
  const chip = (status) => `<span class="status-chip status-${escapeHtml(status)}">${escapeHtml(labelStatus(status))}</span>`;
  const repoLink = (path) => `<a href="../${escapeHtml(path)}" target="_blank" rel="noopener">${escapeHtml(path)}</a>`;
  const evidenceLinks = (items = []) => items.map((path) => `<a class="evidence-link" href="../${escapeHtml(path)}" target="_blank" rel="noopener">${escapeHtml(path)}</a>`).join("");
  const listOrEmpty = (items) => items && items.length ? items.map((item) => `<li>${escapeHtml(item)}</li>`).join("") : "<li>None listed</li>";

  function renderHeader() {
    const discovered = data.discovered || {};
    const project = data.project || {};
    const revision = discovered.revision || "revision unavailable";
    byId("revision-label").textContent = `${discovered.branch || "branch unknown"} · ${revision}`;
    const changed = Number(discovered.worktree?.changedFiles || 0);
    const worktree = byId("worktree-label");
    if (!discovered.worktree?.available || discovered.worktree.changedFiles == null) {
      worktree.textContent = "WORKTREE UNKNOWN";
      worktree.className = "pill";
    } else {
      worktree.textContent = changed ? `DIRTY · ${changed} files` : "CLEAN WORKTREE";
      worktree.className = changed ? "pill" : "pill clean-pill";
    }
    byId("maturity-label").textContent = project.maturity || "Assessment unavailable";
    byId("maturity-basis").textContent = project.maturityBasis || "";
    byId("focus-label").textContent = project.workFocus?.label || "No declared work focus";
    byId("focus-basis").textContent = project.workFocus?.basis || "No current development signal is recorded.";
    byId("focus-confidence").textContent = project.workFocus?.confidence === "inferred" ? "INFERRED FROM WORKTREE" : "MAINTAINED PROJECT STATUS";
    const refreshed = discovered.lastRefreshed;
    const date = refreshed ? new Date(refreshed) : null;
    const display = date && !Number.isNaN(date.valueOf()) ? date.toLocaleString() : "Refresh not recorded";
    byId("refreshed-date").textContent = date && !Number.isNaN(date.valueOf()) ? date.toLocaleDateString() : "SNAPSHOT";
    byId("footer-refresh").textContent = `Data refreshed ${display}`;
  }

  function renderOverview() {
    const assessments = data.assessments || [];
    const counts = assessments.reduce((result, item) => {
      result[item.status] = (result[item.status] || 0) + 1;
      return result;
    }, {});
    byId("assessment-total").textContent = String(assessments.length).padStart(2, "0");
    byId("count-verified").textContent = counts.verified || 0;
    byId("count-validation").textContent = counts.implemented_unvalidated || 0;
    const legendOrder = ["verified", "implemented_unvalidated", "partial", "missing", "blocked", "unknown"];
    byId("assessment-bar").innerHTML = legendOrder.filter((status) => counts[status]).map((status) =>
      `<span class="stacked-segment" style="width:${(counts[status] / Math.max(assessments.length, 1)) * 100}%;background:${statusColors[status]}" title="${escapeHtml(labelStatus(status))}: ${counts[status]}"></span>`
    ).join("");
    byId("assessment-legend").innerHTML = legendOrder.filter((status) => counts[status]).map((status) =>
      `<span class="legend-item" style="--legend-color:${statusColors[status]}">${escapeHtml(labelStatus(status))} ${counts[status]}</span>`
    ).join("");

    const priorities = (data.board || []).filter((task) => task.priority === 1 && task.status !== "done");
    byId("blocker-count").textContent = String(priorities.length).padStart(2, "0");
    const top = [...priorities].sort((a, b) => a.priority - b.priority).slice(0, 3);
    byId("top-blockers").innerHTML = top.map((task, index) => `
      <article class="blocker-card"><span class="blocker-index">0${index + 1}</span><div>
        <strong>${escapeHtml(task.title)}</strong>
        <p>${escapeHtml(task.description)}</p>
      </div></article>`).join("");

    const current = data.verification?.currentWorktree || {};
    byId("overview-test-dot").className = `status-dot ${current.status === "passed" ? "green" : current.status === "failed" ? "red" : "amber"}`;
    byId("overview-test-result").textContent = current.summary || labelStatus(current.status || "unknown");
    byId("overview-test-time").textContent = current.checkedAt ? new Date(current.checkedAt).toLocaleString() : "No current run recorded";
  }

  function flowNode(item) {
    return `<article class="flow-node status-${escapeHtml(item.status)}" title="${escapeHtml(item.role)}">
      <span class="node-id">${escapeHtml(item.id.toUpperCase())}</span>
      <strong>${escapeHtml(item.name)}</strong>
      <span class="node-status">${escapeHtml(labelStatus(item.status).toUpperCase())}</span>
    </article>`;
  }

  function renderArchitecture() {
    const components = data.architecture || [];
    const request = components.filter((item) => item.stage === "request");
    const decision = components.filter((item) => item.stage === "decision");
    const approval = components.filter((item) => item.stage === "approval");
    const effects = components.filter((item) => item.stage === "effect");
    const evidence = components.filter((item) => item.stage === "evidence");
    byId("request-flow").innerHTML = [...request, ...decision].map(flowNode).join("");
    byId("approval-flow").innerHTML = approval.map(flowNode).join("");
    byId("effect-flow").innerHTML = effects.map(flowNode).join("");
    byId("evidence-flow").innerHTML = evidence.map((item, index) =>
      `${index ? '<span class="evidence-arrow" aria-hidden="true">→</span>' : ""}<div class="evidence-node" title="${escapeHtml(item.role)}">${escapeHtml(item.name)}</div>`
    ).join("");
    byId("architecture-details").innerHTML = components.map((item) => `
      <details class="architecture-detail">
        <summary><span>${escapeHtml(item.name)}</span>${chip(item.status)}</summary>
        <div><p>${escapeHtml(item.role)}</p>
          <p><strong>Dependencies:</strong> ${escapeHtml((item.dependencies || []).join(", ") || "None listed")}</p>
          <p><strong>Limitations:</strong> ${escapeHtml((item.limitations || []).join(" "))}</p>
          <div class="evidence-links">${evidenceLinks(item.evidence)}</div>
        </div>
      </details>`).join("");
  }

  function renderAssessments(filter = "all") {
    const items = (data.assessments || []).filter((item) => filter === "all" || item.status === filter);
    byId("assessment-grid").innerHTML = items.map((item) => `
      <details class="assessment-card">
        <summary><span class="assess-name">${escapeHtml(item.area)}</span>${chip(item.status)}</summary>
        <div class="card-content">
          <p>${escapeHtml(item.summary)}</p>
          <div class="field-label">EVIDENCE</div><div class="evidence-links">${evidenceLinks(item.evidence)}</div>
          <div class="field-label">LIMITATIONS</div><p>${escapeHtml((item.limitations || []).join(" "))}</p>
          <div class="field-label">NEXT ACTION</div><p>${escapeHtml(item.next)}</p>
          <div class="field-label">LAST ASSESSED</div><p>${escapeHtml(item.verifiedOn || "Unknown")} · base revision ${escapeHtml(item.lastVerifiedRevision || "unknown")}${data.discovered?.worktree?.changedFiles ? " · assessment reflects a dirty worktree snapshot" : ""}</p>
        </div>
      </details>`).join("") || '<p class="subtle-note">No matching foundation areas.</p>';
  }

  function componentData() {
    const discovered = data.discovered?.packages || [];
    const manual = new Map((data.components || []).map((item) => [item.id, item]));
    const result = discovered.map((found) => {
      const assessment = manual.get(found.id);
      if (assessment) return { ...found, ...assessment, discovered: found };
      return {
        ...found,
        type: "Discovered repository component",
        purpose: found.description || "Detected in repository metadata; purpose has not been assessed.",
        status: "unknown",
        limitations: "No manually maintained assessment exists yet.",
        next: "Add a purpose, evidence-backed status, limitations and next action to dashboard-data.json.",
        discovered: found
      };
    });
    const discoveredIds = new Set(discovered.map((item) => item.id));
    for (const assessment of data.components || []) {
      if (!discoveredIds.has(assessment.id)) result.push({ ...assessment, discovered: null });
    }
    return result;
  }

  function renderInventory() {
    const all = componentData();
    const search = byId("inventory-search").value.trim().toLowerCase();
    const statusFilter = byId("inventory-status").value;
    const typeFilter = byId("inventory-type").value;
    const items = all.filter((item) => {
      const text = [item.id, item.type, item.path, item.purpose, ...(item.dependencies || [])].join(" ").toLowerCase();
      return (!search || text.includes(search)) &&
        (statusFilter === "all" || item.status === statusFilter) &&
        (typeFilter === "all" || item.type === typeFilter);
    });
    byId("inventory-summary").textContent = `${items.length} of ${all.length} components`;
    byId("inventory-body").innerHTML = items.map((item) => {
      const found = item.discovered || {};
      const testCount = found.rustTestAttributes || 0;
      const testLabel = found.testFiles?.length ? `${found.testFiles.length} test file${found.testFiles.length === 1 ? "" : "s"}` : "No separate test file found";
      return `<tr>
        <td><span class="component-name">${escapeHtml(item.id)}</span><span class="component-path">${escapeHtml(item.path || "Path not discovered")}</span></td>
        <td>${chip(item.status)}</td>
        <td><div class="dep-list">${escapeHtml((found.localDependencies || []).join(", ") || "No local package dependency")}</div></td>
        <td><span class="test-count">${testCount} test annotations discovered</span><span class="test-note">${escapeHtml(testLabel)}</span></td>
        <td><details class="inventory-detail"><summary aria-label="Show ${escapeHtml(item.id)} details"></summary>
          <p>${escapeHtml(item.purpose)}</p>
          <p><strong>Limitations:</strong> ${escapeHtml(item.limitations)}</p>
          <p><strong>Next:</strong> ${escapeHtml(item.next)}</p>
          ${found.description ? `<p><strong>Cargo:</strong> ${escapeHtml(found.description)}</p>` : ""}
          ${found.manifest ? `<p>Manifest: ${repoLink(found.manifest)}</p>` : ""}
        </details></td>
      </tr>`;
    }).join("") || '<tr><td colspan="5" class="empty-row">No components match these filters.</td></tr>';
  }

  function renderSecurity(filter = "all") {
    const controls = data.securityControls || [];
    const visible = controls.filter((control) => filter === "all" || control.status === filter);
    byId("security-list").innerHTML = visible.map((control) => `
      <details class="security-row">
        <summary><span class="security-name">${escapeHtml(control.name)}</span>${chip(control.status)}</summary>
        <div class="security-detail">
          <p><span class="field-label">IMPLEMENTED MECHANISM</span>${escapeHtml(control.mechanism)}</p>
          <p><span class="field-label">EVIDENCE</span>${(control.evidence || []).map(repoLink).join("<br>")}<br><br><span class="field-label">ASSUMPTIONS / LIMITATIONS</span>${escapeHtml(control.assumptions)}</p>
        </div>
      </details>`).join("");
  }

  function renderReadiness() {
    byId("readiness-grid").innerHTML = (data.readiness || []).map((item) => `
      <article class="readiness-item">
        <strong>${escapeHtml(item.item)}</strong>${chip(item.status)}
        <p>${escapeHtml(item.detail)}</p>
        <p class="next-action"><strong>Next:</strong> ${escapeHtml(item.next)}</p>
      </article>`).join("");
  }

  function renderBoard() {
    const category = byId("board-category").value;
    const status = byId("board-status").value;
    const tasks = [...(data.board || [])].sort((a, b) => a.priority - b.priority || a.title.localeCompare(b.title));
    const visible = tasks.filter((task) =>
      (category === "all" || task.category === category) &&
      (status === "all" || task.status === status)
    );
    byId("board-count").textContent = `${visible.length} tasks`;
    byId("board-grid").innerHTML = visible.map((task) => `
      <details class="board-card priority-${task.priority}">
        <summary>
          <div class="board-meta"><span class="priority-tag">P${task.priority}</span><span class="category-tag">${escapeHtml(task.category.toUpperCase())}</span>${chip(task.status)}</div>
          <h3>${escapeHtml(task.title)}</h3>
        </summary>
        <div class="board-detail">
          <p>${escapeHtml(task.description)}</p>
          <p><strong>Why it matters:</strong> ${escapeHtml(task.why)}</p>
          <span class="field-label">DEPENDENCIES</span><ul>${listOrEmpty(task.dependencies)}</ul>
          <span class="field-label">ACCEPTANCE CRITERIA</span><p>${escapeHtml(task.acceptance)}</p>
          <span class="field-label">COMPLETION EVIDENCE</span><ul>${listOrEmpty(task.evidence)}</ul>
        </div>
      </details>`).join("") || '<p class="subtle-note">No tasks match these filters.</p>';
  }

  function renderMilestones() {
    byId("milestones").innerHTML = (data.milestones || []).map((item, index) => `
      <article class="milestone">
        <div class="milestone-marker">${String(index + 1).padStart(2, "0")}</div>
        <div class="milestone-body">
          <h3>${escapeHtml(item.name)}</h3><p>${escapeHtml(item.objective)}</p>
          <div class="milestone-fields">
            <div><strong>PREREQUISITES</strong><ul>${listOrEmpty(item.prerequisites)}</ul></div>
            <div><strong>DEFINITION OF DONE</strong>${escapeHtml(item.done)}</div>
            <div><strong>REQUIRED TESTS / DEMOS</strong><ul>${listOrEmpty(item.tests)}</ul></div>
            <div><strong>REMAINING BLOCKERS</strong>${escapeHtml(item.blockers.join(" "))}</div>
          </div>
          <div class="milestone-blocker"><strong>Gate:</strong> ${escapeHtml(item.blockers.join(" "))}</div>
        </div>
      </article>`).join("");
  }

  function renderVerification() {
    const verification = data.verification || {};
    const current = verification.currentWorktree || {};
    const status = current.status || "unknown";
    byId("verification-stamp").textContent = current.checkedAt ? `Captured ${new Date(current.checkedAt).toLocaleString()}` : "No current result recorded";
    byId("verification-banner").innerHTML = `<span aria-hidden="true">◌</span><div><strong>Local worktree: ${escapeHtml(labelStatus(status))}</strong><p>${escapeHtml(current.result || "No current worktree validation has been recorded.")}${current.command ? `<br><code>${escapeHtml(current.command)}</code>` : ""}</p></div>`;
    const ci = verification.ci || {};
    const items = [
      ...(verification.knownGates || []),
      { kind: "Hosted CI for this snapshot", command: "No live CI connection configured", evidence: ".github/workflows/assurance.yml", status: ci.status, result: ci.result }
    ];
    byId("verification-grid").innerHTML = items.map((item) => `
      <article class="verification-item">
        <strong>${escapeHtml(item.kind)}</strong>${chip(item.status)}
        <code>${escapeHtml(item.command)}</code>
        <span class="result-note">${escapeHtml(item.result || `Configured in ${item.evidence}; this page does not infer a passing result.`)}</span>
      </article>`).join("");
  }

  function addOptions(id, values, firstLabel) {
    const element = byId(id);
    element.innerHTML = `<option value="all">${escapeHtml(firstLabel)}</option>` + values.map((value) =>
      `<option value="${escapeHtml(value)}">${escapeHtml(labelStatus(value))}</option>`
    ).join("");
  }

  function addPlainOptions(id, values, firstLabel) {
    const element = byId(id);
    element.innerHTML = `<option value="all">${escapeHtml(firstLabel)}</option>` + values.map((value) =>
      `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`
    ).join("");
  }

  function setupNavigation() {
    const links = [...document.querySelectorAll(".nav-link")];
    const sections = links.map((link) => document.querySelector(link.getAttribute("href"))).filter(Boolean);
    const updateActive = () => {
      const marker = Math.min(window.innerHeight * 0.28, 240);
      let active = sections[0];
      sections.forEach((section) => {
        if (section.getBoundingClientRect().top <= marker) active = section;
      });
      links.forEach((link) => link.classList.toggle("active", link.getAttribute("href") === `#${active.id}`));
    };
    let frame = 0;
    window.addEventListener("scroll", () => {
      if (frame) return;
      frame = window.requestAnimationFrame(() => {
        frame = 0;
        updateActive();
      });
    }, { passive: true });
    window.addEventListener("hashchange", updateActive);
    links.forEach((link) => link.addEventListener("click", () => {
      document.getElementById("side-nav").classList.remove("nav-open");
      byId("menu-toggle").setAttribute("aria-expanded", "false");
    }));
    updateActive();
  }

  const statusValues = [...new Set((data.assessments || []).map((item) => item.status))];
  addOptions("foundation-filter", statusValues, "All states");
  addOptions("inventory-status", [...new Set((data.components || []).map((item) => item.status))], "All statuses");
  addPlainOptions("inventory-type", [...new Set((data.components || []).map((item) => item.type))], "All types");
  addOptions("security-filter", [...new Set((data.securityControls || []).map((item) => item.status))], "All controls");
  addPlainOptions("board-category", [...new Set((data.board || []).map((item) => item.category))], "All categories");
  addOptions("board-status", [...new Set((data.board || []).map((item) => item.status))], "All statuses");

  byId("foundation-filter").addEventListener("change", (event) => renderAssessments(event.target.value));
  byId("inventory-search").addEventListener("input", renderInventory);
  byId("inventory-status").addEventListener("change", renderInventory);
  byId("inventory-type").addEventListener("change", renderInventory);
  byId("security-filter").addEventListener("change", (event) => renderSecurity(event.target.value));
  byId("board-category").addEventListener("change", renderBoard);
  byId("board-status").addEventListener("change", renderBoard);

  renderHeader();
  renderOverview();
  renderArchitecture();
  renderAssessments();
  renderInventory();
  renderSecurity();
  renderReadiness();
  renderBoard();
  renderMilestones();
  renderVerification();
  setupNavigation();
})();
