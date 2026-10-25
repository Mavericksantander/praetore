"use strict";

(() => {
  const tokenInput = document.getElementById("token");
  const connectButton = document.getElementById("connect");
  const authState = document.getElementById("auth-state");
  const notice = document.getElementById("notice");
  const body = document.getElementById("operations-body");
  const detail = document.getElementById("detail");
  const limit = 25;
  let bearer = "";
  let offset = 0;
  let total = 0;
  let currentFilters = {};

  const text = (value) => String(value ?? "");
  const setNotice = (message, bad = false) => {
    notice.textContent = message;
    notice.classList.toggle("bad", bad);
  };

  async function api(path) {
    const response = await fetch(path, {
      headers: { Authorization: `Bearer ${bearer}`, Accept: "application/json" },
      cache: "no-store",
    });
    if (!response.ok) {
      const result = await response.json().catch(() => ({}));
      const error = new Error(result.error || `request_failed_${response.status}`);
      error.payload = result;
      throw error;
    }
    return response.json();
  }

  function stateCell(value) {
    const span = document.createElement("span");
    span.className = `badge state-${value}`;
    span.textContent = value.replaceAll("_", " ");
    return span;
  }

  function renderOperations(page) {
    total = page.total;
    body.replaceChildren();
    if (page.operations.length === 0) {
      const row = document.createElement("tr");
      const cell = document.createElement("td");
      cell.colSpan = 7;
      cell.className = "empty";
      cell.textContent = "No operations match these filters.";
      row.append(cell);
      body.append(row);
    }
    for (const operation of page.operations) {
      const row = document.createElement("tr");
      row.tabIndex = 0;
      row.className = "operation-row";
      row.addEventListener("click", () => loadDetail(operation.tenant_id, operation.agent_id, operation.request_id));
      row.addEventListener("keydown", (event) => {
        if (event.key === "Enter") loadDetail(operation.tenant_id, operation.agent_id, operation.request_id);
      });
      const values = [
        operation.created_at,
        operation.tenant_id,
        operation.agent_id,
        `${operation.action_type}${operation.capability ? ` · ${operation.capability}` : ""}`,
        operation.decision,
      ];
      for (const value of values) {
        const cell = document.createElement("td");
        cell.textContent = text(value);
        row.append(cell);
      }
      const execution = document.createElement("td");
      execution.append(stateCell(operation.execution_state));
      row.append(execution);
      const evidence = document.createElement("td");
      evidence.textContent = `${operation.evidence_integrity} / ${operation.attester_signature}`;
      row.append(evidence);
      body.append(row);
    }
    document.getElementById("page-label").textContent =
      `${total ? offset + 1 : 0}–${Math.min(offset + limit, total)} of ${total}`;
    document.getElementById("prev").disabled = offset === 0;
    document.getElementById("next").disabled = offset + limit >= total;
  }

  async function loadOperations() {
    if (!bearer) return;
    const parameters = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    for (const [key, value] of Object.entries(currentFilters)) {
      if (value) parameters.set(key, value);
    }
    try {
      const page = await api(`/api/v1/operations?${parameters}`);
      renderOperations(page);
      setNotice("Journal query complete. Results are read-only snapshots.");
    } catch (error) {
      setNotice(`Operations unavailable: ${text(error.message)}`, true);
    }
  }

  function field(label, value) {
    const element = document.createElement("div");
    element.className = "detail-field";
    const heading = document.createElement("span");
    heading.textContent = label;
    const content = document.createElement("strong");
    content.textContent = text(value);
    element.append(heading, content);
    return element;
  }

  async function loadDetail(tenant, agent, request) {
    try {
      const result = await api(`/api/v1/operations/${encodeURIComponent(tenant)}/${encodeURIComponent(agent)}/${encodeURIComponent(request)}`);
      const operation = result.operation;
      detail.replaceChildren();
      detail.classList.remove("hidden");
      const title = document.createElement("h2");
      title.textContent = "Operation detail";
      const grid = document.createElement("div");
      grid.className = "detail-grid";
      [
        ["Tenant", operation.tenant_id],
        ["Agent", operation.agent_id],
        ["Request", operation.request_id],
        ["Action", operation.action_type],
        ["Capability", operation.capability || "not recorded"],
        ["Decision", operation.decision],
        ["Execution", operation.execution_state],
        ["Action digest", operation.action_digest],
        ["Request digest", operation.request_digest],
        ["Evidence integrity", operation.evidence_integrity],
        ["Attester signature", operation.attester_signature],
        ["Agent intent signature", operation.agent_intent_signature],
        ["Authority signature", operation.authority_signature],
        ["Policy digest", result.policy_digest || "not recorded"],
        ["Policy semantics", result.policy_semantics_version ?? "not recorded"],
        ["Adapter output", result.adapter_output],
        ["Execution interpretation", result.execution_interpretation],
        ["History", result.transition_history],
        ["Current authorization", result.current_authorization ? "yes" : "no"],
      ].forEach(([label, value]) => grid.append(field(label, value)));
      const warning = document.createElement("p");
      warning.className = "redaction-note";
      warning.textContent = "Target, parameters, context, policy-supplied rationale, and stored adapter output are redacted.";
      const history = document.createElement("ol");
      history.className = "timeline";
      for (const transition of result.transitions) {
        const item = document.createElement("li");
        const edge = document.createElement("span");
        edge.textContent = `${transition.from || "start"} →`;
        item.append(edge);
        item.append(stateCell(transition.to));
        const timestamp = document.createElement("time");
        timestamp.textContent = transition.occurred_at;
        item.append(timestamp);
        history.append(item);
      }
      detail.append(title, grid, warning, history);
      detail.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
      setNotice(`Operation detail unavailable: ${text(error.message)}`, true);
    }
  }

  async function loadHealth() {
    try {
      const health = await api("/api/v1/health");
      renderCards("health-cards", [
        ["PostgreSQL", health.database],
        ["Adapter telemetry", health.adapter_telemetry],
        ["Journal error telemetry", health.journal_error_telemetry],
      ]);
    } catch (error) {
      const health = error.payload;
      if (health) {
        renderCards("health-cards", [
          ["PostgreSQL", health.database],
          ["Adapter telemetry", health.adapter_telemetry],
          ["Journal error telemetry", health.journal_error_telemetry],
        ]);
      } else {
        renderCards("health-cards", [["Service probe", text(error.message)]]);
      }
      setNotice("Health probe failed; unavailable is not healthy.", true);
    }
  }

  async function loadAssurance() {
    try {
      const assurance = await api("/api/v1/assurance");
      renderCards("assurance-cards", Object.entries(assurance).map(([key, value]) => [
        key.replaceAll("_", " "),
        value,
      ]));
    } catch (error) {
      setNotice(`Assurance data unavailable: ${text(error.message)}`, true);
    }
  }

  function renderCards(id, values) {
    const container = document.getElementById(id);
    container.replaceChildren();
    for (const [label, value] of values) container.append(field(label, value));
  }

  connectButton.addEventListener("click", async () => {
    bearer = tokenInput.value.trim();
    tokenInput.value = "";
    try {
      const health = await api("/api/v1/health");
      authState.textContent = "Authenticated";
      authState.classList.add("good");
      setNotice(`Connected. PostgreSQL: ${health.database}.`);
      await loadOperations();
    } catch (error) {
      bearer = "";
      authState.textContent = "Disconnected";
      authState.classList.remove("good");
      setNotice(`Authentication or service check failed: ${text(error.message)}`, true);
    }
  });

  document.getElementById("filters").addEventListener("submit", (event) => {
    event.preventDefault();
    currentFilters = Object.fromEntries(new FormData(event.currentTarget));
    offset = 0;
    loadOperations();
  });
  document.getElementById("prev").addEventListener("click", () => {
    offset = Math.max(0, offset - limit);
    loadOperations();
  });
  document.getElementById("next").addEventListener("click", () => {
    offset = Math.min(Number.MAX_SAFE_INTEGER, offset + limit);
    loadOperations();
  });
  document.getElementById("refresh-health").addEventListener("click", loadHealth);
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((item) => item.classList.remove("active"));
      tab.classList.add("active");
      document.querySelectorAll(".view").forEach((view) => view.classList.add("hidden"));
      document.getElementById(tab.dataset.view).classList.remove("hidden");
      if (tab.dataset.view === "health") loadHealth();
      if (tab.dataset.view === "assurance") loadAssurance();
    });
  });
})();
