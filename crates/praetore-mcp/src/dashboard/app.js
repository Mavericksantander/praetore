// praetore-mcp dashboard (read-only). Every value from the journal is
// written with textContent, never as HTML.
"use strict";

const I18N = {
  es: {
    title: "PRÆTORE MCP · recibos",
    readonly: "Solo lectura, servido en 127.0.0.1",
    language: "Idioma",
    reload: "Recargar",
    verification: "Verificación (la misma de praetore-mcp verify)",
    verification_short: "Verificación",
    decisions: "Decisiones",
    detail: "Detalle del recibo",
    f_decision: "Decisión",
    f_tool: "Herramienta",
    f_text: "Texto",
    all: "Todas",
    c_local: "Hora local",
    c_utc: "UTC",
    c_server: "Servidor",
    c_tool: "Herramienta",
    c_args: "Argumentos",
    c_decision: "Decisión",
    c_rule: "Regla",
    c_mode: "Modo",
    c_verify: "verify",
    default_deny: "default deny",
    shown: (n, t) => `${n} de ${t}`,
    total: "Total",
    policy: "Política activa",
    policy_error: "No se pudo leer la política",
    verify_ok: "OK",
    verify_fail: "FALLA",
    verify_error: "verify no pudo correr",
    verified_n: (ok, total, failed) => `${ok} de ${total} recibos verificados, ${failed} fallas`,
    checked: "Qué comprueba verify",
    checked_list: (a, i) => [
      "hash de integridad",
      `firma del attester (${a})`,
      "firma del intent del agente",
      `firma de la autoridad contra ${i} a la hora de la decisión`,
      "vínculo de praetore.mode",
      "orden del journal (seq y enlace hash)",
      "journal de aprobaciones: firma del aprobador, vínculo con la llamada retenida, vencimiento, uso único",
    ],
    head: "Journal head",
    head_text: (n, seq, prev, u) => `${n} entradas encadenadas, próximo seq ${seq}, head ${prev} (${u} entradas sin encadenar anteriores)`,
    head_none: (c, u) => `sin head (${c} encadenadas, ${u} sin encadenar)`,
    head_warn: "Guarda este head fuera de esta máquina y pásalo como --expected-head: sin él no se detectan entradas borradas al final del journal.",
    expected_head: (h) => `Comparado con --expected-head ${h}.`,
    failures: "Fallas reportadas por verify",
    approvals: (d, e, h) => `Journal de aprobaciones: ${d} decisiones, ${e} ejecuciones, head ${h}`,
    approvals_none: "Journal de aprobaciones: no hay",
    observe_note: "Un recibo observe registra una decisión que NO se aplicó.",
    warn_allow_all: (rules, n) => `La política tiene una regla que permite todo (${rules}) y hay ${n} recibos en modo enforce: en enforce esa regla deja pasar cualquier llamada que no cubra una regla DENY o REQUIRE_APPROVAL.`,
    note_allow_all: (rules) => `La política tiene una regla que permite todo (${rules}). Por ahora no hay recibos en modo enforce.`,
    signatures: "Firmas",
    sig_agent: "Agente (intent)",
    sig_attester: "Attester",
    sig_authority: "Autoridad",
    key: "Llave",
    result: "Resultado",
    other_checks: "Otras comprobaciones de verify",
    chk_shape: "Forma HighAssurance (v2)",
    chk_authority_subject: "La autoridad nombra al agente",
    chk_audience: "Audiencia praetore-mcp",
    chk_mode: "praetore.mode válido",
    st_ok: "OK",
    st_fail: "FALLA",
    st_not_run: "no se comprobó",
    chain: "Encadenado",
    order_ok: "seq/prev siguen a la entrada anterior",
    unchained: "entrada sin encadenar (versión anterior)",
    path_check: "path_check",
    path_none: "Este recibo no tiene path_check.",
    lexical: "lexical",
    resolved: "resolved",
    status: "status",
    json: "JSON completo de la línea",
    location: "Ubicación",
    approval: "Aprobación",
    unreadable: "Línea ilegible",
    omitted: (b, h) => `(omitidos: ${b} bytes, sha256 ${h})`,
    load_error: "No se pudo cargar /api/state",
    generated: "Leído",
    yes: "sí",
    no: "no",
  },
  en: {
    title: "PRÆTORE MCP · receipts",
    readonly: "Read-only, served on 127.0.0.1",
    language: "Language",
    reload: "Reload",
    verification: "Verification (the same as praetore-mcp verify)",
    verification_short: "Verification",
    decisions: "Decisions",
    detail: "Receipt detail",
    f_decision: "Decision",
    f_tool: "Tool",
    f_text: "Text",
    all: "All",
    c_local: "Local time",
    c_utc: "UTC",
    c_server: "Server",
    c_tool: "Tool",
    c_args: "Arguments",
    c_decision: "Decision",
    c_rule: "Rule",
    c_mode: "Mode",
    c_verify: "verify",
    default_deny: "default deny",
    shown: (n, t) => `${n} of ${t}`,
    total: "Total",
    policy: "Active policy",
    policy_error: "Cannot read the policy",
    verify_ok: "OK",
    verify_fail: "FAIL",
    verify_error: "verify could not run",
    verified_n: (ok, total, failed) => `${ok} of ${total} receipts verified, ${failed} failures`,
    checked: "What verify checks",
    checked_list: (a, i) => [
      "integrity hash",
      `attester signature (${a})`,
      "agent intent signature",
      `authority signature against ${i} at decision time`,
      "praetore.mode binding",
      "journal order (seq and hash link)",
      "approval journal: approver signature, binding to the held call, expiry, single use",
    ],
    head: "Journal head",
    head_text: (n, seq, prev, u) => `${n} chained entries present, next seq ${seq}, head ${prev} (${u} unchained earlier entries)`,
    head_none: (c, u) => `no head (${c} chained, ${u} unchained)`,
    head_warn: "Keep this head outside this machine and pass it as --expected-head: without it, entries removed at the end of the journal are not detected.",
    expected_head: (h) => `Compared with --expected-head ${h}.`,
    failures: "Failures reported by verify",
    approvals: (d, e, h) => `Approval journal: ${d} decision(s), ${e} execution(s), head ${h}`,
    approvals_none: "Approval journal: none",
    observe_note: "An observe receipt records a decision that was NOT enforced.",
    warn_allow_all: (rules, n) => `The policy has an allow-all rule (${rules}) and there are ${n} enforce receipts: in enforce, that rule lets through any call no DENY or REQUIRE_APPROVAL rule covers.`,
    note_allow_all: (rules) => `The policy has an allow-all rule (${rules}). There are no enforce receipts yet.`,
    signatures: "Signatures",
    sig_agent: "Agent (intent)",
    sig_attester: "Attester",
    sig_authority: "Authority",
    key: "Key",
    result: "Result",
    other_checks: "Other verify checks",
    chk_shape: "HighAssurance (v2) shape",
    chk_authority_subject: "Authority names the agent",
    chk_audience: "praetore-mcp audience",
    chk_mode: "valid praetore.mode",
    st_ok: "OK",
    st_fail: "FAIL",
    st_not_run: "not checked",
    chain: "Chain",
    order_ok: "seq/prev follow the previous entry",
    unchained: "unchained entry (earlier version)",
    path_check: "path_check",
    path_none: "This receipt has no path_check.",
    lexical: "lexical",
    resolved: "resolved",
    status: "status",
    json: "Full JSON of the line",
    location: "Location",
    approval: "Approval",
    unreadable: "Unreadable line",
    omitted: (b, h) => `(omitted: ${b} bytes, sha256 ${h})`,
    load_error: "Cannot load /api/state",
    generated: "Read",
    yes: "yes",
    no: "no",
  },
  pt: {
    title: "PRÆTORE MCP · recibos",
    readonly: "Somente leitura, servido em 127.0.0.1",
    language: "Idioma",
    reload: "Recarregar",
    verification: "Verificação (a mesma de praetore-mcp verify)",
    verification_short: "Verificação",
    decisions: "Decisões",
    detail: "Detalhe do recibo",
    f_decision: "Decisão",
    f_tool: "Ferramenta",
    f_text: "Texto",
    all: "Todas",
    c_local: "Hora local",
    c_utc: "UTC",
    c_server: "Servidor",
    c_tool: "Ferramenta",
    c_args: "Argumentos",
    c_decision: "Decisão",
    c_rule: "Regra",
    c_mode: "Modo",
    c_verify: "verify",
    default_deny: "default deny",
    shown: (n, t) => `${n} de ${t}`,
    total: "Total",
    policy: "Política ativa",
    policy_error: "Não foi possível ler a política",
    verify_ok: "OK",
    verify_fail: "FALHA",
    verify_error: "verify não pôde rodar",
    verified_n: (ok, total, failed) => `${ok} de ${total} recibos verificados, ${failed} falhas`,
    checked: "O que o verify confere",
    checked_list: (a, i) => [
      "hash de integridade",
      `assinatura do attester (${a})`,
      "assinatura do intent do agente",
      `assinatura da autoridade contra ${i} na hora da decisão`,
      "vínculo de praetore.mode",
      "ordem do journal (seq e link hash)",
      "journal de aprovações: assinatura do aprovador, vínculo com a chamada retida, expiração, uso único",
    ],
    head: "Journal head",
    head_text: (n, seq, prev, u) => `${n} entradas encadeadas, próximo seq ${seq}, head ${prev} (${u} entradas não encadeadas anteriores)`,
    head_none: (c, u) => `sem head (${c} encadeadas, ${u} não encadeadas)`,
    head_warn: "Guarde este head fora desta máquina e passe-o como --expected-head: sem ele, entradas apagadas no fim do journal não são detectadas.",
    expected_head: (h) => `Comparado com --expected-head ${h}.`,
    failures: "Falhas reportadas pelo verify",
    approvals: (d, e, h) => `Journal de aprovações: ${d} decisões, ${e} execuções, head ${h}`,
    approvals_none: "Journal de aprovações: não há",
    observe_note: "Um recibo observe registra uma decisão que NÃO foi aplicada.",
    warn_allow_all: (rules, n) => `A política tem uma regra que permite tudo (${rules}) e há ${n} recibos em modo enforce: em enforce essa regra deixa passar qualquer chamada que nenhuma regra DENY ou REQUIRE_APPROVAL cubra.`,
    note_allow_all: (rules) => `A política tem uma regra que permite tudo (${rules}). Ainda não há recibos em modo enforce.`,
    signatures: "Assinaturas",
    sig_agent: "Agente (intent)",
    sig_attester: "Attester",
    sig_authority: "Autoridade",
    key: "Chave",
    result: "Resultado",
    other_checks: "Outras verificações do verify",
    chk_shape: "Forma HighAssurance (v2)",
    chk_authority_subject: "A autoridade nomeia o agente",
    chk_audience: "Audiência praetore-mcp",
    chk_mode: "praetore.mode válido",
    st_ok: "OK",
    st_fail: "FALHA",
    st_not_run: "não verificado",
    chain: "Encadeamento",
    order_ok: "seq/prev seguem a entrada anterior",
    unchained: "entrada não encadeada (versão anterior)",
    path_check: "path_check",
    path_none: "Este recibo não tem path_check.",
    lexical: "lexical",
    resolved: "resolved",
    status: "status",
    json: "JSON completo da linha",
    location: "Localização",
    approval: "Aprovação",
    unreadable: "Linha ilegível",
    omitted: (b, h) => `(omitidos: ${b} bytes, sha256 ${h})`,
    load_error: "Não foi possível carregar /api/state",
    generated: "Lido",
    yes: "sim",
    no: "não",
  },
};

let lang = "es";
let state = null;
let selected = null;

function t(key, ...args) {
  const value = (I18N[lang] && I18N[lang][key]) ?? I18N.es[key] ?? key;
  return typeof value === "function" ? value(...args) : value;
}

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") node.className = v;
    else node.setAttribute(k, v);
  }
  for (const child of children) {
    if (child === null || child === undefined) continue;
    node.append(child instanceof Node ? child : String(child));
  }
  return node;
}

function pill(status) {
  const cls = status === "ok" ? "ok" : status === "fail" ? "bad" : "neutral";
  return el("span", { class: `pill ${cls}` }, t(`st_${status}`));
}

function decisionPill(decision) {
  const cls = decision === "ALLOW" ? "ok" : decision === "DENY" ? "bad" : "warn";
  return el("span", { class: `pill ${cls}` }, decision);
}

function utcText(iso) {
  if (!iso) return "-";
  return `${iso.slice(0, 19).replace("T", " ")} UTC`;
}

function localText(iso) {
  if (!iso) return "-";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString(lang, {
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function argsText(args) {
  if (args === null || args === undefined) return "-";
  if (args && args.omitted === true) return t("omitted", args.bytes, args.sha256);
  return JSON.stringify(args);
}

function readStoredLang() {
  try {
    return localStorage.getItem("praetore-mcp-dashboard-lang");
  } catch (_) {
    return null;
  }
}

function storeLang(value) {
  try {
    localStorage.setItem("praetore-mcp-dashboard-lang", value);
  } catch (_) {
    // Storage unavailable: the choice lasts for this page only.
  }
}

function applyStaticText() {
  document.documentElement.lang = lang;
  for (const node of document.querySelectorAll("[data-i18n]")) {
    node.textContent = t(node.getAttribute("data-i18n"));
  }
}

function card(key, value, small) {
  return el("div", { class: "card" },
    el("div", { class: "k" }, key),
    el("div", { class: small ? "v small" : "v" }, value));
}

function renderSummary() {
  const s = state.summary;
  const p = state.policy;
  const v = state.verify;
  const cards = document.getElementById("cards");
  cards.replaceChildren();
  cards.append(card(t("total"), s.total));
  cards.append(card("ALLOW", s.allow));
  cards.append(card("DENY", s.deny));
  cards.append(card("REQUIRE_APPROVAL", s.require_approval));
  const vText = v.status === "ok" ? t("verify_ok") : v.status === "fail" ? t("verify_fail") : t("verify_error");
  const vNode = el("span", { class: `pill ${v.status === "ok" ? "ok" : "bad"}` }, `verify: ${vText}`);
  cards.append(card(t("verification_short"), vNode));
  if (p.status === "ok") {
    cards.append(card(t("policy"),
      el("span", {}, `${p.id} v${p.version}`, el("br"),
        el("span", { class: "mono" }, `digest ${p.digest ?? "-"}`)), true));
  } else {
    cards.append(card(t("policy"), el("span", { class: "mono" }, `${t("policy_error")}: ${p.error}`), true));
  }
  const warning = document.getElementById("policy-warning");
  if (p.status === "ok" && p.allow_all_rules.length > 0) {
    warning.hidden = false;
    warning.className = p.warn_allow_all_enforce ? "banner bad" : "banner warn";
    warning.textContent = p.warn_allow_all_enforce
      ? t("warn_allow_all", p.allow_all_rules.join(", "), s.enforce_receipts)
      : t("note_allow_all", p.allow_all_rules.join(", "));
  } else {
    warning.hidden = true;
  }
}

function renderVerify() {
  const v = state.verify;
  const box = document.getElementById("verify");
  box.replaceChildren();
  if (v.status === "error") {
    box.append(el("p", { class: "banner bad" }, `${t("verify_error")}: ${v.error}`));
    return;
  }
  box.append(el("p", {},
    el("span", { class: `pill ${v.status === "ok" ? "ok" : "bad"}` },
      v.status === "ok" ? t("verify_ok") : t("verify_fail")),
    " ", t("verified_n", v.verified, v.total, v.failed)));
  if (v.failures.length > 0) {
    box.append(el("h3", {}, t("failures")));
    const ul = el("ul", { class: "plain mono" });
    for (const f of v.failures) ul.append(el("li", {}, f));
    box.append(ul);
  }
  box.append(el("h3", {}, t("head")));
  box.append(el("p", { class: "mono" }, v.head
    ? t("head_text", v.chained, v.head.next_seq, v.head.prev, v.unchained)
    : t("head_none", v.chained, v.unchained)));
  box.append(el("p", { class: "banner warn" }, t("head_warn")));
  if (v.expected_head) box.append(el("p", { class: "mono" }, t("expected_head", v.expected_head)));
  box.append(el("p", { class: "mono" }, v.approval.head
    ? t("approvals", v.approval.decisions, v.approval.executions, v.approval.head)
    : t("approvals_none")));
  box.append(el("h3", {}, t("checked")));
  const ul = el("ul", { class: "plain" });
  for (const item of t("checked_list", v.attester_pin, v.issuer_pins)) ul.append(el("li", {}, item));
  box.append(ul);
  box.append(el("p", { class: "muted" }, t("observe_note")));
}

function renderToolFilter() {
  const select = document.getElementById("f-tool");
  const current = select.value;
  const tools = [...new Set(state.receipts.map((r) => r.tool).filter((x) => typeof x === "string"))].sort();
  select.replaceChildren(el("option", { value: "" }, t("all")));
  for (const tool of tools) select.append(el("option", { value: tool }, tool));
  if (tools.includes(current)) select.value = current;
}

function matches(r) {
  const decision = document.getElementById("f-decision").value;
  const tool = document.getElementById("f-tool").value;
  const text = document.getElementById("f-text").value.trim().toLowerCase();
  if (decision && r.decision !== decision) return false;
  if (tool && r.tool !== tool) return false;
  if (text && !r.raw_text.toLowerCase().includes(text)) return false;
  return true;
}

function renderTable() {
  const body = document.querySelector("#table tbody");
  body.replaceChildren();
  const rows = state.receipts.map((r, i) => [r, i]).reverse();
  let shown = 0;
  for (const [r, index] of rows) {
    if (!matches(r)) continue;
    shown += 1;
    const tr = el("tr", {});
    if (index === selected) tr.className = "selected";
    tr.addEventListener("click", () => {
      selected = index;
      if (r.evidence_id) history.replaceState(null, "", `#e=${encodeURIComponent(r.evidence_id)}`);
      renderTable();
      renderDetail();
    });
    if (r.parse_error) {
      tr.append(el("td", { colspan: "10", class: "mono" },
        el("span", { class: "pill bad" }, t("unreadable")), ` ${r.location.file}:${r.location.line}: ${r.parse_error}`));
    } else {
      tr.append(el("td", {}, localText(r.decided_at)));
      tr.append(el("td", { class: "mono" }, utcText(r.decided_at)));
      tr.append(el("td", {}, r.server ?? "-"));
      tr.append(el("td", {}, r.tool ?? "-"));
      const args = argsText(r.arguments);
      tr.append(el("td", { class: "args mono", title: args }, args));
      tr.append(el("td", {}, decisionPill(r.decision)));
      tr.append(el("td", {}, r.rule ?? t("default_deny")));
      tr.append(el("td", {}, r.mode ?? "?"));
      tr.append(el("td", {}, el("span", { class: `pill ${r.verified ? "ok" : "bad"}` },
        r.verified ? t("st_ok") : t("st_fail"))));
      tr.append(el("td", { class: "mono" }, r.evidence_id));
    }
    body.append(tr);
  }
  document.getElementById("shown").textContent = t("shown", shown, state.receipts.length);
}

function kv(pairs) {
  const box = el("div", { class: "kv" });
  for (const [k, v] of pairs) {
    box.append(el("div", { class: "k" }, k));
    box.append(el("div", { class: "mono" }, v ?? "-"));
  }
  return box;
}

function checkCell(check) {
  const cell = el("td", {}, pill(check.status));
  if (check.error) cell.append(" ", el("span", { class: "mono" }, check.error));
  return cell;
}

function renderDetail() {
  const section = document.getElementById("detail");
  const body = document.getElementById("detail-body");
  if (selected === null || !state || !state.receipts[selected]) {
    section.hidden = true;
    return;
  }
  const r = state.receipts[selected];
  section.hidden = false;
  body.replaceChildren();
  body.append(kv([
    [t("location"), `${r.location.file}:${r.location.line}`],
    ["evidence_id", r.evidence_id],
    [t("c_local"), localText(r.decided_at)],
    [t("c_utc"), utcText(r.decided_at)],
    [t("c_decision"), r.decision],
    [t("c_rule"), r.rule ?? t("default_deny")],
    [t("c_mode"), r.mode],
    [t("approval"), r.approval],
    ["policy_digest", r.policy_digest],
  ]));
  if (!r.parse_error) {
    body.append(el("h3", {}, t("signatures")));
    const sig = el("table", {},
      el("thead", {}, el("tr", {}, el("th", {}, ""), el("th", {}, t("key")), el("th", {}, t("result")))));
    const tbody = el("tbody", {});
    const s = r.signatures;
    tbody.append(el("tr", {}, el("td", {}, t("sig_agent")),
      el("td", { class: "mono" }, `agent_id ${s.agent.agent_id}`, el("br"),
        `subject_key_hash ${s.agent.subject_key_hash ?? "-"}`),
      checkCell(s.agent.check)));
    tbody.append(el("tr", {}, el("td", {}, t("sig_attester")),
      el("td", { class: "mono" }, `attester_key_id ${s.attester.key_id ?? "-"}`),
      checkCell(s.attester.check)));
    tbody.append(el("tr", {}, el("td", {}, t("sig_authority")),
      el("td", { class: "mono" }, `issuer ${s.authority.issuer}`, el("br"),
        `issuer_key_id ${s.authority.key_id ?? "-"}`, el("br"),
        `authority_id ${s.authority.authority_id}`),
      checkCell(s.authority.check)));
    sig.append(tbody);
    body.append(el("div", { class: "table-wrap" }, sig));

    body.append(el("h3", {}, t("other_checks")));
    const other = el("table", {});
    const otherBody = el("tbody", {});
    for (const name of ["shape", "authority_subject", "audience", "mode"]) {
      const check = r.checks[name] || { status: "not_run", error: null };
      otherBody.append(el("tr", {}, el("td", {}, t(`chk_${name}`)), checkCell(check)));
    }
    other.append(otherBody);
    body.append(other);

    body.append(el("h3", {}, t("chain")));
    if (r.seq === null || r.seq === undefined) {
      body.append(el("p", {}, t("unchained")));
    } else {
      body.append(kv([["seq", String(r.seq)], ["prev", r.prev]]));
    }
    body.append(el("p", {}, r.order
      ? el("span", {}, pill("fail"), " ", el("span", { class: "mono" }, r.order))
      : el("span", {}, pill("ok"), " ", t("order_ok"))));

    body.append(el("h3", {}, t("path_check")));
    if (r.path_check && typeof r.path_check === "object") {
      const table = el("table", {},
        el("thead", {}, el("tr", {}, el("th", {}, "key"), el("th", {}, t("lexical")),
          el("th", {}, t("resolved")), el("th", {}, t("status")))));
      const pb = el("tbody", {});
      for (const [key, value] of Object.entries(r.path_check)) {
        pb.append(el("tr", {}, el("td", { class: "mono" }, key),
          el("td", { class: "mono" }, value.lexical ?? "-"),
          el("td", { class: "mono" }, value.resolved ?? "-"),
          el("td", {}, el("span", { class: `pill ${value.status === "same" ? "ok" : "warn"}` }, value.status ?? "-"))));
      }
      table.append(pb);
      body.append(el("div", { class: "table-wrap" }, table));
    } else {
      body.append(el("p", { class: "muted" }, t("path_none")));
    }
  }
  body.append(el("h3", {}, t("json")));
  body.append(el("pre", {}, r.raw !== null ? JSON.stringify(r.raw, null, 2) : r.raw_text));
}

function renderAll() {
  applyStaticText();
  if (!state) return;
  document.getElementById("home").textContent = `${state.home} · ${t("generated")} ${localText(state.generated_at_utc)}`;
  renderSummary();
  renderVerify();
  renderToolFilter();
  renderTable();
  renderDetail();
}

async function load() {
  const error = document.getElementById("load-error");
  try {
    const response = await fetch("/api/state", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    state = await response.json();
    error.hidden = true;
    // #e=<evidence_id> opens that receipt.
    const wanted = decodeURIComponent((location.hash.match(/^#e=(.+)$/) || [])[1] || "");
    if (wanted) {
      const index = state.receipts.findIndex((r) => r.evidence_id === wanted);
      if (index >= 0) selected = index;
    }
  } catch (e) {
    error.hidden = false;
    error.textContent = `${t("load_error")}: ${e.message}`;
  }
  renderAll();
}

document.addEventListener("DOMContentLoaded", () => {
  const stored = readStoredLang();
  const nav = (navigator.language || "es").slice(0, 2);
  lang = I18N[stored] ? stored : I18N[nav] ? nav : "es";
  const select = document.getElementById("lang");
  select.value = lang;
  select.addEventListener("change", () => {
    lang = I18N[select.value] ? select.value : "es";
    storeLang(lang);
    renderAll();
  });
  document.getElementById("reload").addEventListener("click", load);
  for (const id of ["f-decision", "f-tool"]) {
    document.getElementById(id).addEventListener("change", renderTable);
  }
  document.getElementById("f-text").addEventListener("input", renderTable);
  applyStaticText();
  load();
});
