// praetore-mcp dashboard. Every value from the journal, the pending files
// and the policy is written with textContent, never as HTML.
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
    live: "En vivo",
    readonly_approvals: "Servido en 127.0.0.1 · aprobaciones desde la página habilitadas",
    pending: "Esperando aprobación",
    pending_none: "No hay llamadas esperando aprobación.",
    pending_error: "No se pudieron leer las aprobaciones pendientes",
    expires: "Vence",
    expires_in: (m, s) => `vence en ${m}:${String(s).padStart(2, "0")}`,
    expired: "vencida: ya no se puede aprobar",
    held_receipt: "Recibo de la retención",
    arguments_exact: "Argumentos exactos (canónicos), los que quedan ligados a la firma",
    approve: "Aprobar…",
    reject: "Rechazar…",
    confirm_approve: "Confirmar aprobación",
    confirm_reject: "Confirmar rechazo",
    cancel: "Cancelar",
    confirm_text_approve: "Vas a firmar con la llave de aprobador de este computador que el agente puede ejecutar UNA vez esta llamada exacta antes de que venza. Revisa servidor, herramienta y argumentos.",
    confirm_text_reject: "Vas a firmar el rechazo de esta llamada. No se reenviará; un nuevo intento vuelve a pedir aprobación.",
    sending: "Firmando…",
    decided_approve: (id) => `Aprobada ${id}. El agente puede reintentar esta llamada exacta una vez.`,
    decided_reject: (id) => `Rechazada ${id}.`,
    decide_error: "No se firmó nada",
    need_token: "Esta pestaña no tiene el token de sesión. Abre el enlace con #s= que imprimió la terminal para decidir desde aquí.",
    cli_hint: "Para decidir, ejecuta en una terminal (o arranca el dashboard con --approvals):",
    policy_rules: (n) => `Reglas de la política (${n})`,
    r_id: "id",
    r_effect: "Efecto",
    r_target: "Servidor",
    r_conditions: "Condiciones",
    r_any: "cualquiera",
    r_none: "ninguna",
    new_receipts: (n) => `${n} recibo(s) nuevo(s)`,
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
    live: "Live",
    readonly_approvals: "Served on 127.0.0.1 · approvals from the page enabled",
    pending: "Waiting for approval",
    pending_none: "No calls are waiting for approval.",
    pending_error: "Cannot read the pending approvals",
    expires: "Expires",
    expires_in: (m, s) => `expires in ${m}:${String(s).padStart(2, "0")}`,
    expired: "expired: it can no longer be approved",
    held_receipt: "Receipt of the hold",
    arguments_exact: "Exact (canonical) arguments, the ones bound to the signature",
    approve: "Approve…",
    reject: "Reject…",
    confirm_approve: "Confirm approval",
    confirm_reject: "Confirm rejection",
    cancel: "Cancel",
    confirm_text_approve: "You are about to sign, with this computer's approver key, that the agent may run this exact call ONCE before it expires. Check server, tool and arguments.",
    confirm_text_reject: "You are about to sign the rejection of this call. It will not be forwarded; a new attempt asks for approval again.",
    sending: "Signing…",
    decided_approve: (id) => `Approved ${id}. The agent can retry this exact call once.`,
    decided_reject: (id) => `Rejected ${id}.`,
    decide_error: "Nothing was signed",
    need_token: "This tab has no session token. Open the #s= link the terminal printed to decide from here.",
    cli_hint: "To decide, run in a terminal (or start the dashboard with --approvals):",
    policy_rules: (n) => `Policy rules (${n})`,
    r_id: "id",
    r_effect: "Effect",
    r_target: "Server",
    r_conditions: "Conditions",
    r_any: "any",
    r_none: "none",
    new_receipts: (n) => `${n} new receipt(s)`,
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
    live: "Ao vivo",
    readonly_approvals: "Servido em 127.0.0.1 · aprovações pela página habilitadas",
    pending: "Aguardando aprovação",
    pending_none: "Não há chamadas aguardando aprovação.",
    pending_error: "Não foi possível ler as aprovações pendentes",
    expires: "Expira",
    expires_in: (m, s) => `expira em ${m}:${String(s).padStart(2, "0")}`,
    expired: "expirada: não pode mais ser aprovada",
    held_receipt: "Recibo da retenção",
    arguments_exact: "Argumentos exatos (canônicos), os que ficam vinculados à assinatura",
    approve: "Aprovar…",
    reject: "Rejeitar…",
    confirm_approve: "Confirmar aprovação",
    confirm_reject: "Confirmar rejeição",
    cancel: "Cancelar",
    confirm_text_approve: "Você vai assinar, com a chave de aprovador deste computador, que o agente pode executar UMA vez esta chamada exata antes de expirar. Confira servidor, ferramenta e argumentos.",
    confirm_text_reject: "Você vai assinar a rejeição desta chamada. Ela não será encaminhada; uma nova tentativa pede aprovação de novo.",
    sending: "Assinando…",
    decided_approve: (id) => `Aprovada ${id}. O agente pode repetir esta chamada exata uma vez.`,
    decided_reject: (id) => `Rejeitada ${id}.`,
    decide_error: "Nada foi assinado",
    need_token: "Esta aba não tem o token de sessão. Abra o link com #s= que o terminal imprimiu para decidir daqui.",
    cli_hint: "Para decidir, execute em um terminal (ou inicie o dashboard com --approvals):",
    policy_rules: (n) => `Regras da política (${n})`,
    r_id: "id",
    r_effect: "Efeito",
    r_target: "Servidor",
    r_conditions: "Condições",
    r_any: "qualquer",
    r_none: "nenhuma",
    new_receipts: (n) => `${n} recibo(s) novo(s)`,
    yes: "sim",
    no: "não",
  },
};

let lang = "es";
let state = null;
let selected = null;
let fingerprint = null;
let knownIds = null;
let freshIds = new Set();
let loading = false;
let live = true;
// Pending id -> "approve" | "reject" while its confirmation box is open.
const confirming = new Map();
// Pending id -> { ok, text } after a decision from this tab.
const decisionNotes = new Map();
const SESSION_KEY = "praetore-mcp-dashboard-session";
const LIVE_KEY = "praetore-mcp-dashboard-live";
const POLL_MS = 3000;

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

function storageGet(store, key) {
  try {
    return store.getItem(key);
  } catch (_) {
    return null;
  }
}

function storageSet(store, key, value) {
  try {
    store.setItem(key, value);
  } catch (_) {
    // Storage unavailable: lasts for this page only.
  }
}

// The terminal prints the session token after #s=. Keep it in this tab's
// sessionStorage only, and take it out of the address bar.
let sessionToken = null;
function takeSessionToken() {
  const match = location.hash.match(/^#s=([0-9a-f]{64})$/);
  if (match) {
    storageSet(sessionStorage, SESSION_KEY, match[1]);
    history.replaceState(null, "", location.pathname);
  }
  sessionToken = storageGet(sessionStorage, SESSION_KEY) || sessionToken || (match && match[1]) || null;
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
    const classes = [];
    if (index === selected) classes.push("selected");
    if (freshIds.has(r.evidence_id)) classes.push("fresh");
    tr.className = classes.join(" ");
    tr.addEventListener("click", () => {
      selected = index;
      freshIds.delete(r.evidence_id);
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

function renderPending() {
  const box = document.getElementById("pending-body");
  const section = document.getElementById("pending");
  box.replaceChildren();
  const pending = state.pending;
  if (!Array.isArray(pending)) {
    section.className = "panel";
    box.append(el("p", { class: "banner bad" }, `${t("pending_error")}: ${pending && pending.error}`));
    return;
  }
  section.className = pending.length > 0 ? "panel attention" : "panel";
  document.title = pending.length > 0 ? `(${pending.length}) PRÆTORE MCP` : "PRÆTORE MCP receipts";
  for (const [id, note] of decisionNotes) {
    box.append(el("p", { class: `banner ${note.ok ? "ok" : "bad"}` }, note.text));
    if (!pending.some((p) => p.approval_id === id)) decisionNotes.delete(id);
  }
  if (pending.length === 0) {
    box.append(el("p", { class: "muted" }, t("pending_none")));
    return;
  }
  for (const p of pending) box.append(pendingItem(p));
}

function pendingItem(p) {
  const expires = new Date(p.expires_at);
  const left = Math.floor((expires.getTime() - Date.now()) / 1000);
  const expired = !Number.isNaN(left) && left <= 0;
  const item = el("div", { class: "pending-item" });
  item.append(el("div", { class: "pending-head" },
    el("span", { class: "pill warn" }, "REQUIRE_APPROVAL"), " ",
    el("strong", {}, `${p.server} · ${p.tool}`), " ",
    el("span", { class: expired ? "pill bad" : "pill neutral countdown", "data-expires": p.expires_at },
      expired ? t("expired") : t("expires_in", Math.floor(left / 60), left % 60))));
  const receipt = el("a", { href: `#e=${encodeURIComponent(p.evidence_id)}` }, p.evidence_id);
  receipt.addEventListener("click", (event) => {
    event.preventDefault();
    const index = state.receipts.findIndex((r) => r.evidence_id === p.evidence_id);
    if (index >= 0) {
      selected = index;
      history.replaceState(null, "", `#e=${encodeURIComponent(p.evidence_id)}`);
      renderTable();
      renderDetail();
      document.getElementById("detail").scrollIntoView({ behavior: "smooth" });
    }
  });
  item.append(kv([
    ["approval_id", p.approval_id],
    [t("expires"), `${localText(p.expires_at)} · ${utcText(p.expires_at)}`],
    [t("held_receipt"), receipt],
  ]));
  if (p.error) {
    item.append(el("p", { class: "banner bad mono" }, p.error));
    return item;
  }
  item.append(el("div", { class: "k small" }, t("arguments_exact")));
  item.append(el("pre", { class: "args-full" }, p.arguments_canonical));
  if (expired) return item;

  if (!state.approvals_from_page) {
    item.append(el("p", { class: "muted" }, t("cli_hint")));
    item.append(el("pre", {},
      `praetore-mcp approve ${p.approval_id} --dir ${state.home}\n` +
      `praetore-mcp reject ${p.approval_id} --dir ${state.home}`));
    return item;
  }
  if (!sessionToken) {
    item.append(el("p", { class: "banner warn" }, t("need_token")));
    return item;
  }
  const mode = confirming.get(p.approval_id);
  if (!mode) {
    const approve = el("button", { type: "button", class: "primary" }, t("approve"));
    const reject = el("button", { type: "button", class: "danger" }, t("reject"));
    approve.addEventListener("click", () => { confirming.set(p.approval_id, "approve"); renderPending(); });
    reject.addEventListener("click", () => { confirming.set(p.approval_id, "reject"); renderPending(); });
    item.append(el("div", { class: "actions" }, approve, reject));
    return item;
  }
  const confirmBox = el("div", { class: `banner ${mode === "approve" ? "warn" : "bad"}` },
    el("p", {}, t(mode === "approve" ? "confirm_text_approve" : "confirm_text_reject")));
  const go = el("button", { type: "button", class: mode === "approve" ? "primary" : "danger" },
    t(mode === "approve" ? "confirm_approve" : "confirm_reject"));
  const cancel = el("button", { type: "button" }, t("cancel"));
  cancel.addEventListener("click", () => { confirming.delete(p.approval_id); renderPending(); });
  go.addEventListener("click", () => decide(p, mode, go));
  confirmBox.append(el("div", { class: "actions" }, go, cancel));
  item.append(confirmBox);
  return item;
}

async function decide(p, mode, button) {
  button.disabled = true;
  button.textContent = t("sending");
  let note;
  try {
    const response = await fetch(mode === "approve" ? "/api/approve" : "/api/reject", {
      method: "POST",
      cache: "no-store",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${sessionToken}` },
      body: JSON.stringify({
        approval_id: p.approval_id,
        server: p.server,
        tool: p.tool,
        evidence_id: p.evidence_id,
        arguments_canonical: p.arguments_canonical,
      }),
    });
    const text = await response.text();
    let body = null;
    try { body = JSON.parse(text); } catch (_) { body = null; }
    if (response.ok && body && body.ok) {
      note = { ok: true, text: t(mode === "approve" ? "decided_approve" : "decided_reject", body.approval_id) };
    } else {
      note = { ok: false, text: `${t("decide_error")}: HTTP ${response.status} ${body && body.error ? body.error : text}` };
    }
  } catch (e) {
    note = { ok: false, text: `${t("decide_error")}: ${e.message}` };
  }
  confirming.delete(p.approval_id);
  decisionNotes.set(p.approval_id, note);
  fingerprint = null;
  await load();
}

function conditionsText(rule) {
  const parts = [];
  for (const c of rule.parameter_conditions || []) parts.push(JSON.stringify(c));
  for (const c of rule.context_conditions || []) parts.push(`context ${JSON.stringify(c)}`);
  if (rule.required_capability) parts.push(`capability ${rule.required_capability}`);
  if (rule.control_loop) parts.push(`loop ${rule.control_loop}${rule.delta_ms ? ` δ=${rule.delta_ms}ms` : ""}`);
  return parts.length ? parts.join("\n") : t("r_none");
}

function effectPill(effect) {
  const label = String(effect).toUpperCase();
  const cls = label.includes("ALLOW") ? "ok" : label.includes("DENY") ? "bad" : "warn";
  return el("span", { class: `pill ${cls}` }, label);
}

function renderPolicy() {
  const box = document.getElementById("policy-body");
  const title = document.getElementById("policy-title");
  box.replaceChildren();
  const p = state.policy;
  if (p.status !== "ok") {
    title.textContent = t("policy");
    box.append(el("p", { class: "banner bad mono" }, `${t("policy_error")}: ${p.error}`));
    return;
  }
  const rules = Array.isArray(p.rules_detail) ? p.rules_detail : [];
  title.textContent = t("policy_rules", rules.length);
  box.append(kv([["id", `${p.id} v${p.version}`], ["digest", p.digest], ["path", p.path]]));
  const table = el("table", {},
    el("thead", {}, el("tr", {},
      el("th", {}, t("r_id")), el("th", {}, t("r_effect")),
      el("th", {}, t("r_target")), el("th", {}, t("r_conditions")))));
  const body = el("tbody", { class: "static" });
  for (const rule of rules) {
    const allowAll = p.allow_all_rules.includes(rule.id);
    body.append(el("tr", { class: allowAll ? "allow-all" : "" },
      el("td", { class: "mono" }, rule.id),
      el("td", {}, effectPill(rule.effect)),
      el("td", {}, rule.target ?? t("r_any")),
      el("td", { class: "mono pre" }, conditionsText(rule))));
  }
  table.append(body);
  box.append(el("div", { class: "table-wrap" }, table));
}

function renderAll() {
  applyStaticText();
  document.getElementById("live-label").textContent = t("live");
  if (!state) return;
  document.querySelector("[data-i18n=readonly]").textContent =
    state.approvals_from_page ? t("readonly_approvals") : t("readonly");
  renderStamp();
  renderSummary();
  renderPending();
  renderVerify();
  renderPolicy();
  renderToolFilter();
  renderTable();
  renderDetail();
}

function renderStamp() {
  const fresh = freshIds.size > 0 ? ` · ${t("new_receipts", freshIds.size)}` : "";
  document.getElementById("home").textContent =
    `${state.home} · ${t("generated")} ${localText(state.generated_at_utc)}${fresh}`;
}

function fingerprintOf(s) {
  return JSON.stringify([
    s.summary, s.verify && s.verify.status, s.verify && s.verify.head, s.verify && s.verify.failed,
    s.verify && s.verify.approval, s.pending, s.policy && s.policy.digest, s.policy && s.policy.status,
    s.approvals_from_page,
  ]);
}

// Ticks the countdowns without a reload.
function tickCountdowns() {
  for (const node of document.querySelectorAll(".countdown[data-expires]")) {
    const left = Math.floor((new Date(node.getAttribute("data-expires")).getTime() - Date.now()) / 1000);
    if (Number.isNaN(left)) continue;
    if (left <= 0) {
      fingerprint = null;
      if (state) renderPending();
      return;
    }
    node.textContent = t("expires_in", Math.floor(left / 60), left % 60);
  }
}

async function load() {
  if (loading) return;
  loading = true;
  const error = document.getElementById("load-error");
  try {
    const response = await fetch("/api/state", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const next = await response.json();
    error.hidden = true;
    const firstLoad = state === null;
    const ids = new Set(next.receipts.map((r) => r.evidence_id).filter(Boolean));
    if (knownIds) {
      for (const id of ids) if (!knownIds.has(id)) freshIds.add(id);
    }
    knownIds = ids;
    state = next;
    if (firstLoad) {
      // #e=<evidence_id> opens that receipt.
      const wanted = decodeURIComponent((location.hash.match(/^#e=(.+)$/) || [])[1] || "");
      if (wanted) {
        const index = state.receipts.findIndex((r) => r.evidence_id === wanted);
        if (index >= 0) selected = index;
      }
    }
    const print = fingerprintOf(state);
    if (print === fingerprint) {
      renderStamp();
    } else {
      fingerprint = print;
      renderAll();
    }
  } catch (e) {
    error.hidden = false;
    error.textContent = `${t("load_error")}: ${e.message}`;
    if (!state) renderAll();
  } finally {
    loading = false;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  takeSessionToken();
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
  document.getElementById("reload").addEventListener("click", () => { fingerprint = null; load(); });
  const liveBox = document.getElementById("live");
  live = storageGet(localStorage, LIVE_KEY) !== "off";
  liveBox.checked = live;
  liveBox.addEventListener("change", () => {
    live = liveBox.checked;
    storageSet(localStorage, LIVE_KEY, live ? "on" : "off");
    if (live) load();
  });
  setInterval(() => {
    if (live && !document.hidden) load();
  }, POLL_MS);
  setInterval(tickCountdowns, 1000);
  document.addEventListener("visibilitychange", () => {
    if (live && !document.hidden) load();
  });
  for (const id of ["f-decision", "f-tool"]) {
    document.getElementById(id).addEventListener("change", renderTable);
  }
  document.getElementById("f-text").addEventListener("input", renderTable);
  applyStaticText();
  load();
});
