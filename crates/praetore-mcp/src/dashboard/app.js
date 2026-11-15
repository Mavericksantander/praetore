// praetore-mcp dashboard. Every value from the journal, the pending files
// and the policy is written with textContent, never as HTML.
"use strict";

const TOOLS = {
  es: {
    read_file: "Leer archivo", read_text_file: "Leer archivo", read_media_file: "Leer archivo multimedia",
    read_multiple_files: "Leer varios archivos", write_file: "Escribir archivo", edit_file: "Editar archivo",
    append_file: "Agregar a archivo", create_directory: "Crear carpeta", list_directory: "Listar carpeta",
    list_directory_with_sizes: "Listar carpeta con tamaños", directory_tree: "Ver árbol de carpetas",
    move_file: "Mover archivo", copy_file: "Copiar archivo", search_files: "Buscar archivos",
    get_file_info: "Ver información de archivo", list_allowed_directories: "Listar carpetas permitidas",
  },
  en: {
    read_file: "Read file", read_text_file: "Read file", read_media_file: "Read media file",
    read_multiple_files: "Read several files", write_file: "Write file", edit_file: "Edit file",
    append_file: "Append to file", create_directory: "Create folder", list_directory: "List folder",
    list_directory_with_sizes: "List folder with sizes", directory_tree: "View folder tree",
    move_file: "Move file", copy_file: "Copy file", search_files: "Search files",
    get_file_info: "Get file info", list_allowed_directories: "List allowed folders",
  },
  pt: {
    read_file: "Ler arquivo", read_text_file: "Ler arquivo", read_media_file: "Ler arquivo de mídia",
    read_multiple_files: "Ler vários arquivos", write_file: "Escrever arquivo", edit_file: "Editar arquivo",
    append_file: "Acrescentar ao arquivo", create_directory: "Criar pasta", list_directory: "Listar pasta",
    list_directory_with_sizes: "Listar pasta com tamanhos", directory_tree: "Ver árvore de pastas",
    move_file: "Mover arquivo", copy_file: "Copiar arquivo", search_files: "Buscar arquivos",
    get_file_info: "Ver informações do arquivo", list_allowed_directories: "Listar pastas permitidas",
  },
};

const I18N = {
  es: {
    nav_operation: "Operación", nav_info: "Información",
    sub_operation: "Lo que tu agente está haciendo, en tiempo real",
    sub_info: "Registro, reglas y verificación de todo lo que hizo tu agente",
    sec_decide: "Por decidir", decide_none: "Nada por decidir.",
    sec_live: "En vivo", see_log: "Ver registro completo →",
    it_log: "Registro", it_approvals: "Aprobaciones", it_policy: "Reglas", it_integrity: "Verificación", it_stats: "Estadísticas",
    tech_details: "Datos técnicos", home_dir: "Carpeta de datos",
    nav_overview: "Resumen", nav_approvals: "Aprobaciones", nav_activity: "Actividad",
    nav_policy: "Política", nav_integrity: "Integridad",
    sub_overview: "Qué hizo tu agente y qué decidió PRÆTORE",
    sub_approvals: "Acciones del agente que esperan una decisión humana",
    sub_activity: "Cada llamada a una herramienta, con su recibo firmado",
    sub_policy: "Las reglas que deciden cada llamada",
    sub_integrity: "La misma verificación que praetore-mcp verify",
    live: "En vivo", updated: (s) => `Actualizado ${s}`,
    mode_readonly: "Solo lectura",
    hero_ok_t: "Todo en orden.",
    hero_ok_d: (n) => `${n} acciones de tu agente registradas, firmadas y verificadas.`,
    hero_bad_t: "Algo no cuadra.",
    hero_bad_d: (f) => `La verificación del registro encontró ${f} problema(s).`,
    hero_err_t: "No pudimos verificar el registro.",
    hero_empty_t: "En silencio, por ahora.",
    hero_empty_d: "Cuando tu agente use una herramienta, la decisión aparecerá aquí.",
    see_integrity: "Ver detalles",
    cta_pending: (n) => n === 1 ? "Una acción espera tu decisión." : `${n} acciones esperan tu decisión.`,
    cta_sub: "Tu agente está en pausa hasta que la apruebes o la rechaces desde una terminal.",
    review: "Revisar",
    k_total: "Decisiones", k_allow: "Permitidas", k_deny: "Bloqueadas", k_ask: "Pidieron aprobación",
    pct: (p) => `${p}% del total`, k_total_foot: (n) => `${n} en modo enforce`,
    chart_title: "Actividad", chart_hours: "Últimas 24 horas, por hora", chart_days: "Últimos 14 días, por día",
    recent: "Actividad reciente", see_all: "Ver todo →",
    tools_title: "Herramientas más usadas", tools_sub: "Llamadas por herramienta",
    empty_recent: "Todavía no hay actividad.",
    d_ALLOW: "Permitida", d_DENY: "Bloqueada", d_REQUIRE_APPROVAL: "Pidió aprobación",
    ap_pending: "Esperando decisión", ap_held: "Retenida (sin decisión)", ap_approve: "Aprobada",
    ap_reject: "Rechazada", ap_executed: "Ejecutada tras aprobación", ap_would: "En enforce pediría aprobación",
    pend_none_t: "Nada pendiente.", pend_none_d: "No hay acciones esperando aprobación.",
    agent_wants: "El agente quiere", on_server: (s) => `en el servidor ${s}`,
    expires_in: (m, s) => `Vence en ${m}:${String(s).padStart(2, "0")}`,
    expired: "Vencida: ya no se puede aprobar",
    unsigned_tag: "Sin firma",
    unsigned_note: "Este aviso sale de approvals/pending: no está firmado y verify no lo comprueba. El recibo de la llamada retenida sí está firmado y verify lo comprueba.",
    sec_decide_n: (n) => `Por decidir (${n}, sin firma)`,
    exact_args: "Lo que hará exactamente",
    exact_args_hint: "Esto es exactamente lo que se firma y lo único que el agente podrá ejecutar.",
    approve: "Aprobar", reject: "Rechazar", view_receipt: "Ver recibo",
    history: "Historial", history_sub: "Llamadas que pidieron aprobación y cómo terminaron",
    history_none: "Aún no hay llamadas que hayan pedido aprobación.",
    cli_hint: "Para decidir, ejecuta uno de estos comandos en una terminal de este computador", copy_approve: "Copiar comando para aprobar",
    copy: "Copiar", copied: "Copiado",
    toast_pending: "Nueva acción esperando tu aprobación",
    toast_new: (n) => n === 1 ? "1 decisión nueva" : `${n} decisiones nuevas`,
    search_ph: "Buscar por archivo, herramienta, regla o id…",
    all: "Todas", all_tools: "Todas las herramientas", shown: (n, t) => `${n} de ${t}`,
    shown_range: (a, b, n) => `${a}–${b} de ${n}`, page_newer: "← Más recientes", page_older: "Más antiguos →",
    f_from: "Desde", f_to: "Hasta", f_search: "Buscar en los recibos", f_tool_label: "Herramienta", f_decision_label: "Decisión",
    empty_home_t: "Este home todavía no tiene recibos.",
    empty_home_d: "Aparecen cuando un cliente MCP llama a una herramienta a través de praetore-mcp wrap.",
    c_when: "Cuándo", c_action: "Acción", c_server: "Servidor", c_result: "Resultado", c_rule: "Regla", c_verify: "Firma",
    default_deny: "Bloqueo por defecto",
    empty_filter_t: "Sin resultados", empty_filter_d: "Prueba con otro filtro.",
    tab_summary: "Resumen", tab_signatures: "Verificación", tab_paths: "Rutas", tab_json: "Datos técnicos",
    f_decision: "Decisión", f_rule: "Regla", f_mode: "Modo", f_server: "Servidor", f_tool: "Herramienta",
    f_local: "Hora local", f_utc: "UTC", f_approval: "Aprobación", f_policy: "Política (digest)",
    f_location: "Ubicación", args: "Argumentos", omitted: (b, h) => `(omitidos: ${b} bytes, sha256 ${h})`,
    sig_title: "Las tres firmas del recibo",
    sig_agent: "Agente (intent)", sig_attester: "Attester", sig_authority: "Autoridad",
    other_checks: "Otras comprobaciones de verify",
    chk_shape: "Forma HighAssurance (v2)", chk_authority_subject: "La autoridad nombra al agente",
    chk_audience: "Audiencia praetore-mcp", chk_mode: "praetore.mode válido",
    chain: "Encadenado", order_ok: "seq/prev siguen a la entrada anterior", unchained: "Entrada sin encadenar (versión anterior)",
    st_ok: "Válida", st_fail: "Falla", st_not_run: "No comprobada",
    path_desc: "Cómo resolvió PRÆTORE cada ruta en el disco antes de decidir.",
    path_none: "Este recibo no tiene path_check.", lexical: "Pedida", resolved: "Resuelta", status: "Estado",
    pol_active: "Política activa", pol_meta: (v, n) => `versión ${v} · ${n} reglas`,
    effect_Allow: "Permitir", effect_Deny: "Bloquear", effect_RequireApproval: "Pedir aprobación",
    any_tool: "cualquier herramienta", any_server: "en cualquier servidor", in_server: (s) => `en ${s}`,
    when: "cuando", and: "y",
    c_within: (k, v) => `${k} está dentro de ${v}`, c_exact: (k, v) => `${k} es ${v}`,
    c_prefix: (k, v) => `${k} empieza con ${v}`,
    rule_default_t: "Todo lo demás", rule_default_d: "Cualquier llamada que ninguna regla cubra se bloquea (default deny).",
    allow_all_tag: "Permite todo",
    pol_note: "Los procesos wrap leen la política al arrancar: reinicia tu cliente MCP después de cambiarla.",
    int_ok: "El journal está íntegro.", int_fail: "Se encontraron fallas",
    verified_n: (ok, total, failed) => `${ok} de ${total} recibos verificados, ${failed} fallas`,
    head: "Journal head",
    head_text: (n, seq, u) => `${n} entradas encadenadas, próximo seq ${seq}, ${u} sin encadenar anteriores`,
    head_none: (c, u) => `Sin head (${c} encadenadas, ${u} sin encadenar)`,
    head_warn: "Guarda este head fuera de esta máquina y pásalo como --expected-head: sin él no se detectan entradas borradas al final del journal.",
    expected_head: (h) => `Comparado con --expected-head ${h}.`,
    failures: "Fallas reportadas por verify",
    appr_journal: "Journal de aprobaciones",
    appr_text: (d, e) => `${d} decisiones, ${e} ejecuciones`, appr_none: "Todavía no hay decisiones de aprobación.",
    checked: "Qué comprueba verify",
    checked_list: (a, i) => [
      "Hash de integridad de cada recibo",
      `Firma del attester (${a})`,
      "Firma del intent del agente",
      `Firma de la autoridad contra ${i} a la hora de la decisión`,
      "Vínculo de praetore.mode",
      "Orden del journal (seq y enlace hash)",
      "Journal de aprobaciones: firma del aprobador, vínculo con la llamada retenida, vencimiento, uso único",
    ],
    observe_note: "Un recibo observe registra una decisión que NO se aplicó.",
    verify_error: "verify no pudo correr",
    warn_allow_all: (rules, n) => `Tus reglas incluyen una que permite todo (${rules}): cualquier acción que no tenga una regla de bloqueo o de aprobación pasa sin control.`,
    note_allow_all: (rules) => `La política tiene una regla que permite todo (${rules}). Por ahora no hay recibos en modo enforce.`,
    policy_error: "No se pudo leer la política",
    load_error: "No se pudo cargar /api/state",
    unreadable: "Línea ilegible",
  },
  en: {
    nav_operation: "Operation", nav_info: "Information",
    sub_operation: "What your agent is doing, in real time",
    sub_info: "Log, rules and verification of everything your agent did",
    sec_decide: "To decide", decide_none: "Nothing to decide.",
    sec_live: "Live", see_log: "See the full log →",
    it_log: "Log", it_approvals: "Approvals", it_policy: "Rules", it_integrity: "Verification", it_stats: "Statistics",
    tech_details: "Technical data", home_dir: "Data folder",
    nav_overview: "Overview", nav_approvals: "Approvals", nav_activity: "Activity",
    nav_policy: "Policy", nav_integrity: "Integrity",
    sub_overview: "What your agent did and what PRÆTORE decided",
    sub_approvals: "Agent actions waiting for a human decision",
    sub_activity: "Every tool call, with its signed receipt",
    sub_policy: "The rules that decide each call",
    sub_integrity: "The same verification as praetore-mcp verify",
    live: "Live", updated: (s) => `Updated ${s}`,
    mode_readonly: "Read-only",
    hero_ok_t: "All in order.",
    hero_ok_d: (n) => `${n} actions by your agent recorded, signed and verified.`,
    hero_bad_t: "Something does not add up.",
    hero_bad_d: (f) => `Verifying the log found ${f} problem(s).`,
    hero_err_t: "We could not verify the log.",
    hero_empty_t: "Quiet, for now.",
    hero_empty_d: "When your agent uses a tool, the decision will show up here.",
    see_integrity: "See details",
    cta_pending: (n) => n === 1 ? "One action is waiting for you." : `${n} actions are waiting for you.`,
    cta_sub: "Your agent is paused until you approve or reject it from a terminal.",
    review: "Review",
    k_total: "Decisions", k_allow: "Allowed", k_deny: "Blocked", k_ask: "Asked for approval",
    pct: (p) => `${p}% of total`, k_total_foot: (n) => `${n} in enforce mode`,
    chart_title: "Activity", chart_hours: "Last 24 hours, by hour", chart_days: "Last 14 days, by day",
    recent: "Recent activity", see_all: "View all →",
    tools_title: "Most used tools", tools_sub: "Calls per tool",
    empty_recent: "No activity yet.",
    d_ALLOW: "Allowed", d_DENY: "Blocked", d_REQUIRE_APPROVAL: "Asked for approval",
    ap_pending: "Waiting for decision", ap_held: "Held (no decision)", ap_approve: "Approved",
    ap_reject: "Rejected", ap_executed: "Executed after approval", ap_would: "Enforce would ask",
    pend_none_t: "Nothing pending.", pend_none_d: "No actions are waiting for approval.",
    agent_wants: "The agent wants to", on_server: (s) => `on server ${s}`,
    expires_in: (m, s) => `Expires in ${m}:${String(s).padStart(2, "0")}`,
    expired: "Expired: it can no longer be approved",
    unsigned_tag: "Not signed",
    unsigned_note: "This notice comes from approvals/pending: it is not signed and verify does not check it. The receipt of the held call is signed and verify checks it.",
    sec_decide_n: (n) => `To decide (${n}, not signed)`,
    exact_args: "Exactly what it will do",
    exact_args_hint: "This is exactly what gets signed and the only call the agent will be able to run.",
    approve: "Approve", reject: "Reject", view_receipt: "View receipt",
    history: "History", history_sub: "Calls that asked for approval and how they ended",
    history_none: "No call has asked for approval yet.",
    cli_hint: "To decide, run one of these commands in a terminal on this computer", copy_approve: "Copy approve command",
    copy: "Copy", copied: "Copied",
    toast_pending: "New action waiting for your approval",
    toast_new: (n) => n === 1 ? "1 new decision" : `${n} new decisions`,
    search_ph: "Search by file, tool, rule or id…",
    all: "All", all_tools: "All tools", shown: (n, t) => `${n} of ${t}`,
    shown_range: (a, b, n) => `${a}–${b} of ${n}`, page_newer: "← Newer", page_older: "Older →",
    f_from: "From", f_to: "To", f_search: "Search the receipts", f_tool_label: "Tool", f_decision_label: "Decision",
    empty_home_t: "This home has no receipts yet.",
    empty_home_d: "They appear when an MCP client calls a tool through praetore-mcp wrap.",
    c_when: "When", c_action: "Action", c_server: "Server", c_result: "Result", c_rule: "Rule", c_verify: "Signature",
    default_deny: "Default deny",
    empty_filter_t: "No results", empty_filter_d: "Try another filter.",
    tab_summary: "Summary", tab_signatures: "Verification", tab_paths: "Paths", tab_json: "Technical data",
    f_decision: "Decision", f_rule: "Rule", f_mode: "Mode", f_server: "Server", f_tool: "Tool",
    f_local: "Local time", f_utc: "UTC", f_approval: "Approval", f_policy: "Policy (digest)",
    f_location: "Location", args: "Arguments", omitted: (b, h) => `(omitted: ${b} bytes, sha256 ${h})`,
    sig_title: "The receipt's three signatures",
    sig_agent: "Agent (intent)", sig_attester: "Attester", sig_authority: "Authority",
    other_checks: "Other verify checks",
    chk_shape: "HighAssurance (v2) shape", chk_authority_subject: "Authority names the agent",
    chk_audience: "praetore-mcp audience", chk_mode: "Valid praetore.mode",
    chain: "Chain", order_ok: "seq/prev follow the previous entry", unchained: "Unchained entry (earlier version)",
    st_ok: "Valid", st_fail: "Failed", st_not_run: "Not checked",
    path_desc: "How PRÆTORE resolved each path on disk before deciding.",
    path_none: "This receipt has no path_check.", lexical: "Requested", resolved: "Resolved", status: "Status",
    pol_active: "Active policy", pol_meta: (v, n) => `version ${v} · ${n} rules`,
    effect_Allow: "Allow", effect_Deny: "Block", effect_RequireApproval: "Ask for approval",
    any_tool: "any tool", any_server: "on any server", in_server: (s) => `on ${s}`,
    when: "when", and: "and",
    c_within: (k, v) => `${k} is inside ${v}`, c_exact: (k, v) => `${k} is ${v}`,
    c_prefix: (k, v) => `${k} starts with ${v}`,
    rule_default_t: "Everything else", rule_default_d: "Any call no rule covers is blocked (default deny).",
    allow_all_tag: "Allows everything",
    pol_note: "wrap processes read the policy when they start: restart your MCP client after changing it.",
    int_ok: "The journal is intact.", int_fail: "Failures found",
    verified_n: (ok, total, failed) => `${ok} of ${total} receipts verified, ${failed} failures`,
    head: "Journal head",
    head_text: (n, seq, u) => `${n} chained entries, next seq ${seq}, ${u} unchained earlier entries`,
    head_none: (c, u) => `No head (${c} chained, ${u} unchained)`,
    head_warn: "Keep this head outside this machine and pass it as --expected-head: without it, entries removed at the end of the journal are not detected.",
    expected_head: (h) => `Compared with --expected-head ${h}.`,
    failures: "Failures reported by verify",
    appr_journal: "Approval journal",
    appr_text: (d, e) => `${d} decision(s), ${e} execution(s)`, appr_none: "No approval decisions yet.",
    checked: "What verify checks",
    checked_list: (a, i) => [
      "Integrity hash of each receipt",
      `Attester signature (${a})`,
      "Agent intent signature",
      `Authority signature against ${i} at decision time`,
      "praetore.mode binding",
      "Journal order (seq and hash link)",
      "Approval journal: approver signature, binding to the held call, expiry, single use",
    ],
    observe_note: "An observe receipt records a decision that was NOT enforced.",
    verify_error: "verify could not run",
    warn_allow_all: (rules, n) => `Your rules include one that allows everything (${rules}): any action without a block or approval rule goes through unchecked.`,
    note_allow_all: (rules) => `The policy has an allow-all rule (${rules}). There are no enforce receipts yet.`,
    policy_error: "Cannot read the policy",
    load_error: "Cannot load /api/state",
    unreadable: "Unreadable line",
  },
  pt: {
    nav_operation: "Operação", nav_info: "Informação",
    sub_operation: "O que seu agente está fazendo, em tempo real",
    sub_info: "Registro, regras e verificação de tudo o que seu agente fez",
    sec_decide: "Para decidir", decide_none: "Nada para decidir.",
    sec_live: "Ao vivo", see_log: "Ver registro completo →",
    it_log: "Registro", it_approvals: "Aprovações", it_policy: "Regras", it_integrity: "Verificação", it_stats: "Estatísticas",
    tech_details: "Dados técnicos", home_dir: "Pasta de dados",
    nav_overview: "Resumo", nav_approvals: "Aprovações", nav_activity: "Atividade",
    nav_policy: "Política", nav_integrity: "Integridade",
    sub_overview: "O que seu agente fez e o que o PRÆTORE decidiu",
    sub_approvals: "Ações do agente aguardando uma decisão humana",
    sub_activity: "Cada chamada de ferramenta, com seu recibo assinado",
    sub_policy: "As regras que decidem cada chamada",
    sub_integrity: "A mesma verificação do praetore-mcp verify",
    live: "Ao vivo", updated: (s) => `Atualizado ${s}`,
    mode_readonly: "Somente leitura",
    hero_ok_t: "Tudo em ordem.",
    hero_ok_d: (n) => `${n} ações do seu agente registradas, assinadas e verificadas.`,
    hero_bad_t: "Algo não confere.",
    hero_bad_d: (f) => `A verificação do registro encontrou ${f} problema(s).`,
    hero_err_t: "Não conseguimos verificar o registro.",
    hero_empty_t: "Em silêncio, por enquanto.",
    hero_empty_d: "Quando seu agente usar uma ferramenta, a decisão aparecerá aqui.",
    see_integrity: "Ver detalhes",
    cta_pending: (n) => n === 1 ? "Uma ação aguarda sua decisão." : `${n} ações aguardam sua decisão.`,
    cta_sub: "Seu agente está em pausa até você aprovar ou rejeitar em um terminal.",
    review: "Revisar",
    k_total: "Decisões", k_allow: "Permitidas", k_deny: "Bloqueadas", k_ask: "Pediram aprovação",
    pct: (p) => `${p}% do total`, k_total_foot: (n) => `${n} em modo enforce`,
    chart_title: "Atividade", chart_hours: "Últimas 24 horas, por hora", chart_days: "Últimos 14 dias, por dia",
    recent: "Atividade recente", see_all: "Ver tudo →",
    tools_title: "Ferramentas mais usadas", tools_sub: "Chamadas por ferramenta",
    empty_recent: "Ainda não há atividade.",
    d_ALLOW: "Permitida", d_DENY: "Bloqueada", d_REQUIRE_APPROVAL: "Pediu aprovação",
    ap_pending: "Aguardando decisão", ap_held: "Retida (sem decisão)", ap_approve: "Aprovada",
    ap_reject: "Rejeitada", ap_executed: "Executada após aprovação", ap_would: "Em enforce pediria aprovação",
    pend_none_t: "Nada pendente.", pend_none_d: "Não há ações aguardando aprovação.",
    agent_wants: "O agente quer", on_server: (s) => `no servidor ${s}`,
    expires_in: (m, s) => `Expira em ${m}:${String(s).padStart(2, "0")}`,
    expired: "Expirada: não pode mais ser aprovada",
    unsigned_tag: "Sem assinatura",
    unsigned_note: "Este aviso vem de approvals/pending: não está assinado e o verify não o verifica. O recibo da chamada retida está assinado e o verify o verifica.",
    sec_decide_n: (n) => `Para decidir (${n}, sem assinatura)`,
    exact_args: "O que fará exatamente",
    exact_args_hint: "Isto é exatamente o que é assinado e a única chamada que o agente poderá executar.",
    approve: "Aprovar", reject: "Rejeitar", view_receipt: "Ver recibo",
    history: "Histórico", history_sub: "Chamadas que pediram aprovação e como terminaram",
    history_none: "Nenhuma chamada pediu aprovação ainda.",
    cli_hint: "Para decidir, execute um destes comandos em um terminal deste computador", copy_approve: "Copiar comando para aprovar",
    copy: "Copiar", copied: "Copiado",
    toast_pending: "Nova ação aguardando sua aprovação",
    toast_new: (n) => n === 1 ? "1 decisão nova" : `${n} decisões novas`,
    search_ph: "Buscar por arquivo, ferramenta, regra ou id…",
    all: "Todas", all_tools: "Todas as ferramentas", shown: (n, t) => `${n} de ${t}`,
    shown_range: (a, b, n) => `${a}–${b} de ${n}`, page_newer: "← Mais recentes", page_older: "Mais antigos →",
    f_from: "De", f_to: "Até", f_search: "Buscar nos recibos", f_tool_label: "Ferramenta", f_decision_label: "Decisão",
    empty_home_t: "Este home ainda não tem recibos.",
    empty_home_d: "Eles aparecem quando um cliente MCP chama uma ferramenta através de praetore-mcp wrap.",
    c_when: "Quando", c_action: "Ação", c_server: "Servidor", c_result: "Resultado", c_rule: "Regra", c_verify: "Assinatura",
    default_deny: "Bloqueio padrão",
    empty_filter_t: "Sem resultados", empty_filter_d: "Tente outro filtro.",
    tab_summary: "Resumo", tab_signatures: "Verificação", tab_paths: "Caminhos", tab_json: "Dados técnicos",
    f_decision: "Decisão", f_rule: "Regra", f_mode: "Modo", f_server: "Servidor", f_tool: "Ferramenta",
    f_local: "Hora local", f_utc: "UTC", f_approval: "Aprovação", f_policy: "Política (digest)",
    f_location: "Localização", args: "Argumentos", omitted: (b, h) => `(omitidos: ${b} bytes, sha256 ${h})`,
    sig_title: "As três assinaturas do recibo",
    sig_agent: "Agente (intent)", sig_attester: "Attester", sig_authority: "Autoridade",
    other_checks: "Outras verificações do verify",
    chk_shape: "Forma HighAssurance (v2)", chk_authority_subject: "A autoridade nomeia o agente",
    chk_audience: "Audiência praetore-mcp", chk_mode: "praetore.mode válido",
    chain: "Encadeamento", order_ok: "seq/prev seguem a entrada anterior", unchained: "Entrada não encadeada (versão anterior)",
    st_ok: "Válida", st_fail: "Falha", st_not_run: "Não verificada",
    path_desc: "Como o PRÆTORE resolveu cada caminho no disco antes de decidir.",
    path_none: "Este recibo não tem path_check.", lexical: "Pedido", resolved: "Resolvido", status: "Estado",
    pol_active: "Política ativa", pol_meta: (v, n) => `versão ${v} · ${n} regras`,
    effect_Allow: "Permitir", effect_Deny: "Bloquear", effect_RequireApproval: "Pedir aprovação",
    any_tool: "qualquer ferramenta", any_server: "em qualquer servidor", in_server: (s) => `em ${s}`,
    when: "quando", and: "e",
    c_within: (k, v) => `${k} está dentro de ${v}`, c_exact: (k, v) => `${k} é ${v}`,
    c_prefix: (k, v) => `${k} começa com ${v}`,
    rule_default_t: "Todo o resto", rule_default_d: "Qualquer chamada que nenhuma regra cubra é bloqueada (default deny).",
    allow_all_tag: "Permite tudo",
    pol_note: "Os processos wrap leem a política ao iniciar: reinicie seu cliente MCP depois de alterá-la.",
    int_ok: "O journal está íntegro.", int_fail: "Foram encontradas falhas",
    verified_n: (ok, total, failed) => `${ok} de ${total} recibos verificados, ${failed} falhas`,
    head: "Journal head",
    head_text: (n, seq, u) => `${n} entradas encadeadas, próximo seq ${seq}, ${u} não encadeadas anteriores`,
    head_none: (c, u) => `Sem head (${c} encadeadas, ${u} não encadeadas)`,
    head_warn: "Guarde este head fora desta máquina e passe-o como --expected-head: sem ele, entradas apagadas no fim do journal não são detectadas.",
    expected_head: (h) => `Comparado com --expected-head ${h}.`,
    failures: "Falhas reportadas pelo verify",
    appr_journal: "Journal de aprovações",
    appr_text: (d, e) => `${d} decisões, ${e} execuções`, appr_none: "Ainda não há decisões de aprovação.",
    checked: "O que o verify confere",
    checked_list: (a, i) => [
      "Hash de integridade de cada recibo",
      `Assinatura do attester (${a})`,
      "Assinatura do intent do agente",
      `Assinatura da autoridade contra ${i} na hora da decisão`,
      "Vínculo de praetore.mode",
      "Ordem do journal (seq e link hash)",
      "Journal de aprovações: assinatura do aprovador, vínculo com a chamada retida, expiração, uso único",
    ],
    observe_note: "Um recibo observe registra uma decisão que NÃO foi aplicada.",
    verify_error: "o verify não pôde rodar",
    warn_allow_all: (rules, n) => `Suas regras incluem uma que permite tudo (${rules}): qualquer ação sem regra de bloqueio ou aprovação passa sem controle.`,
    note_allow_all: (rules) => `A política tem uma regra que permite tudo (${rules}). Ainda não há recibos em modo enforce.`,
    policy_error: "Não foi possível ler a política",
    load_error: "Não foi possível carregar /api/state",
    unreadable: "Linha ilegível",
  },
};

const VIEWS = ["operation", "info"];
const INFO_TABS = ["log", "approvals", "policy", "integrity", "stats"];
const LIVE_KEY = "praetore-mcp-dashboard-live";
const LANG_KEY = "praetore-mcp-dashboard-lang";
const POLL_MS = 3000;

let lang = "es";
let view = "operation";
let infoTab = "log";
let state = null;
let selected = null; // the receipt shown in the drawer
const PAGE = 100;
let pageOffset = 0;
let reloadQueued = false;
let searchTimer = null;
let drawerTab = "summary";
let decisionFilter = "";
let fingerprint = null;
let knownIds = null;
let knownPending = null;
const freshIds = new Set();
let loading = false;
let live = true;
let lastLoadedAt = null;

// ---------- helpers ----------

function t(key, ...args) {
  const value = (I18N[lang] && I18N[lang][key]) ?? I18N.es[key] ?? key;
  return typeof value === "function" ? value(...args) : value;
}

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.className = v;
    // The CSP has no 'unsafe-inline' for styles: a style attribute would be
    // dropped, so styles go through the CSSOM.
    else if (k === "style") node.style.cssText = v;
    else if (k === "onclick") node.addEventListener("click", v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : String(child));
  }
  return node;
}

function storageGet(store, key) {
  try { return store.getItem(key); } catch (_) { return null; }
}

function storageSet(store, key, value) {
  try { store.setItem(key, value); } catch (_) { /* this page only */ }
}

function toolLabel(tool) {
  if (typeof tool !== "string") return "-";
  return (TOOLS[lang] && TOOLS[lang][tool]) || tool;
}

function decisionClass(decision) {
  return decision === "ALLOW" ? "ok" : decision === "DENY" ? "bad" : "warn";
}

function decisionTag(decision) {
  return el("span", { class: `tag ${decisionClass(decision)}` }, t(`d_${decision}`));
}

function basename(path) {
  if (typeof path !== "string") return "";
  const parts = path.split("/").filter(Boolean);
  return parts.length ? parts[parts.length - 1] : path;
}

// The main object of a call, for a one-line description.
function targetOf(args) {
  if (!args || typeof args !== "object") return { short: "", full: "" };
  if (args.omitted === true) return { short: t("omitted", args.bytes, args.sha256), full: "" };
  if (typeof args.source === "string" && typeof args.destination === "string") {
    return { short: `${basename(args.source)} → ${basename(args.destination)}`, full: `${args.source} → ${args.destination}` };
  }
  if (typeof args.path === "string") return { short: basename(args.path) || args.path, full: args.path };
  if (Array.isArray(args.paths)) {
    return { short: args.paths.map(basename).join(", "), full: args.paths.join(", ") };
  }
  const first = Object.values(args).find((v) => typeof v === "string");
  return { short: first || "", full: first || "" };
}

function argsText(args) {
  if (args === null || args === undefined) return "-";
  if (args && args.omitted === true) return t("omitted", args.bytes, args.sha256);
  return JSON.stringify(args, null, 2);
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
    year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function relativeText(iso) {
  const date = new Date(iso);
  if (!iso || Number.isNaN(date.getTime())) return "-";
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: "auto" });
  const abs = Math.abs(seconds);
  if (abs < 45) return rtf.format(seconds, "second");
  if (abs < 2700) return rtf.format(Math.round(seconds / 60), "minute");
  if (abs < 79200) return rtf.format(Math.round(seconds / 3600), "hour");
  return rtf.format(Math.round(seconds / 86400), "day");
}

function approvalLabel(value) {
  if (!value) return null;
  if (value === "pending") return { text: t("ap_pending"), cls: "warn" };
  if (value === "held") return { text: t("ap_held"), cls: "neutral" };
  if (value === "executed once") return { text: t("ap_executed"), cls: "ok" };
  if (value === "enforce would ask") return { text: t("ap_would"), cls: "neutral" };
  if (value.startsWith("approve")) return { text: t("ap_approve"), cls: "ok" };
  if (value.startsWith("reject")) return { text: t("ap_reject"), cls: "bad" };
  return { text: value, cls: "neutral" };
}

function copyButton(text) {
  const button = el("button", { type: "button", class: "btn-sm copy" }, t("copy"));
  button.addEventListener("click", async (event) => {
    event.stopPropagation();
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = t("copied");
      setTimeout(() => { button.textContent = t("copy"); }, 1500);
    } catch (_) {
      button.textContent = "×";
    }
  });
  return button;
}

function copyButtonLabeled(text, label) {
  const button = el("button", { type: "button", class: "btn-ok" }, label);
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = t("copied");
      setTimeout(() => { button.textContent = label; }, 1800);
    } catch (_) {
      button.textContent = "×";
    }
  });
  return button;
}

function kv(pairs) {
  const box = el("div", { class: "kv" });
  for (const [k, v] of pairs) {
    box.append(el("div", { class: "k" }, k));
    box.append(el("div", { class: "v mono" }, v ?? "-"));
  }
  return box;
}

function toast(text, cls, onClick) {
  const node = el("div", { class: `toast ${cls || ""}` }, text);
  if (onClick) node.addEventListener("click", () => { onClick(); node.remove(); });
  document.getElementById("toasts").append(node);
  setTimeout(() => node.remove(), 6000);
}

function pending() {
  return state && Array.isArray(state.pending) ? state.pending : [];
}

function isExpired(p) {
  const at = new Date(p.expires_at).getTime();
  return !Number.isNaN(at) && at <= Date.now();
}

// Pending calls that can still be decided.
function activePending() {
  return pending().filter((p) => !isExpired(p));
}

// ---------- shell ----------

function applyStaticText() {
  document.documentElement.lang = lang;
  for (const node of document.querySelectorAll("[data-i18n]")) {
    node.textContent = t(node.getAttribute("data-i18n"));
  }
  document.getElementById("live-label").textContent = t("live");
  document.getElementById("f-text").setAttribute("placeholder", t("search_ph"));
  document.getElementById("page-title").textContent = t(`nav_${view}`);
  document.getElementById("page-sub").textContent = t(`sub_${view}`);
}

function renderShell() {
  for (const link of document.querySelectorAll("#nav a")) {
    link.classList.toggle("active", link.getAttribute("data-view") === view);
  }
  for (const name of VIEWS) document.getElementById(`view-${name}`).hidden = name !== view;
  if (!state) return;
  const count = activePending().length;
  const badge = document.getElementById("nav-badge");
  badge.hidden = count === 0;
  badge.textContent = String(count);
  document.title = count > 0 ? `(${count}) PRÆTORE MCP` : "PRÆTORE MCP";
  const chip = document.getElementById("mode-chip");
  chip.className = "chip ok";
  chip.textContent = t("mode_readonly");
}

function renderStamp() {
  document.getElementById("updated").textContent =
    lastLoadedAt ? t("updated", relativeText(lastLoadedAt.toISOString())) : "";
}

function go(name) {
  location.hash = `#/${name}`;
}

// ---------- overview ----------

function renderOperation() {
  const root = document.getElementById("view-operation");
  root.replaceChildren();
  const s = state.summary;
  const v = state.verify;
  // One sentence for the state of things: integrity first, then what
  // waits for a person, then calm.
  const count = activePending().length;
  let hero;
  if (v.status === "error") {
    hero = heroCard("bad", "!", t("hero_err_t"), String(v.error), t("see_integrity"), "info/integrity");
  } else if (v.status === "fail") {
    hero = heroCard("bad", "!", t("hero_bad_t"), t("hero_bad_d", v.failed), t("see_integrity"), "info/integrity");
  } else if (count > 0) {
    hero = heroCard("warn", "", t("cta_pending", count), t("cta_sub"), null);
  } else if (s.total === 0) {
    hero = heroCard("ok", "", t("hero_empty_t"), t("hero_empty_d"), null);
  } else {
    hero = heroCard("ok", "", t("hero_ok_t"), t("hero_ok_d", v.verified), t("see_integrity"), "info/integrity");
  }
  root.append(hero);

  const active = activePending();
  const decide = el("section", { class: "op-section" },
    el("h2", { class: "eyebrow" }, active.length ? t("sec_decide_n", active.length) : t("sec_decide")));
  if (active.length === 0) decide.append(el("p", { class: "calm" }, t("decide_none")));
  for (const p of active) decide.append(approvalCard(p));
  root.append(decide);
  root.append(recentCard());
}

function renderStats() {
  const root = document.getElementById("info-stats");
  root.replaceChildren();
  const s = state.summary;
  const pct = (n) => (s.total ? Math.round((n / s.total) * 100) : 0);
  root.append(el("div", { class: "grid kpis" },
    kpi(t("k_total"), s.total, t("k_total_foot", s.enforce_receipts), "var(--ink)", 100),
    kpi(t("k_allow"), s.allow, t("pct", pct(s.allow)), "var(--bar-allow)", pct(s.allow)),
    kpi(t("k_deny"), s.deny, t("pct", pct(s.deny)), "var(--bar-deny)", pct(s.deny)),
    kpi(t("k_ask"), s.require_approval, t("pct", pct(s.require_approval)), "var(--bar-ask)", pct(s.require_approval))));
  const grid = el("div", { class: "grid two section-gap" });
  grid.append(chartCard());
  grid.append(toolsCard());
  root.append(grid);
}

function heroCard(cls, icon, title, text, linkText, target = "info/integrity") {
  return el("div", { class: `card hero ${cls}` },
    el("div", { class: "hero-icon" }, icon),
    el("div", { class: "hero-text" }, el("h2", {}, title), el("p", {}, text)),
    linkText ? el("button", { type: "button", class: "hero-cta", onclick: () => go(target) }, linkText) : null);
}

function kpi(label, value, foot, color, percent) {
  return el("div", { class: "card kpi" },
    el("div", { class: "label" }, el("span", { class: "dot", style: `background:${color}` }), label),
    el("div", { class: "value" }, String(value)),
    el("div", { class: "foot" }, foot),
    el("div", { class: "meter" }, el("span", { style: `width:${percent}%;background:${color}` })));
}

function chartCard() {
  // 15-minute UTC buckets from the server, regrouped by local hour or day.
  const counts = state.activity.buckets;
  const now = new Date();
  const newest = state.recent.length && state.recent[0].decided_at ? new Date(state.recent[0].decided_at) : now;
  const hourly = now.getTime() - newest.getTime() < 24 * 3600 * 1000;
  const buckets = [];
  if (hourly) {
    const end = new Date(now); end.setMinutes(0, 0, 0);
    for (let i = 23; i >= 0; i -= 1) {
      const start = new Date(end.getTime() - i * 3600 * 1000);
      buckets.push({ start, end: new Date(start.getTime() + 3600 * 1000),
        label: start.toLocaleTimeString(lang, { hour: "2-digit", minute: "2-digit" }) });
    }
  } else {
    const end = new Date(now); end.setHours(0, 0, 0, 0);
    for (let i = 13; i >= 0; i -= 1) {
      const start = new Date(end); start.setDate(end.getDate() - i);
      const stop = new Date(start); stop.setDate(start.getDate() + 1);
      buckets.push({ start, end: stop, label: start.toLocaleDateString(lang, { day: "2-digit", month: "short" }) });
    }
  }
  for (const b of buckets) { b.ALLOW = 0; b.DENY = 0; b.REQUIRE_APPROVAL = 0; }
  for (const c of counts) {
    const time = c.start * 1000;
    const b = buckets.find((x) => time >= x.start.getTime() && time < x.end.getTime());
    if (!b) continue;
    for (const key of ["ALLOW", "DENY", "REQUIRE_APPROVAL"]) b[key] += c[key];
  }
  const max = Math.max(1, ...buckets.map((b) => b.ALLOW + b.DENY + b.REQUIRE_APPROVAL));
  const chart = el("div", { class: "chart" });
  const colors = { ALLOW: "var(--bar-allow)", DENY: "var(--bar-deny)", REQUIRE_APPROVAL: "var(--bar-ask)" };
  for (const b of buckets) {
    const total = b.ALLOW + b.DENY + b.REQUIRE_APPROVAL;
    const col = el("div", { class: "col",
      title: `${b.label} · ${t("d_ALLOW")} ${b.ALLOW} · ${t("d_DENY")} ${b.DENY} · ${t("d_REQUIRE_APPROVAL")} ${b.REQUIRE_APPROVAL}` });
    for (const key of ["ALLOW", "REQUIRE_APPROVAL", "DENY"]) {
      if (b[key] > 0) col.append(el("div", { class: "seg", style: `height:${(b[key] / max) * 100}%;background:${colors[key]}` }));
    }
    if (total === 0) col.append(el("div", { class: "seg", style: "height:2px;background:var(--line)" }));
    chart.append(col);
  }
  const mid = buckets[Math.floor(buckets.length / 2)];
  return el("div", { class: "card" },
    el("div", { class: "card-head" }, el("h2", {}, t("chart_title")),
      el("div", { class: "legend" },
        el("span", {}, el("i", { style: "background:var(--bar-allow)" }), t("d_ALLOW")),
        el("span", {}, el("i", { style: "background:var(--bar-deny)" }), t("d_DENY")),
        el("span", {}, el("i", { style: "background:var(--bar-ask)" }), t("d_REQUIRE_APPROVAL")))),
    el("p", { class: "card-sub" }, hourly ? t("chart_hours") : t("chart_days")),
    chart,
    el("div", { class: "chart-axis" },
      el("span", {}, buckets[0].label), el("span", {}, mid.label), el("span", {}, buckets[buckets.length - 1].label)));
}

function toolsCard() {
  const top = state.tools.slice(0, 6).map((x) => [x.tool, x.count]);
  const max = Math.max(1, ...top.map(([, n]) => n));
  const bars = el("div", { class: "bars" });
  for (const [tool, n] of top) {
    bars.append(el("div", { class: "row" },
      el("span", { title: tool }, toolLabel(tool)), el("span", { class: "muted" }, String(n)),
      el("div", { class: "track" }, el("span", { style: `width:${(n / max) * 100}%` }))));
  }
  if (top.length === 0) bars.append(el("p", { class: "muted" }, t("empty_recent")));
  return el("div", { class: "card" }, el("h2", {}, t("tools_title")), el("p", { class: "card-sub" }, t("tools_sub")), bars);
}

function recentCard() {
  const list = el("ul", { class: "feed" });
  const rows = state.recent;
  for (const r of rows) {
    const target = targetOf(r.arguments);
    // For a held call, what the client cares about is how it ended.
    const outcome = r.decision === "REQUIRE_APPROVAL" ? approvalLabel(r.approval) : null;
    const cls = outcome ? outcome.cls : decisionClass(r.decision);
    const li = el("li", { class: freshIds.has(r.evidence_id) ? "fresh" : "", onclick: () => openDrawer(r) },
      el("span", { class: `avatar ${cls}` }),
      el("div", { class: "what" },
        el("strong", {}, toolLabel(r.tool)),
        el("div", { class: "target", title: target.full }, target.short || r.server || "")),
      outcome ? el("span", { class: `tag ${outcome.cls}` }, outcome.text) : decisionTag(r.decision),
      el("time", { title: localText(r.decided_at) }, relativeText(r.decided_at)));
    list.append(li);
  }
  if (rows.length === 0) list.append(el("li", { class: "muted" }, t("empty_recent")));
  return el("section", { class: "op-section" },
    el("div", { class: "card-head" }, el("h2", { class: "eyebrow" }, t("sec_live")),
      el("a", { href: "#/info/log" }, t("see_log"))),
    list);
}

// ---------- approvals ----------

function renderApprovalsInfo() {
  const root = document.getElementById("info-approvals");
  root.replaceChildren();
  if (state.pending && !Array.isArray(state.pending)) {
    root.append(el("p", { class: "alert bad" }, String(state.pending.error)));
  }
  root.append(historyCard());
}

function approvalCard(p) {
  const receipt = p.receipt;
  const start = receipt ? new Date(receipt.decided_at).getTime() : NaN;
  const expires = new Date(p.expires_at).getTime();
  const left = Math.floor((expires - Date.now()) / 1000);
  const expired = !Number.isNaN(left) && left <= 0;
  let args = null;
  try { args = JSON.parse(p.arguments_canonical); } catch (_) { args = null; }
  const target = targetOf(args);
  const total = Number.isNaN(start) ? 600 : Math.max(1, (expires - start) / 1000);

  const card = el("div", { class: expired ? "card approval expired" : "card approval" });
  card.append(el("div", { class: "approval-head" },
    el("div", {},
      el("p", { class: "approval-title" },
        `${t("agent_wants")} ${toolLabel(p.tool).toLowerCase()}`, target.short ? `: ${target.short}` : "",
        el("small", {}, `${t("on_server", p.server)} · ${p.tool}`))),
    el("span", { class: expired ? "tag bad" : "tag warn countdown", "data-expires": p.expires_at },
      expired ? t("expired") : t("expires_in", Math.floor(left / 60), left % 60))));
  if (p.signed === false) {
    card.append(el("p", { class: "unsigned" }, el("span", { class: "tag neutral" }, t("unsigned_tag")), ` ${t("unsigned_note")}`));
  }
  card.append(el("div", { class: "countdown-bar" },
    el("span", { class: "countdown-fill", "data-expires": p.expires_at, "data-total": String(total),
      style: `width:${Math.max(0, Math.min(100, (left / total) * 100))}%` })));

  if (p.error) {
    card.append(el("p", { class: "alert bad mono" }, p.error));
    return card;
  }
  card.append(el("div", { class: "label-sm" }, t("exact_args")));
  card.append(el("div", { class: "code-box" }, el("pre", {}, p.arguments_canonical)));
  card.append(el("p", { class: "muted" }, t("exact_args_hint")));

  if (!expired) {
    const commands = `praetore-mcp approve ${p.approval_id} --dir ${state.home}\npraetore-mcp reject ${p.approval_id} --dir ${state.home}`;
    card.append(el("div", { class: "label-sm" }, t("cli_hint")));
    card.append(el("div", { class: "code-box" }, el("pre", {}, commands)));
  }
  const actions = el("div", { class: "actions" });
  if (!expired) {
    const commands = `praetore-mcp approve ${p.approval_id} --dir ${state.home}`;
    actions.append(copyButtonLabeled(commands, t("copy_approve")));
  }
  if (receipt) {
    actions.append(el("button", { type: "button", onclick: () => openDrawer(receipt) }, t("view_receipt")));
  }
  card.append(actions);
  return card;
}

function historyCard() {
  const rows = state.approval_history;
  const card = el("div", { class: "card flush" });
  card.append(el("div", { class: "card-pad" },
    el("h2", {}, t("history")), el("p", { class: "card-sub" }, t("history_sub"))));
  if (rows.length === 0) {
    card.append(el("div", { class: "empty" }, t("history_none")));
    return card;
  }
  const body = el("tbody", {});
  for (const r of rows) {
    const target = targetOf(r.arguments);
    const label = approvalLabel(r.approval);
    body.append(el("tr", { onclick: () => openDrawer(r) },
      el("td", { class: "cell-when" }, relativeText(r.decided_at), el("small", {}, localText(r.decided_at))),
      el("td", { class: "cell-action" }, el("strong", {}, toolLabel(r.tool)),
        el("div", { class: "target", title: target.full }, target.short)),
      el("td", {}, label ? el("span", { class: `tag ${label.cls}` }, label.text) : "-")));
  }
  card.append(el("div", { class: "table-wrap" }, el("table", { class: "data" },
    el("thead", {}, el("tr", {}, el("th", {}, t("c_when")), el("th", {}, t("c_action")), el("th", {}, t("f_approval")))),
    body)));
  return card;
}

// ---------- activity ----------

function renderDecisionFilter() {
  const box = document.getElementById("f-decision");
  box.replaceChildren();
  for (const [value, label] of [["", t("all")], ["ALLOW", t("d_ALLOW")], ["DENY", t("d_DENY")], ["REQUIRE_APPROVAL", t("d_REQUIRE_APPROVAL")]]) {
    const button = el("button", { type: "button", class: decisionFilter === value ? "on" : "" }, label);
    button.addEventListener("click", () => { decisionFilter = value; renderDecisionFilter(); filtersChanged(); });
    box.append(button);
  }
}

function renderToolFilter() {
  const select = document.getElementById("f-tool");
  const current = select.value;
  const tools = state.tools.map((x) => x.tool).sort();
  select.replaceChildren(el("option", { value: "" }, t("all_tools")));
  for (const tool of tools) select.append(el("option", { value: tool }, `${toolLabel(tool)} · ${tool}`));
  if (tools.includes(current)) select.value = current;
}

// A datetime-local value (local time, to the minute) as a UTC instant.
// "To" covers the whole minute it names.
function instantOf(value, endOfMinute) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  if (endOfMinute) date.setSeconds(59, 999);
  return date.toISOString();
}

// The filters are applied by the server, over the whole journal.
function stateUrl() {
  const params = new URLSearchParams();
  const tool = document.getElementById("f-tool").value;
  const text = document.getElementById("f-text").value.trim();
  const from = instantOf(document.getElementById("f-from").value, false);
  const to = instantOf(document.getElementById("f-to").value, true);
  if (decisionFilter) params.set("decision", decisionFilter);
  if (tool) params.set("tool", tool);
  if (text) params.set("q", text);
  if (from) params.set("from", from);
  if (to) params.set("to", to);
  params.set("offset", String(pageOffset));
  params.set("limit", String(PAGE));
  return `/api/state?${params}`;
}

function filtersChanged() {
  pageOffset = 0;
  fingerprint = null;
  load();
}

function goPage(offset) {
  pageOffset = Math.max(0, offset);
  fingerprint = null;
  load();
}

function renderTable() {
  const body = document.querySelector("#table tbody");
  body.replaceChildren();
  const page = state.page;
  const rows = page.receipts;
  for (const r of rows) {
    const classes = [];
    if (selected && r.evidence_id && selected.evidence_id === r.evidence_id) classes.push("selected");
    if (freshIds.has(r.evidence_id)) classes.push("fresh");
    const tr = el("tr", { class: classes.join(" "), onclick: () => openDrawer(r) });
    if (r.parse_error) {
      tr.append(el("td", { colspan: "6", class: "mono" },
        el("span", { class: "tag bad" }, t("unreadable")), ` ${r.location.file}:${r.location.line}: ${r.parse_error}`));
    } else {
      const target = targetOf(r.arguments);
      const label = approvalLabel(r.approval);
      tr.append(
        el("td", { class: "cell-when", title: utcText(r.decided_at) }, relativeText(r.decided_at), el("small", {}, localText(r.decided_at))),
        el("td", { class: "cell-action" }, el("strong", {}, toolLabel(r.tool)),
          el("div", { class: "target mono", title: target.full }, target.full || target.short || "-")),
        el("td", {}, r.server ?? "-"),
        el("td", {}, decisionTag(r.decision), label ? el("div", { class: "muted", style: "font-size:12px;margin-top:4px" }, label.text) : null),
        el("td", { class: "mono" }, r.rule ?? t("default_deny")),
        el("td", {}, el("span", { class: `check-icon ${r.verified ? "ok" : "bad"}`, title: r.verified ? t("st_ok") : t("st_fail") },
          r.verified ? "✓" : "✕")));
    }
    body.append(tr);
  }
  document.getElementById("shown").textContent = rows.length
    ? t("shown_range", page.offset + 1, page.offset + rows.length, page.matching)
    : t("shown", 0, page.matching);
  const newer = document.getElementById("page-newer");
  const older = document.getElementById("page-older");
  newer.textContent = t("page_newer");
  older.textContent = t("page_older");
  newer.disabled = page.offset === 0;
  older.disabled = page.offset + rows.length >= page.matching;
  const empty = document.getElementById("table-empty");
  empty.hidden = rows.length > 0;
  const none = state.summary.total === 0;
  empty.replaceChildren(el("strong", {}, none ? t("empty_home_t") : t("empty_filter_t")),
    el("p", {}, none ? t("empty_home_d") : t("empty_filter_d")));
}

// ---------- drawer ----------

function openDrawer(r) {
  selected = r;
  drawerTab = "summary";
  if (r && r.evidence_id) history.replaceState(null, "", `#e=${encodeURIComponent(r.evidence_id)}`);
  renderDrawer();
  if (view === "info") renderTable();
}

function closeDrawer() {
  selected = null;
  history.replaceState(null, "", `#/${currentRoute()}`);
  renderDrawer();
  if (view === "info") renderTable();
}

function renderDrawer() {
  const drawer = document.getElementById("drawer");
  const scrim = document.getElementById("scrim");
  const r = selected;
  if (!r) {
    drawer.classList.remove("open");
    drawer.setAttribute("aria-hidden", "true");
    scrim.hidden = true;
    return;
  }
  drawer.classList.add("open");
  drawer.setAttribute("aria-hidden", "false");
  scrim.hidden = false;
  const target = targetOf(r.arguments);
  document.getElementById("drawer-title").replaceChildren(
    r.parse_error ? el("span", { class: "tag bad" }, t("unreadable")) : decisionTag(r.decision),
    el("h2", {}, r.parse_error ? t("unreadable") : toolLabel(r.tool)),
    el("div", { class: "target" }, target.full || `${r.location.file}:${r.location.line}`));

  const tabs = document.getElementById("drawer-tabs");
  tabs.replaceChildren();
  const available = r.parse_error ? ["json"] : ["summary", "signatures", "paths", "json"];
  if (!available.includes(drawerTab)) drawerTab = available[0];
  for (const name of available) {
    const button = el("button", { type: "button", class: drawerTab === name ? "on" : "" }, t(`tab_${name}`));
    button.addEventListener("click", () => { drawerTab = name; renderDrawer(); });
    tabs.append(button);
  }
  const body = document.getElementById("drawer-body");
  body.replaceChildren();
  if (drawerTab === "summary") drawerSummary(body, r);
  if (drawerTab === "signatures") drawerSignatures(body, r);
  if (drawerTab === "paths") drawerPaths(body, r);
  if (drawerTab === "json") {
    if (!r.parse_error) {
      body.append(kv([
        ["evidence_id", el("span", {}, r.evidence_id, copyButton(r.evidence_id))],
        [t("f_tool"), r.tool],
        [t("f_mode"), r.mode],
        [t("f_utc"), utcText(r.decided_at)],
        [t("f_policy"), r.policy_digest],
        [t("f_location"), `${r.location.file}:${r.location.line}`],
      ]));
      body.append(el("h3", {}, "JSON"));
    }
    body.append(el("pre", { class: "json" }, r.raw !== null && r.raw !== undefined ? JSON.stringify(r.raw, null, 2) : r.raw_text));
  }
}

function drawerSummary(body, r) {
  const label = approvalLabel(r.approval);
  body.append(kv([
    [t("f_decision"), decisionTag(r.decision)],
    [t("f_rule"), r.rule ?? t("default_deny")],
    [t("f_server"), r.server],
    [t("f_tool"), toolLabel(r.tool)],
    [t("f_local"), localText(r.decided_at)],
    [t("f_approval"), label ? el("span", { class: `tag ${label.cls}` }, label.text) : "-"],
  ]));
  body.append(el("h3", {}, t("args")));
  body.append(el("pre", { class: "json" }, argsText(r.arguments)));
}

function sigBlock(name, keyLines, check) {
  const cls = check.status === "ok" ? "ok" : check.status === "fail" ? "bad" : "neutral";
  return el("div", { class: "sig" },
    el("div", { class: `sig-icon ${cls}` }, cls === "ok" ? "✓" : cls === "bad" ? "✕" : "–"),
    el("div", { class: "sig-name" }, name),
    el("span", { class: `tag ${cls}` }, t(`st_${check.status}`)),
    el("div", { class: "sig-key mono" }, ...keyLines.flatMap((line, i) => (i ? [el("br"), line] : [line]))),
    check.error ? el("div", { class: "sig-key mono", style: "color:var(--bad)" }, check.error) : null);
}

function drawerSignatures(body, r) {
  const s = r.signatures;
  body.append(el("h3", {}, t("sig_title")));
  body.append(sigBlock(t("sig_agent"), [`agent_id ${s.agent.agent_id}`, `subject_key_hash ${s.agent.subject_key_hash ?? "-"}`], s.agent.check));
  body.append(sigBlock(t("sig_attester"), [`attester_key_id ${s.attester.key_id ?? "-"}`], s.attester.check));
  body.append(sigBlock(t("sig_authority"), [`issuer ${s.authority.issuer}`, `issuer_key_id ${s.authority.key_id ?? "-"}`,
    `authority_id ${s.authority.authority_id}`], s.authority.check));
  body.append(el("h3", {}, t("other_checks")));
  const table = el("table", { class: "mini" });
  const tbody = el("tbody", {});
  for (const name of ["shape", "authority_subject", "audience", "mode"]) {
    const check = r.checks[name] || { status: "not_run", error: null };
    const cls = check.status === "ok" ? "ok" : check.status === "fail" ? "bad" : "neutral";
    tbody.append(el("tr", {}, el("td", {}, t(`chk_${name}`)),
      el("td", {}, el("span", { class: `tag ${cls}` }, t(`st_${check.status}`)), check.error ? ` ${check.error}` : "")));
  }
  table.append(tbody);
  body.append(table);
  body.append(el("h3", {}, t("chain")));
  if (r.seq === null || r.seq === undefined) body.append(el("p", {}, t("unchained")));
  else body.append(kv([["seq", String(r.seq)], ["prev", r.prev]]));
  body.append(el("p", {}, r.order
    ? el("span", { class: "tag bad" }, r.order)
    : el("span", { class: "tag ok" }, t("order_ok"))));
}

function drawerPaths(body, r) {
  body.append(el("p", { class: "muted" }, t("path_desc")));
  if (!r.path_check || typeof r.path_check !== "object") {
    body.append(el("p", { class: "muted" }, t("path_none")));
    return;
  }
  const tbody = el("tbody", {});
  for (const [key, value] of Object.entries(r.path_check)) {
    tbody.append(el("tr", {},
      el("td", { class: "mono" }, key),
      el("td", { class: "mono" }, value.lexical ?? "-"),
      el("td", { class: "mono" }, value.resolved ?? "-"),
      el("td", {}, el("span", { class: `tag ${value.status === "same" ? "ok" : "warn"}` }, value.status ?? "-"))));
  }
  body.append(el("div", { class: "table-wrap" }, el("table", { class: "mini" },
    el("thead", {}, el("tr", {}, el("th", {}, "key"), el("th", {}, t("lexical")), el("th", {}, t("resolved")), el("th", {}, t("status")))),
    tbody)));
}

// ---------- policy ----------

function conditionText(c) {
  const key = c.key;
  const value = typeof c.expected === "string" ? c.expected : JSON.stringify(c.expected);
  if (c.operator === "PathPrefix") return t("c_within", key, value);
  if (c.operator === "Exact") return t("c_exact", key, value);
  if (c.operator === "Prefix") return t("c_prefix", key, value);
  return JSON.stringify(c);
}

function ruleSentence(rule) {
  const conditions = rule.parameter_conditions || [];
  const toolCond = conditions.find((c) => c.key === "tool" && c.operator === "Exact");
  const others = conditions.filter((c) => c !== toolCond).map(conditionText);
  for (const c of rule.context_conditions || []) others.push(`context: ${conditionText(c)}`);
  const tool = toolCond ? `${toolLabel(toolCond.expected).toLowerCase()} (${toolCond.expected})` : t("any_tool");
  const server = rule.target ? t("in_server", rule.target) : t("any_server");
  let sentence = `${t(`effect_${rule.effect}`)}: ${tool} ${server}`;
  if (others.length) sentence += `, ${t("when")} ${others.join(` ${t("and")} `)}`;
  return sentence;
}

function effectClass(effect) {
  return effect === "Allow" ? "ok" : effect === "Deny" ? "bad" : "warn";
}

function renderPolicy() {
  const root = document.getElementById("info-policy");
  root.replaceChildren();
  const p = state.policy;
  if (p.status === "ok" && p.allow_all_rules.length > 0) {
    root.append(el("p", { class: "alert bad" }, t("warn_allow_all", p.allow_all_rules.join(", "), state.summary.enforce_receipts)));
  }
  if (p.status !== "ok") {
    root.append(el("p", { class: "alert bad mono" }, `${t("policy_error")}: ${p.error}`));
    return;
  }
  const rules = Array.isArray(p.rules_detail) ? p.rules_detail : [];
  root.append(el("div", { class: "card" },
    el("div", { class: "card-head" },
      el("div", {}, el("h2", {}, `${t("pol_active")}: ${p.id}`), el("p", { class: "card-sub" }, t("pol_meta", p.version, rules.length)))),
    kv([["digest", el("span", {}, p.digest ?? "-", p.digest ? copyButton(p.digest) : null)], ["path", p.path]]),
    el("p", { class: "muted section-gap" }, t("pol_note"))));

  const list = el("div", { class: "card section-gap" });
  for (const rule of rules) {
    const allowAll = p.allow_all_rules.includes(rule.id);
    list.append(el("div", { class: allowAll ? "rule allow-all" : "rule" },
      el("div", { class: "effect" }, el("span", { class: `tag ${effectClass(rule.effect)}` }, t(`effect_${rule.effect}`))),
      el("div", { class: "rule-text" },
        el("p", {}, ruleSentence(rule)),
        el("div", { class: "rule-id mono" }, rule.id, allowAll ? el("span", { class: "tag warn plain", style: "margin-left:8px" }, t("allow_all_tag")) : null))));
  }
  list.append(el("div", { class: "rule" },
    el("div", { class: "effect" }, el("span", { class: "tag bad" }, t("effect_Deny"))),
    el("div", { class: "rule-text" }, el("p", {}, el("strong", {}, t("rule_default_t"))), el("div", { class: "muted" }, t("rule_default_d")))));
  root.append(list);
}

// ---------- integrity ----------

function renderIntegrity() {
  const root = document.getElementById("info-integrity");
  root.replaceChildren();
  const v = state.verify;
  if (v.status === "error") {
    root.append(el("p", { class: "alert bad" }, `${t("verify_error")}: ${v.error}`));
    return;
  }
  root.append(heroCard(v.status === "ok" ? "ok" : "bad", v.status === "ok" ? "✓" : "!",
    v.status === "ok" ? t("int_ok") : t("int_fail"), t("verified_n", v.verified, v.total, v.failed), null));
  if (v.failures.length > 0) {
    const ul = el("ul", { class: "mono" });
    for (const f of v.failures) ul.append(el("li", {}, f));
    root.append(el("div", { class: "card section-gap" }, el("h2", {}, t("failures")), ul));
  }
  const head = el("div", { class: "card section-gap" }, el("h2", {}, t("head")));
  if (v.head) {
    head.append(el("p", { class: "card-sub" }, t("head_text", v.chained, v.head.next_seq, v.unchained)));
    head.append(el("div", { class: "hash" }, el("span", { class: "mono" }, v.head.prev), copyButton(v.head.prev)));
  } else {
    head.append(el("p", { class: "card-sub" }, t("head_none", v.chained, v.unchained)));
  }
  head.append(el("p", { class: "alert warn section-gap" }, t("head_warn")));
  if (v.expected_head) head.append(el("p", { class: "mono" }, t("expected_head", v.expected_head)));
  root.append(head);

  const appr = el("div", { class: "card section-gap" }, el("h2", {}, t("appr_journal")));
  if (v.approval.head) {
    appr.append(el("p", { class: "card-sub" }, t("appr_text", v.approval.decisions, v.approval.executions)));
    appr.append(el("div", { class: "hash" }, el("span", { class: "mono" }, v.approval.head), copyButton(v.approval.head)));
  } else {
    appr.append(el("p", { class: "card-sub" }, t("appr_none")));
  }
  root.append(appr);

  root.append(el("div", { class: "card section-gap" }, el("h2", {}, t("home_dir")),
    el("div", { class: "hash" }, el("span", { class: "mono" }, state.home), copyButton(state.home))));
  const list = el("ul", { class: "checklist" });
  for (const item of t("checked_list", v.attester_pin, v.issuer_pins)) list.append(el("li", {}, item));
  root.append(el("div", { class: "card section-gap" }, el("h2", {}, t("checked")), list,
    el("p", { class: "muted section-gap" }, t("observe_note"))));
}

// ---------- render + load ----------

function renderSubnav() {
  const nav = document.getElementById("subnav");
  nav.replaceChildren();
  for (const tab of INFO_TABS) {
    nav.append(el("a", { href: `#/info/${tab}`, class: tab === infoTab ? "on" : "" }, t(`it_${tab}`)));
    document.getElementById(`info-${tab}`).hidden = tab !== infoTab;
  }
}

function renderAll() {
  applyStaticText();
  renderShell();
  renderStamp();
  renderSubnav();
  if (!state) return;
  renderOperation();
  renderApprovalsInfo();
  renderDecisionFilter();
  renderToolFilter();
  renderTable();
  renderPolicy();
  renderIntegrity();
  renderStats();
  renderDrawer();
}

function fingerprintOf(s) {
  return JSON.stringify([
    s.summary, s.verify && s.verify.status, s.verify && s.verify.head, s.verify && s.verify.failed,
    s.verify && s.verify.approval, s.pending, s.policy && s.policy.digest, s.policy && s.policy.status,
    s.page.offset, s.page.matching, s.page.receipts.map((r) => [r.evidence_id, r.approval]),
    s.recent.map((r) => [r.evidence_id, r.approval]),
  ]);
}

function announce(next) {
  const ids = new Set(next.recent.map((r) => r.evidence_id).filter(Boolean));
  const pendingIds = new Set((Array.isArray(next.pending) ? next.pending : []).map((p) => p.approval_id));
  if (knownIds) {
    for (const id of ids) if (!knownIds.has(id)) freshIds.add(id);
    const added = Math.max(0, next.summary.total - state.summary.total);
    let newPending = 0;
    for (const id of pendingIds) if (!knownPending.has(id)) newPending += 1;
    if (newPending > 0) toast(t("toast_pending"), "warn", () => go("operation"));
    else if (added > 0) toast(t("toast_new", added), "", () => go("operation"));
  }
  knownIds = ids;
  knownPending = pendingIds;
}

async function load() {
  if (loading) { reloadQueued = true; return; }
  loading = true;
  const error = document.getElementById("load-error");
  try {
    const response = await fetch(stateUrl(), { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const next = await response.json();
    error.hidden = true;
    const firstLoad = state === null;
    announce(next);
    state = next;
    lastLoadedAt = new Date();
    if (firstLoad) routeFromHash();
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
    if (reloadQueued) { reloadQueued = false; load(); }
  }
}

// A receipt named by #e=<evidence_id>: from what is loaded, or asked for.
async function openEvidence(id) {
  const loaded = [...state.page.receipts, ...state.recent, ...state.approval_history,
    ...(Array.isArray(state.pending) ? state.pending.map((p) => p.receipt).filter(Boolean) : [])];
  const found = loaded.find((r) => r.evidence_id === id);
  if (found) { openDrawer(found); return; }
  try {
    const response = await fetch(`/api/receipt?${new URLSearchParams({ id })}`, { cache: "no-store" });
    if (response.ok) openDrawer(await response.json());
  } catch (_) { /* the link names no receipt here */ }
}

// #/operation, #/info/<tab>; #e=<evidence_id> opens that receipt over the
// log. Older links (#/overview, #/activity, #/policy...) still land.
const LEGACY = {
  overview: ["operation"], approvals: ["operation"], activity: ["info", "log"],
  policy: ["info", "policy"], integrity: ["info", "integrity"],
};
function routeFromHash() {
  const hash = location.hash;
  const evidence = hash.match(/^#e=(.+)$/);
  if (evidence) {
    if (state) openEvidence(decodeURIComponent(evidence[1]));
    return;
  }
  const match = hash.match(/^#\/([a-z]+)(?:\/([a-z]+))?/);
  let [name, tab] = match ? [match[1], match[2]] : ["operation", undefined];
  if (LEGACY[name]) [name, tab] = LEGACY[name];
  view = VIEWS.includes(name) ? name : "operation";
  if (view === "info") infoTab = INFO_TABS.includes(tab) ? tab : "log";
}

function currentRoute() {
  return view === "info" ? `info/${infoTab}` : view;
}

// Ticks the approval countdowns and the "updated" stamp without a reload.
function tick() {
  renderStamp();
  for (const node of document.querySelectorAll(".countdown[data-expires]")) {
    const left = Math.floor((new Date(node.getAttribute("data-expires")).getTime() - Date.now()) / 1000);
    if (Number.isNaN(left)) continue;
    if (left <= 0) { fingerprint = null; if (state) renderOperation(); return; }
    node.textContent = t("expires_in", Math.floor(left / 60), left % 60);
  }
  for (const node of document.querySelectorAll(".countdown-fill[data-expires]")) {
    const left = (new Date(node.getAttribute("data-expires")).getTime() - Date.now()) / 1000;
    const total = Number(node.getAttribute("data-total")) || 600;
    node.style.width = `${Math.max(0, Math.min(100, (left / total) * 100))}%`;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const stored = storageGet(localStorage, LANG_KEY);
  const nav = (navigator.language || "es").slice(0, 2);
  lang = I18N[stored] ? stored : I18N[nav] ? nav : "es";
  routeFromHash();
  const select = document.getElementById("lang");
  select.value = lang;
  select.addEventListener("change", () => {
    lang = I18N[select.value] ? select.value : "es";
    storageSet(localStorage, LANG_KEY, lang);
    renderAll();
  });
  window.addEventListener("hashchange", () => {
    if (/^#e=/.test(location.hash)) return;
    routeFromHash();
    selected = null;
    renderAll();
    window.scrollTo(0, 0);
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
  document.getElementById("f-tool").addEventListener("change", filtersChanged);
  document.getElementById("f-from").addEventListener("change", filtersChanged);
  document.getElementById("f-to").addEventListener("change", filtersChanged);
  document.getElementById("f-text").addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(filtersChanged, 250);
  });
  document.getElementById("page-newer").addEventListener("click", () => goPage(pageOffset - PAGE));
  document.getElementById("page-older").addEventListener("click", () => goPage(pageOffset + PAGE));
  document.getElementById("drawer-close").addEventListener("click", closeDrawer);
  document.getElementById("scrim").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    if (selected !== null) closeDrawer();
  });
  setInterval(() => { if (live && !document.hidden) load(); }, POLL_MS);
  setInterval(tick, 1000);
  document.addEventListener("visibilitychange", () => { if (live && !document.hidden) load(); });
  applyStaticText();
  renderShell();
  load();
});
