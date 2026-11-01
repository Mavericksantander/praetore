# SAF-14 · Identidad por agente: una llave y una autoridad por agente (propuesta)

Estado: **propuesta**, con una parte implementada en el ejemplo
`examples/claude-code-hook` (§12). Todas las decisiones están marcadas
**PROPUESTA**; ninguna está decidida.
Base: `origin/main` en `dfbe047` (#75).
Nombre: SAF-12 está tomado por #58 (abierto) y SAF-13 está en `main`
(`SAF-13-anclaje-del-head-del-journal.md`). Ninguna rama remota menciona
SAF-14 (revisado con `git grep SAF-14` sobre todas las ramas de `origin`).
Relación:
- SAF-11 (#44 propuesta, #73 trait `Signer` y PKCS#11/KMS, abiertos): dónde
  viven las llaves. SAF-14 dice **cuántas** llaves de agente hay y qué
  atribuyen; no cambia dónde se guardan (§7).
- ADOPT-01 (#43, abierto): instalación local de `praetore-mcp`. La parte MCP
  de esta propuesta (§4.2) toca `init`, `wrap` e `install`.

La frase de partida del fundador: *"hoy la firma identifica al perfil, no al
agente"*. §1 dice con exactitud qué identifica hoy la firma en cada
componente. Resumen: en `praetore-mcp` identifica a la **instalación** (una
llave por home); en el hook de Claude Code identifica al **perfil**
(`agent_type`), no a la instancia; el gateway no tiene llaves de agente.

## 1. Hechos (en `dfbe047`)

### 1.1 praetore-core y praetore-verify

- `AgentId` es un UUID v4 aleatorio, sin relación con la llave
  (`crates/praetore-core/src/identity.rs:17-27`). `AgentIdentity` es
  `{id, public_key, key_algorithm}` (`identity.rs:52-58`). Una `AgentKeyPair`
  produce la identidad con el id que se le pase (`identity.rs:171`).
- La autoridad liga sujeto y llave: `Authority::sign_for_agent` exige
  `subject == agent.id` y fija `subject_key_hash` = huella de la llave
  pública antes de firmar con la llave del emisor
  (`crates/praetore-core/src/authority.rs:191-216`).
  `verify_subject_identity` comprueba ambas cosas (`authority.rs:218-233`).
  La firma del emisor cubre sujeto, huella, capacidades, **constraints** y
  vigencia (`authority.rs:254-285`).
- La firma del agente (intención) cubre `request_id`, la identidad completa,
  la autoridad completa, la acción, `trace_id` y el `context` entero
  (`crates/praetore-core/src/authorization.rs:100-114`, `170-195`,
  `332-354`).
- La evidencia (el recibo) guarda `agent`, `authority`, `action`, `context`,
  `agent_signature` y la firma del atestador (`evidence.rs:37-66`). El
  atestador firma el recibo entero (`evidence.rs:345-400`);
  `verify_agent_intent` re-verifica la firma del agente desde el recibo
  (`evidence.rs:230-243`).
- El motor estricto rechaza sujeto distinto de agente
  (`engine.rs:1173-1176`), verifica la identidad del sujeto
  (`engine.rs:1204`) y la firma de intención (`engine.rs:1228-1232`). **Los
  constraints de la autoridad se exigen contra los parámetros de la acción**
  (salvo `tenant_id`): un constraint `k=v` deniega si la acción no trae el
  parámetro `k` con valor `v` (`engine.rs:1240-1264`).
- `praetore-verify evidence` verifica atestador, policy y, con
  `--issuer-pins`, `verify_subject_identity` más la autoridad contra los pins
  (`crates/praetore-verify/src/main.rs:297-330`, `553-585`); con
  `--require-intent`, la firma del agente. **No informa ni compara el agent
  id**: cualquier agente con una autoridad del emisor pineado pasa.
- Hallazgo lateral: `praetore-verify` comprueba la vigencia de la autoridad
  **en el instante actual** (`main.rs:310`, `OffsetDateTime::now_utc()`), no
  en el de la decisión. Las autoridades de los sets 04 y 05 vencen el
  `2027-01-29`; desde ese día `verify.sh` fallará en CI sobre esos sets
  aunque nada haya cambiado. `praetore-mcp verify` ya usa la hora de la
  decisión (`crates/praetore-mcp/src/receipts.rs:182`). Ver pregunta 6.

### 1.2 praetore-mcp

- `init` crea **una** llave de agente por home
  (`keys/agent.local-dev.key`, `crates/praetore-mcp/src/store.rs:73-75`,
  `153-182`) con una autoridad de una sola capacidad, `mcp:tools/call`
  (`store.rs:165-169`). No hay perfiles ni nombres de agente.
- `load` lee esa llave y `agent.json` (`store.rs:394-405`); cada `wrap` (uno
  por servidor MCP, `cli.rs:316-340`) construye su gate con el mismo
  `LoadedHome` (`gate.rs:943-944`, `963-964`) y firma cada `tools/call` con
  esa llave (`gate.rs:996-1016`, `sign_intent_v2`).
- Lo único que distingue un servidor de otro en el recibo es
  `action.target` y `parameters.server` (`gate.rs:981`, `94-98`): está
  firmado, pero nombra al **servidor**, no al agente. El cliente MCP (Claude
  Desktop, Claude Code, Cursor) no aparece en ningún campo.
- `praetore-mcp verify` comprueba atestador, intención, sujeto y autoridad a
  la hora de la decisión (`receipts.rs:149-190`); no compara el agente con
  nada.

Conclusión MCP: la firma identifica a la **instalación** (`$PRAETORE_MCP_HOME`).
Todos los servidores envueltos y todos los clientes firman como el mismo
agente. La frase del fundador se queda corta: aquí ni siquiera hay perfil.

### 1.3 examples/claude-code-hook

- `init` ya genera **una llave y una autoridad por perfil**: `main`,
  `planner`, `explorer`, `coder`, `web-fetch` y `unregistered`
  (`examples/claude-code-hook/src/main.rs:46-70`, `189-212` en `dfbe047`).
  Cada autoridad lleva solo las capacidades del perfil (el explorer solo
  `fs:read`). La llave del emisor se descarta tras `init`
  (`main.rs:164-166`): el hook no puede emitir autoridades nuevas.
- El hook elige el perfil por `agent_type` del evento de Claude Code; sin
  `agent_type` es `main`. Un nombre mal formado o sin perfil usa
  `unregistered`, que no tiene capacidades: **deniega** con recibo firmado
  (`main.rs:43-45`, `521-558`).
- El recibo firma `context.agent` (el `agent_type` recibido) y
  `context.profile` (el perfil cuya llave firmó) (`main.rs:571-574`).
- Evidencia committeada (agent id por perfil, leído de los recibos):

  | Set | Perfiles e identidades |
  | --- | --- |
  | 03 (= `bundle/`) | coder `35a39cca…`, explorer `bddf4630…`, main `ddde02df…`, planner `a9009a37…`, web-fetch `3e9ef239…`, unregistered `c6cc3acc…` (lo usa `general-purpose`) |
  | 04 | solo main `beca5532…` (hook previo a `context.profile`) |
  | 05 | coder `bad89773…`, explorer `95dde15e…`, main `b8e04f81…`, planner `a096438a…`, web-fetch `6d0813bc…` |

  En cada set, una identidad por perfil y perfiles distintos con
  identidades distintas. `index.json` "agent" coincide con `context.agent`
  en todos los recibos.
- Lo que **no** había en `dfbe047` (se corrige en §12):
  1. `praetore-claude-hook verify` contaba por el campo **sin firmar**
     `agent` de cada línea de `receipts.jsonl` (`main.rs:672`). Editarlo
     re-atribuía un recibo sin que fallara la verificación.
  2. `export` copiaba ese campo sin firmar a `index.json`
     (`main.rs:716`, `730`) y `verify.sh` resumía `index.json` "solo
     informativo" (`verify.sh:75`). Editar `index.json` re-atribuía un
     recibo con exit 0.
  3. El nombre del perfil solo lo firmaban la llave del propio agente y el
     atestador (en `context`), no el emisor. Un `coder.{json,key}` copiado
     sobre `explorer.{json,key}` hacía que el explorer firmara como el coder
     y recibiera sus capacidades, sin error.
  4. (Revisión independiente, M2; ya pasaba antes de este PR.) Un
     `agent_type` explícito `"main"` daba el perfil `main`, igual que la
     ausencia de `agent_type` (`main.rs:522`). Un subagente definido con
     `name: main` (por ejemplo `.claude/agents/main.md` en un repositorio)
     recibía la llave, las capacidades y las reglas `main_only` de la sesión
     principal, y su recibo no se distinguía del de ella.
- Granularidad real: **perfil**, no instancia. Dos subagentes `coder` en
  paralelo comparten llave. Claude Code documenta un `agent_id` por instancia
  de subagente en los campos comunes de los hooks ("Unique identifier for the
  subagent or in-process teammate the hook fires in",
  <https://code.claude.com/docs/en/hooks>), pero la sección de `PreToolUse`
  no lo lista; está **por confirmar** con un evento real.

### 1.4 Gateway

- El gateway no tiene llaves de agente: recibe un `AuthorizationRequest` ya
  firmado por el cliente (`crates/praetore-gateway/src/http_api.rs:495-520`).
- Las credenciales HTTP son tokens por **tenant** con rol `agent` o
  `approver` (`http_api.rs:43-48`, `80-92`); el tenant del request sale del
  constraint `tenant_id` de su autoridad (`http_api.rs:505-512`). La llave de
  replay es `(agent id, request id)` (`engine.rs:950`), reclamada bajo el
  tenant de la autoridad (`engine.rs:951`).
- Por lo tanto el gateway ya admite muchos agentes por tenant (cada uno con su
  identidad y su autoridad del emisor pineado). Lo que no hace es ligar el
  token a un agente: un token `agent` del tenant A puede enviar requests
  firmados por cualquier agente del tenant A.

## 2. Modelo de amenazas

Actores: el **operador** (instala, corre `init`, controla el disco), los
**agentes** (el principal y sus subagentes; en el hook, procesos de Claude
Code bajo el mismo usuario del sistema), el **verificador** (un tercero con
el bundle: recibos, pin del emisor, llave pública del atestador, policy).

### Qué da una llave por agente

**Atribución verificable por un tercero de qué agente pidió la acción**,
bajo agentes cooperativos:

- cada recibo lleva la identidad que firmó la intención; la autoridad de esa
  identidad, firmada por el emisor, dice qué puede hacer y (con §12) para qué
  perfil se emitió;
- un tercero que solo tiene el pin del emisor y la llave pública del
  atestador puede comprobar que el recibo X lo firmó la identidad emitida
  para `explorer` y no la de `coder`;
- editar el nombre del agente en cualquier copia sin firmar (`index.json`,
  la línea de `receipts.jsonl`, el nombre del archivo) se detecta; editarlo
  en el recibo rompe las firmas;
- agregar al bundle un recibo que nadie verificó tampoco cuenta: `verify.sh`
  y `check-attribution.py` aceptan en `evidence/` solo archivos regulares
  `*.json` no ocultos y fallan ante cualquier otra entrada (archivo oculto,
  directorio, symlink, otro nombre). Antes del arreglo (revisión, M1), un
  `evidence/.X.json` con firmas rotas y su entrada en `index.json` no pasaba
  por `praetore-verify` (el glob de bash no ve ocultos) pero sí entraba en la
  atribución (`os.listdir` los ve), con exit 0;
- cada perfil queda acotado por su autoridad: un explorer con solo `fs:read`
  no escribe aunque la policy lo permitiera para otro perfil.

### Qué NO da

- **No aísla a los agentes entre sí.** Todos corren como el mismo usuario del
  sistema y las llaves están en el mismo disco con permisos `0600` de ese
  usuario. Un subagente que puede ejecutar comandos o leer archivos (o que
  corre en el mismo proceso que el agente principal) puede leer la llave del
  agente principal y firmar como él. Esto es **atribución entre agentes
  cooperativos, no contención**.
- No prueba qué proceso usó la llave. El hook elige el perfil por el
  `agent_type` que Claude Code le pasa; si Claude Code (o algo que se haga
  pasar por él en stdin) dice `coder`, el hook firma como `coder`. Cualquier
  agente con `process:execute` puede correr el binario del hook con un stdin
  inventado (`agent_type: explorer`, un `agent_id` de una instancia que nunca
  existió) y obtener un recibo `explorer` que verifica. `claude.agent_id` y
  `claude.session_id` prueban solo lo que el hook recibió por stdin. El
  constraint de §4.2 impide usar la autoridad de un perfil como otro, no que
  quien llega a los archivos del home firme como cualquier perfil con su
  propio par llave/autoridad.
- No protege contra quien tiene la llave del atestador: puede fabricar
  recibos válidos para cualquier agente cuya llave tenga, y las llaves de
  agente están en el mismo directorio.
- No dice nada sobre las tool calls que no pasan por el hook o por `wrap`.
- Una llave por perfil no distingue dos instancias del mismo perfil.

Para obtener aislamiento real haría falta que cada agente corra bajo otro
usuario del sistema, en otro sandbox, o que la llave viva fuera de su alcance
(un firmante externo que autentique al proceso, §7). Esta propuesta no lo
intenta.

## 3. Granularidad

| Opción | Qué atribuye | Llaves | Viable hoy |
| --- | --- | --- | --- |
| Por instalación (MCP hoy) | "esta máquina/home" | 1 | sí |
| **Por perfil / `agent_type`** (hook hoy) | "un explorer" | una por perfil, en `init` | sí |
| Por cliente MCP | "Claude Desktop" vs "Cursor" | una por cliente | sí, con `install` (§4.2) |
| Por sesión | "esta sesión de Claude Code" | una por `session_id` | requiere emitir autoridad en caliente |
| Por instancia | "este subagente coder" | una por `agent_id` | requiere emitir autoridad en caliente y que `PreToolUse` traiga `agent_id` |

- **PROPUESTA 1:** la unidad de llave y autoridad es el **perfil** (en el
  hook) y el **cliente** o perfil declarado (en MCP). La sesión y la
  instancia se registran como **afirmaciones firmadas** en el `context` del
  recibo (`claude.session_id`, `claude.agent_id`), firmadas con la llave del
  perfil y por el atestador, no como llaves propias.
- Razón: una llave por instancia exige que alguien firme una autoridad nueva
  por instancia, con la llave del emisor disponible en caliente en la misma
  máquina y el mismo usuario. Eso empeora lo que hoy da el hook (la llave del
  emisor se descarta tras `init`) y no añade aislamiento: la llave de la
  instancia estaría en el mismo disco. La afirmación firmada da la misma
  atribución bajo agentes cooperativos.

## 4. Generación de llaves y emisión de autoridad

### 4.1 Cuándo se generan

| Opción | A favor | En contra |
| --- | --- | --- |
| **En `init`** (hook hoy) | el emisor se descarta; el conjunto de agentes queda fijo y auditable | un perfil nuevo exige re-`init` |
| Perezosa, en el primer uso | sin re-`init` | el emisor debe quedar en disco, usable por cualquier agente para emitirse autoridades |
| Derivada por HKDF de una raíz | una sola llave que respaldar | comprometer la raíz compromete todas; la autoridad sigue necesitando al emisor; da reproducibilidad, no aislamiento |

- **PROPUESTA 2:** generar en `init`, una llave aleatoria por perfil
  (`OsRng`), como hace el hook. Sin derivación.
- **PROPUESTA 3:** perfil desconocido ⇒ **denegar** con recibo firmado bajo
  `unregistered` (como hoy), no pedir aprobación. Razón: aprobar exige que un
  humano decida sobre un solicitante al que nadie emitió autoridad; la
  aprobación no le daría capacidad (la autoridad de `unregistered` está
  vacía) y obligaría a que la policy tenga una regla `RequireApproval`
  específica para ese caso. Denegar deja rastro firmado y obliga a declarar
  el perfil (como pasó con `web-fetch`, set 04).
- **PROPUESTA 3b (implementada, revisión M2):** el perfil `main` sale **solo**
  de la ausencia de `agent_type`. Los nombres reservados explícitos `main` y
  `unregistered` se evalúan como `unregistered` (Deny con recibo firmado que
  conserva el `agent_type` pedido). Además, las condiciones de contexto de la
  policy por defecto miran `profile` (el perfil cuya llave firma) y no
  `agent` (el `agent_type` crudo), así que un request `unregistered` que diga
  `agent_type: main` no cumple las reglas `main_only` aunque tuviera
  capacidades.
- **PROPUESTA 3c (implementada, revisión B2):** un `agent_id` o `session_id`
  numérico se guarda como su texto JSON canónico (`123` ⇒ `"123"`), para que
  un cambio de tipo en Claude Code no deniegue todas las llamadas. Uno que no
  es string ni número, o de más de 128 bytes UTF-8, se evalúa como
  `unregistered`: Deny **con recibo firmado** que registra en
  `context["praetore.claim_rejected"]` la clave, el motivo, el tipo JSON o el
  largo en bytes, y **no** el valor (que lo controla quien llama). Un
  `agent_type` de más de 64 bytes sigue denegándose **sin** recibo: el nombre
  es el dato que se rechaza y registrarlo sería guardar en el recibo un
  valor arbitrario del llamador.

### 4.2 Autoridad por agente

- **PROPUESTA 4:** cada autoridad lleva solo las capacidades del perfil (hoy
  en el hook: el explorer y el planner solo `fs:read`; `web-fetch` solo
  `network:invoke`) y un constraint `praetore.agent_profile=<perfil>` firmado
  por el emisor. Como el motor exige los constraints contra los parámetros
  de la acción (§1.1), el hook añade el parámetro `praetore.agent_profile`
  a cada acción; una autoridad emitida para un perfil no sirve en un request
  hecho como otro. **Implementado en el hook** (§12).
- **PROPUESTA 5 (MCP, no implementada):**
  - `init --agents claude-desktop,claude-code,cursor` (o un archivo de
    perfiles) crea `agents/<nombre>.{key,json}` y una autoridad por nombre,
    con el mismo constraint. Sin `--agents`, crea solo `default` desde la
    llave actual (compatibilidad, §9).
  - `wrap --agent <nombre>` elige el perfil; sin `--agent`, `default`.
  - `install --client <c>` escribe `--agent <c>` en la config de ese cliente.
  - El gate añade `praetore.agent_profile` a los parámetros. Ojo: una
    autoridad con el constraint usada por un gate viejo (que no envía el
    parámetro) **deniega** todo. Falla cerrado, pero rompe homes mezclados;
    por eso va detrás de una migración explícita.
  - Límite: el nombre del cliente lo pone la config que el cliente lanza.
    Cualquier proceso que pueda lanzar `praetore-mcp wrap --agent cursor`
    firma como `cursor`. Atribución cooperativa, igual que en el hook.
- **PROPUESTA 6 (gateway):** sin cambios de formato. Opcional: ligar cada
  credencial `agent` a una lista de agent ids (o a una huella de llave) para
  que un token no pueda enviar requests de otro agente del mismo tenant.

## 5. Rotación, revocación y vencimiento

- Hoy no hay revocación de autoridades individuales: la vigencia del pin del
  emisor y la de cada autoridad son las únicas cotas (hook: 90 días por
  defecto; MCP: 364).
- **PROPUESTA 7:** rotar = nuevo `init` en un directorio nuevo (hook) o
  `praetore-mcp init --rotate-agent <nombre>` (MCP, futuro) con un emisor
  nuevo; los bundles viejos se verifican con sus propios pins. No mezclar
  dos generaciones en un bundle (el chequeo de §12 exige una identidad por
  perfil por bundle).
- **PROPUESTA 8:** revocación por agente como lista firmada por el emisor
  (`revoked-authorities.jsonl`, por `authority.id`) que `praetore-verify`
  acepte con `--revocations`. Requiere el emisor en línea o una llave de
  revocación aparte; hoy el hook descarta el emisor. Fuera de este PR.
- **PROPUESTA 9:** los recibos históricos se verifican con la vigencia en el
  instante de la decisión (`decided_at` cuando existe), no en el actual. Ver
  el hallazgo de §1.1 y la pregunta 6.

## 6. Almacenamiento

| Opción | Estado | Qué cambia para la atribución |
| --- | --- | --- |
| Archivos `0600` (hook: `agents/<perfil>.key`; MCP: `keys/*.local-dev.key`) | hoy | cualquier proceso del usuario lee todas las llaves |
| Llavero del sistema (Keychain, Secret Service) | no implementado | puede pedir confirmación por app; en macOS los procesos firmados de la misma app comparten acceso |
| `Signer` de SAF-11 con PKCS#11/KMS (#73, abierto) | pendiente | la llave no sale del token, pero quien tiene el PIN o la sesión firma; el token no sabe qué agente lo llama |

- **PROPUESTA 10:** SAF-14 no cambia el almacenamiento. Cuando #73 se
  integre, cada perfil es un `Signer` distinto (un slot o key id por perfil).
  Ninguna de las tres opciones aísla agentes del mismo usuario por sí sola;
  solo cambia quién puede **copiar** la llave, no quién puede **usarla**.

## 7. Archivos de confianza para terceros

- Hoy: un pin de emisor por bundle (`issuer-pins.jsonl`) y la llave pública
  del atestador. Con eso un tercero verifica que cada identidad tiene una
  autoridad emitida, pero (antes de §12) no **para qué perfil**.
- **PROPUESTA 11:** seguir con **pins de emisor**, y que el perfil viaje en
  la autoridad firmada (constraint `praetore.agent_profile`). Un tercero no
  necesita una lista de agentes para atribuir.
- **PROPUESTA 12 (opcional, no implementada):** `export` escribe
  `agent-pins.jsonl` (perfil, agent id, huella de llave, authority id) para
  quien quiera **restringir** la verificación a agentes conocidos, y
  `praetore-verify evidence --expect-agent-id <uuid>` (o
  `--agent-pins <jsonl>`) que falle si el recibo es de otro agente. Hoy
  `praetore-verify` no informa el agent id (§1.1).

## 8. Impacto en recibos, verificador, journal y sets

- **Formato del recibo: sin cambios.** Verificado: el recibo ya lleva
  `agent` (id y llave), `authority.subject`, `authority.subject_key_hash`,
  `authority.constraints` (firmado por el emisor), `action.parameters` y
  `context` (firmados por el agente y el atestador). §12 solo pone valores
  nuevos en campos existentes:
  - `authority.constraints`: `[{"key":"praetore.agent_profile","value":"<perfil>"}]`;
  - `action.parameters["praetore.agent_profile"]`: el perfil (la policy lo
    ve; ninguna regla actual lo usa);
  - `context["claude.agent_id"]`, `context["claude.session_id"]`: solo si
    Claude Code los envía (string o número, ≤128 bytes; si no ⇒ Deny bajo
    `unregistered` con `context["praetore.claim_rejected"]`).
- `index.json` (sin firmar, no es parte del recibo): nuevo campo
  `agent_id`; `agent` y `profile` salen ahora de lo firmado.
- `praetore-verify`: sin cambios en este PR (PROPUESTA 12 para el futuro).
- Journal encadenado (`journal-chain.jsonl`, #69): encadena los bytes de los
  recibos; no cambia. Los heads de 03/04/05 en `assurance.yml` siguen
  valiendo porque esos sets no se tocan.
- Sets 03, 04, 05 y `bundle/`: sin cambios; verifican con el `verify.sh`
  nuevo (sus recibos no tienen el constraint y se marcan "nombre del perfil
  firmado por: agente y atestador").

## 9. Migración y compatibilidad

- Hook, estado existente (sin constraint): **falla cerrado** (revisión B1).
  `authorize` rechaza una autoridad sin `praetore.agent_profile` con un
  mensaje que pide correr `praetore-claude-hook init` en un directorio nuevo;
  Claude Code recibe `deny` con ese motivo en cada llamada hasta migrar. Así
  un home viejo, donde un archivo de perfil copiado sobre otro no se puede
  detectar, no sigue evaluando en silencio. `verify` y `export` siguen
  aceptando los recibos ya escritos sin el constraint.
- Hook, `verify` local: compara la identidad que firmó cada recibo con el
  `agents/<perfil>.json` **actual**. Reemplazar o re-emitir ese archivo hace
  fallar los recibos anteriores en `verify` (el mensaje lo dice). Los
  terceros verifican contra los pins del bundle exportado, no contra ese
  archivo.
- Hook, bundles existentes: verifican igual (ver §13). El chequeo nuevo de
  `verify.sh` exige que `index.json` coincida con lo firmado; los bundles
  exportados por el hook siempre lo cumplieron (el campo venía del mismo
  dato), salvo que alguien lo haya editado.
- Bundles armados a mano: `verify.sh` ahora exige que `index.json` tenga una
  entrada por recibo. `test-verify.sh` arma su `index.json` así.
- MCP (cuando se implemente PROPUESTA 5): un home existente se lee como el
  agente `default` desde `keys/agent.local-dev.key` y `agent.json`, sin
  constraint; `wrap` sin `--agent` usa `default`; los recibos viejos
  verifican con los mismos pins. Agregar agentes requiere el emisor, que en
  MCP sí queda en disco (`keys/issuer.local-dev.key`).

## 10. Alternativas descartadas

- Cambiar el formato del recibo para añadir un campo `agent_profile` de
  primer nivel: innecesario, el constraint de la autoridad ya lo firma el
  emisor.
- Usar `AgentId` derivado de la llave (hash de la pública) para que el id
  "sea" la llave: cambia la semántica de `AgentId` en core; la autoridad ya
  liga id y huella (`subject_key_hash`).
- Una llave por instancia (§3).

## 11. Plan de aceptación

1. Tests unitarios del hook (en `src/attribution_tests.rs` y `src/main.rs`):
   - dos perfiles firman con identidades y llaves distintas, y cada autoridad
     trae el constraint de su perfil;
   - editar el `agent`/`profile` sin firmar de `receipts.jsonl` hace fallar
     `verify` y `export`;
   - editar `context.agent` rompe las firmas;
   - un `coder.{json,key}` copiado sobre `explorer.*` falla cerrado;
   - `index.json` lleva el `agent_id` del recibo;
   - `claude.agent_id` y `claude.session_id` quedan firmados; uno de 129
     bytes deniega;
   - recibos committeados de 03, 04 y 05 se leen con su atribución;
   - (revisión) `agent_type: "main"` y `"unregistered"` explícitos dan Deny
     bajo `unregistered` con recibo, y la ausencia de `agent_type` sigue
     siendo `main` (M2); un home sin el constraint falla cerrado pidiendo
     `init` (B1); `agent_id` numérico se acepta, uno objeto o de 129 bytes
     deniega con recibo firmado que no guarda el valor (B2); los resúmenes
     escapan los `agent_type` no registrados (I1).
2. `test-attribution.sh` (e2e, en CI): regenera un bundle con `demo.sh`,
   verifica con `verify.sh`, muestra dos agent ids distintos (coder y
   explorer) con autoridades emitidas para su perfil, y rechaza tres
   re-atribuciones (en `index.json`, en `context`, cambiando identidad y
   autoridad) y tres entradas de `evidence/` sin verificar: el recibo oculto
   de la revisión (`.0099-coder-Bash-Allow.json`, firmas rotas), un symlink
   y un directorio, cada uno con su entrada en `index.json` (M1).
3. Los tests nuevos fallan contra `dfbe047` (salida real en el PR).
4. `verify.sh` pasa sobre `bundle/`, 03, 04 y 05; `test-verify.sh` pasa.
5. MCP (cuando se implemente): un e2e con dos clientes instalados
   (`--client claude-desktop`, `--client cursor`) que muestre dos agent ids
   en los recibos y que `praetore-mcp verify` y `praetore-verify` fallen al
   editar el agente.

## 12. Lo implementado en este PR (solo `examples/claude-code-hook`)

- `init`: cada autoridad lleva `praetore.agent_profile=<perfil>`.
- `authorize`: añade `praetore.agent_profile` a los parámetros de la acción
  (el motor exige el constraint); falla cerrado si el archivo de perfil trae
  una autoridad emitida para otro perfil o ninguna (home anterior a SAF-14);
  registra `claude.agent_id` y `claude.session_id` en el contexto firmado si
  llegan (PROPUESTA 3c); trata `main`/`unregistered` explícitos como
  `unregistered` (PROPUESTA 3b).
- Policy por defecto: las condiciones de contexto miran `profile`, no `agent`.
- `verify`: cuenta por los nombres firmados; falla si el `agent`/`profile`
  sin firmar de la línea no coincide, si el perfil firmado no coincide con el
  constraint, o si la identidad que firmó no es la de `agents/<perfil>.json`;
  imprime el agent id de cada perfil. Los `agent_type` no registrados se
  muestran como `unregistered(agent_type="…")` escapados a ASCII, para que
  `"coder "` o una `о` cirílica no se lean como el perfil `coder`.
- `export`: `index.json` toma `agent` y `profile` de lo firmado, añade
  `agent_id`, y se niega a exportar una línea cuyo campo sin firmar difiere.
- `verify.sh`: el paso 3 falla ante cualquier entrada de `evidence/` que no
  sea un archivo regular `*.json` no oculto, y `check-attribution.py` aplica
  la misma regla, así que los dos leen el mismo conjunto (M1). Los pasos 5 y
  6 exigen que `index.json` diga lo mismo que los recibos firmados (agente,
  perfil, agent id), una identidad por perfil, y rechazan una copia
  re-atribuida.
- No cambia: el formato del recibo, `praetore-core`, `praetore-verify`,
  `praetore-mcp`, el gateway, la evidencia committeada.

## 13. Preguntas abiertas para el fundador

1. ¿La unidad es el perfil (con instancia y sesión como afirmaciones
   firmadas) o quiere llaves por instancia aun sabiendo que no añaden
   aislamiento y obligan a tener el emisor en caliente?
2. Perfil desconocido: ¿denegar (hoy y PROPUESTA 3) o pedir aprobación?
3. MCP: ¿el agente es el **cliente** (Claude Desktop, Cursor…) o un perfil
   que declare el usuario? ¿Se implementa PROPUESTA 5 antes o después de
   ADOPT-01 (#43)?
4. ¿Quiere `agent-pins.jsonl` y `--expect-agent-id` en `praetore-verify`
   (PROPUESTA 12), o basta con el pin del emisor y el constraint?
5. Gateway: ¿ligar cada token `agent` a uno o más agent ids (PROPUESTA 6)?
6. Vigencia: `praetore-verify` comprueba la autoridad a la hora actual, y
   los sets 04 y 05 dejarán de verificar en CI el `2027-01-29`. ¿Se cambia a
   la hora de la decisión (PROPUESTA 9), se re-exportan los sets, o se
   acepta que la evidencia histórica caduque?
7. ¿Se regenera `bundle/` con el hook nuevo para que el bundle de ejemplo ya
   muestre el constraint? (Cambia su contenido, no los sets 03-05.)
8. Confirmar con un evento real de Claude Code si `PreToolUse` dentro de un
   subagente trae `agent_id` (la doc lo lista en campos comunes, no en
   `PreToolUse`).
