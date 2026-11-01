# Ejemplo: PRÆTORE autoriza las tool calls de agentes de Claude Code

Un hook `PreToolUse` de Claude Code que pasa por PRÆTORE **las acciones de
herramientas que pasan por el hook**: lecturas, escrituras, comandos, red y
delegación, tanto de la sesión principal como de los subagentes. Lo que un
agente haga por otro camino queda fuera (ver Límites).

> Ejemplo independiente: no es miembro del workspace del repositorio y no
> forma parte del producto. Tiene su propio `Cargo.toml` y `Cargo.lock`.

## Qué hace

- `init` crea una clave Ed25519 por perfil de agente y una autoridad firmada
  por un emisor local que da solo las capacidades de ese perfil y nombra el
  perfil (constraint `praetore.agent_profile`, SAF-14). La clave del
  emisor se descarta después de firmar; queda solo su pin público. También
  crea una clave de atestador para firmar los recibos.
- Por cada tool call, el hook arma un `AuthorizationRequest` firmado con la
  clave del perfil (con `praetore.agent_profile` en los parámetros, que el
  motor exige contra la autoridad, y `agent_id`/`session_id` de Claude Code
  en el contexto firmado si llegan), lo evalúa con un motor
  **HighAssurance** (`AuthorizationEngine::production`) contra una policy v2
  que por defecto niega; el motor firma la evidencia con el atestador y el
  hook la agrega a `receipts.jsonl`.
- **Recibos HighAssurance.** Cada recibo registra su hora de decisión
  firmada (`decided_at`): `praetore-verify evidence --issuer-pins` verifica
  la autoridad y el pin del emisor a esa hora, y con
  `--require-decision-time` rechaza los recibos que no la tienen. La
  intención va firmada (v2) para la audiencia `praetore-claude-hook`, bajo el
  digest de la policy cargada, y vale 60 s. Freshness es local: no hay fuente
  de revocación (la clave del emisor se descarta en `init`), así que da una
  lease de 60 s y no detecta revocaciones; para reemplazar las autoridades
  hay que hacer otro `init`.
- **Guard de replay durable.** `init` crea `<estado>/replay/`. Cada request
  firmado que el motor evalúa reclama un archivo
  `replay/<tenant>/<agent id>/<request id>` creado con `create_new`
  (`O_CREAT|O_EXCL`): de varios procesos que crean el mismo nombre, el kernel
  deja ganar a uno solo. Lo que garantiza hoy: el claim de un request firmado
  queda registrado una sola vez, y ese request no se evalúa de nuevo. **No
  deduplica tool calls:** cada invocación del hook arma un request nuevo (con
  su propio `request_id`), así que la misma tool call entregada dos veces da
  dos recibos, cada uno una decisión real del motor. Si un tool call
  re-entregado debe caer en replay (por ejemplo, derivando `request_id` de
  `tool_use_id`) está pendiente de decisión (M1 de la revisión de #88).
  El archivo y sus directorios se sincronizan a disco (`fsync`) antes de dar
  el claim por hecho, y nunca se borran. En cada claim el hook exige que
  `replay/` sea un directorio real del usuario actual, sin ningún bit de
  grupo u otros y, en macOS, sin entradas de ACL extendida; y que el
  directorio de estado sea del usuario actual y no tenga escritura para grupo
  u otros. Cualquier error (directorio ausente o reemplazado, symlink, dueño
  o permisos incorrectos, ACL, disco lleno, fallo de `fsync`) niega la tool
  call sin recibo. El estado debe estar en un sistema de archivos local con
  create exclusivo atómico: no en NFS ni en una carpeta sincronizada (por
  ejemplo, Escritorio y Documentos en iCloud).
- **El recibo se sincroniza a disco** (`fsync` de `receipts.jsonl` en cada
  append, y de su directorio al crearlo) antes de que el hook responda. Si
  escribirlo falla, el hook niega la tool call; el claim de replay ya hecho
  queda sin recibo. `replay/` no es un registro de decisiones: puede tener
  claims huérfanos, que no bloquean nada porque su `request_id` no se
  reutiliza.
- **Un estado anterior a los recibos HighAssurance falla cerrado.** Si
  `<estado>/replay/` no existe, el hook niega cada tool call gobernada con un
  mensaje que pide correr `praetore-claude-hook init` en un directorio nuevo
  (mismo patrón que el chequeo de SAF-14). Las tools `Safety` declaradas
  siguen sin recibir decisión. Los recibos ya escritos siguen verificando con
  `verify`.
- `Deny` → la tool call se bloquea. `RequireApproval` → Claude Code le
  pregunta al usuario. `Allow` → el hook no decide y siguen aplicando los
  permisos propios de Claude Code.
- G7: antes de leer claves o perfiles, firmar o evaluar, el hook clasifica
  la tool call con `action_classes` de la policy (formato 2). Una tool cuyo
  nombre empieza con `safety:` y que la policy declara `Safety` no recibe
  decisión de PRÆTORE (siguen aplicando los permisos propios de Claude Code),
  no se firma nada y no se agrega nada a `receipts.jsonl`; el hook escribe
  `SAFETY_ACTION_NOT_GOVERNED` en stderr. Así, un fallo de PRÆTORE después de
  cargar la policy (por ejemplo, `receipts.jsonl` sin escritura) no la
  retiene. Una tool `safety:*` no declarada se niega con un DENY firmado
  (motivo `unclassified`, guard `unclassified_action`) que se agrega a
  `receipts.jsonl`; el motor verifica la solicitud igual que una de misión y
  no evalúa reglas. Todo DENY con recibo se muestra con el mismo texto,
  `PRÆTORE denied this tool call (evidence ...)`; la regla y el motivo van a
  stderr y al recibo firmado. La policy por defecto declara `Mission`
  los tipos `claude:*` y ninguna acción `Safety`.
- **Migrar la policy antes de actualizar el binario.** Un estado creado
  antes de G7 tiene una policy de formato 1; con el binario nuevo esa policy
  no carga y el hook niega todas las tool calls, incluidas las `safety:*`,
  hasta migrarla (`praetore policy classify --policy <estado>/policy.json`
  propone la tabla) o hacer un `init` nuevo. El mensaje de error del hook
  indica ese paso.
- Declarar una tool `Safety` la saca por completo del gobierno de PRÆTORE;
  esa confianza recae en quien escribe la policy.
- Los recibos ya escritos con una policy de formato 1 (estado creado antes
  de G7) siguen verificando contra esa policy: `verify` y `praetore-verify
  --policy` la leen como `RecordedPolicy`, que solo calcula el digest. Para
  evaluar hace falta un `init` nuevo (policy de formato 2).

| Perfil | Capacidades |
| --- | --- |
| `main` (sesión principal, sin `agent_type`) | `fs:read`, `fs:write`, `process:execute`, `network:invoke`, `agent:delegate`, `tool:invoke` |
| `planner`, `explorer` | `fs:read` |
| `coder` | `fs:read`, `fs:write`, `process:execute` |
| `web-fetch` (lector web incorporado de Claude Code) | `network:invoke` |
| `unregistered` | ninguna |

Cualquier otro `agent_type`, incluidos agentes incorporados como
`general-purpose` y los nombres reservados `main` y `unregistered` cuando
llegan explícitos (solo la ausencia de `agent_type` es la sesión principal),
se evalúa con el perfil `unregistered`. También un `agent_id` o `session_id`
que no es string ni número, o de más de 128 bytes UTF-8 (el recibo registra
el motivo, no el valor). Ese perfil no
tiene capacidades, así que toda solicitud se niega, pero con un recibo
firmado que conserva el `agent_type` pedido. Así ninguna negación queda sin
registrar.

Darle red a `web-fetch` es una decisión de policy: en algunas instalaciones
de Claude Code es la única vía para leer páginas web. Sácalo de `PROFILES`
si no la quieres.

Reglas de la policy por defecto:

- Los subagentes no escriben en `<raíz>/.claude`. La sesión principal sí,
  pero con aprobación.
- Nadie escribe en `<raíz>/.git`.
- `git push` requiere aprobación (ver abajo cómo se detecta).
- Un comando que no se puede analizar requiere aprobación.
- Los subagentes leen y escriben solo dentro de la raíz del proyecto, con la
  ruta ya resuelta (un symlink que sale de la raíz no cuenta como dentro). La
  sesión principal además lee en cualquier lugar y escribe en
  `~/.claude/projects` y `/private/tmp`.

### Resolución de rutas

Como en [#59](https://github.com/Mavericksantander/praetore/pull/59),
`PathPrefix` en core sigue siendo léxico y la resolución ocurre en el hook,
antes de evaluar. Cada ruta (`file_path`, `notebook_path`, `path` de
Grep/Glob, o `cwd`) se resuelve con `fs::canonicalize`. Para un archivo que
todavía no existe, se resuelve el ancestro existente más profundo y se le
agregan los nombres que faltan. Esos nombres no pueden ser symlinks porque
todavía no existen.

Si la ruta no se resuelve a sí misma (`differs`: un symlink en cualquier
parte, `.` o `..`) o no se puede resolver (`unresolved`: un symlink colgante,
una ruta bajo un archivo, `..` bajo un directorio inexistente), el motor no
recibe la ruta sino `praetore-claude-hook:path-check-failed`. Como ese valor
no es absoluto, core lo trata como inseguro: coincide con toda regla
restrictiva de `PathPrefix` y con ninguna de permiso. El recibo guarda
`context["praetore.path_check"] = {"lexical", "resolved", "status"}`, dentro
del contenido firmado.

Diferencia con #59: allí un archivo nuevo en un directorio que no existe se
niega, porque solo se resuelve el padre. Aquí se resuelve el ancestro
existente, para que `coder` pueda crear directorios nuevos.

### Detección de `git push`

[`src/shell.rs`](src/shell.rs) separa el comando en comandos simples
(`;`, `&&`, `||`, `|`, `&`, saltos de línea, paréntesis y redirecciones),
quita comillas y escapes, y busca una palabra `git` cuyo subcomando sea
`push`, saltando las opciones globales (`-C`, `-c`, `--git-dir`, ...).
Detecta `cd x && git push`, `sudo git push`, `/usr/bin/git push` y
`git -C ../repo push`. Nunca ejecuta ni expande nada.

Si el comando contiene algo que no puede analizar léxicamente, lo marca como
no analizable y la policy pide aprobación: sustitución de comandos (`$(...)`,
backticks), sustitución de procesos, heredocs, `eval`, `sh -c` / `bash -c`,
una variable en posición de comando o junto a `push`, o un alias inline
(`git -c alias.x=push x`). Acepta falsos positivos como `echo git push`.

## Probarlo

Desde la raíz de un clon:

```sh
./examples/claude-code-hook/demo.sh /tmp/bundle-ha   # 22 tool calls fijas, recibos HighAssurance
./examples/claude-code-hook/verify.sh /tmp/bundle-ha --require-decision-time
./examples/claude-code-hook/verify.sh   # verifica bundle/ solo con praetore-verify
```

`demo.sh` sin argumento reemplaza `bundle/`. El `bundle/` del repositorio se
generó antes de los recibos HighAssurance: no tiene `decided_at` y con
`--require-decision-time` falla (`DECISION_TIME_MISSING`), lo esperado. Sin
la opción sigue verificando como antes.

`verify.sh` hace lo siguiente, sobre una copia del bundle que toma al
empezar (verifica y atribuye los mismos bytes, aunque el original cambie
mientras corre):

1. Compila `praetore-verify` con `--locked`.
2. Verifica cada recibo con
   `praetore-verify evidence --attester-pin ... --issuer-pins ... --require-intent --policy policy.json`.
   Con `--policy`, praetore-verify exige además que el `policy_digest` de cada
   recibo sea el de la `policy.json` publicada.
3. Altera un byte de una copia y comprueba que la verificación falla.
4. Con `check-attribution.py`, exige que `index.json` (sin firmar) nombre el
   mismo agente, perfil y agent id que cada recibo firmado, que cada recibo
   tenga una entrada, que ningún recibo esté repetido (mismo `evidence_id`, o
   mismo agent id y `request_id`) y que haya una identidad por perfil.
   Imprime el agent id de cada perfil.
5. Re-atribuye un recibo en una copia de `index.json` y comprueba que el
   paso 4 la rechaza.

Sale con 0 solo si praetore-verify acepta todos los recibos y rechaza la copia
alterada, e `index.json` coincide con lo firmado; con 1 en cualquier otro
caso. `test-verify.sh` lo comprueba con 1000 recibos distintos que firma el
hook en un estado temporal, y con uno de ellos alterado. `test-attribution.sh` regenera un bundle y
comprueba que coder y explorer firman con identidades distintas y que tres
re-atribuciones (en `index.json`, en el contexto firmado y cambiando
identidad y autoridad) se rechazan.

No usa el binario del hook ni ninguna clave privada. Las claves privadas del
demo existen solo mientras corre `demo.sh` y se borran al terminar. Las
autoridades del bundle valen 10 años para que el bundle siga verificando.

## Usarlo en un proyecto

```sh
cargo build --release --locked --manifest-path examples/claude-code-hook/Cargo.toml
mkdir -p <proyecto>/.claude/bin <proyecto>/.claude/hooks
cp examples/claude-code-hook/target/release/praetore-claude-hook <proyecto>/.claude/bin/
cp examples/claude-code-hook/hook/praetore-hook.sh <proyecto>/.claude/hooks/
cp examples/claude-code-hook/agents/*.md <proyecto>/.claude/agents/   # opcional
<proyecto>/.claude/bin/praetore-claude-hook init <proyecto>/.claude/praetore --root <proyecto>
```

Después, registrar el hook en `<proyecto>/.claude/settings.local.json`:

```json
{ "hooks": { "PreToolUse": [ { "matcher": "*", "hooks": [
  { "type": "command", "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/praetore-hook.sh" }
] } ] } }
```

Luego reiniciar Claude Code. El wrapper niega todo si falta el binario o el
estado. Para exportar los recibos de una sesión real y verificarlos:

```sh
<proyecto>/.claude/bin/praetore-claude-hook export <proyecto>/.claude/praetore <bundle>
./examples/claude-code-hook/verify.sh <bundle> --require-decision-time
```

Un estado creado con un binario anterior no tiene `replay/` y el hook nuevo
lo rechaza: hay que hacer `init` en un directorio nuevo. Cómo grabar los sets
de evidencia 04 y 05 con el hook HighAssurance:
[evidence/VERIFY.md](evidence/VERIFY.md#7-recording-new-sets-04-and-05-highassurance).

Los subagentes de ejemplo (`agents/`) son `planner` (opus, solo lectura),
`coder` (sonnet) y `explorer` (haiku, solo lectura).

## Qué prueba un recibo y qué no

- **Prueba** que la evidencia no cambió desde que la firmó el atestador, que
  la intención la firmó la clave de ese **perfil de agente**, que la
  autoridad la emitió el emisor pineado para esa clave, y bajo qué policy se
  decidió.
- **Un home anterior a SAF-14 falla cerrado.** Si las autoridades no traen
  `praetore.agent_profile`, el hook deniega cada llamada con un mensaje que
  pide correr `init` en un directorio nuevo. Los recibos ya escritos siguen
  verificando. `verify` compara cada recibo con el `agents/<perfil>.json`
  actual: reemplazar o re-emitir ese archivo hace fallar los recibos
  anteriores (los terceros verifican con los pins del bundle).
- **Atribuye al perfil, no aísla.** La firma dice qué perfil (`agent_type`)
  pidió la acción, y con SAF-14 el emisor firma para qué perfil emitió cada
  identidad. Pero las claves de todos los perfiles y la del atestador viven
  en la misma cuenta de usuario que los agentes: un agente que lee archivos
  puede firmar como otro. Es atribución entre agentes cooperativos, no
  contención. Dos instancias del mismo perfil comparten clave; el
  `agent_id` de Claude Code, si llega, queda como dato firmado, no como
  clave propia. Ver
  [SAF-14](../../docs/proposals/SAF-14-identidad-por-agente.md).
- **No prueba que la acción se ejecutó**, ni que no hubo acciones fuera del
  hook.

## Límites

- **Cooperativo.** Solo cubre las tool calls que pasan por el hook, y solo
  mientras el hook esté configurado. Por eso los subagentes no pueden
  escribir en `.claude/`, y la sesión principal necesita aprobación.
- **Lo que corre dentro de un comando permitido no se ve.** Un script
  (`./deploy.sh`), un `Makefile` o un alias de git definido en la
  configuración pueden hacer push sin que el comando lo diga.
- **Ventana entre el chequeo y la escritura (límite conocido, igual que en
  #59).** La ruta se resuelve cuando el hook evalúa, y la herramienta de
  Claude Code la abre después. Si alguien crea un symlink justo en ese
  intervalo, por ejemplo en el nombre todavía inexistente de un archivo
  nuevo o en lugar de un directorio, la escritura pasa por él. Se cierra
  abriendo la ruta por descriptor con
  `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`, como propone T-013 B
  ([#61](https://github.com/Mavericksantander/praetore/pull/61)). Aquí quien
  abre el archivo es la herramienta de Claude Code y no PRÆTORE, así que el
  hook por sí solo no puede cerrarla: hace falta que un ejecutor confinado
  como el de T-013 B sea el que abra el archivo.
- **macOS:** `/tmp` y `/var` son symlinks a `/private/...`. Una ruta como
  `/tmp/x` no se resuelve a sí misma, así que se niega bajo cualquier regla de
  ruta. Hay que usar rutas resueltas.
- **Raíz fija.** La raíz de la policy es la ruta absoluta dada en `init`.
  Mover el proyecto exige otro `init`.
- **El estado del hook y los procesos del mismo usuario.** Las operaciones
  sobre el estado van por ruta, no relativas a un descriptor de directorio:
  los chequeos de symlink, dueño, permisos y ACL valen en el momento en que
  corren. Un proceso del mismo usuario está dentro del perímetro de
  confianza: ya puede leer las claves de los agentes y del atestador en el
  estado. Lo que puede hacer con `replay/` (borrarlo, reemplazarlo, llenar el
  disco) hace que el hook niegue, no que permita: esos errores fallan
  cerrado. Tampoco hay que fiarse de `decided_at` más que de la clave del
  atestador: quien la tenga puede firmar cualquier `decided_at`.
