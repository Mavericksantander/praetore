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
  en el contexto firmado si llegan), lo evalúa con un motor `strict` contra
  una policy v2 que
  por defecto niega, firma la evidencia con el atestador y la agrega a
  `receipts.jsonl`.
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
  hasta hacer un `init` nuevo (recomendado) o migrarla (`praetore policy
  classify --policy <estado>/policy.json` propone la tabla). Migrar conserva
  las autoridades emitidas antes, incluido `process:execute` para `coder`, y
  la policy sigue sin las reglas nuevas (ver
  [`Bash` y `process:execute`](#bash-y-processexecute)). El mensaje de error
  del hook lo indica.
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
| `coder` | `fs:read`, `fs:write` |
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

Ningún subagente recibe `process:execute` (ver
[`Bash` y `process:execute`](#bash-y-processexecute)). Solo la sesión
principal, que es la del usuario, puede ejecutar comandos.

Darle red a `web-fetch` es una decisión de policy: en algunas instalaciones
de Claude Code es la única vía para leer páginas web. Sácalo de `PROFILES`
si no la quieres.

Reglas de la policy por defecto:

- Los subagentes no escriben en `<raíz>/.claude`. La sesión principal sí,
  pero con aprobación.
- Nadie escribe en `<raíz>/.git`.
- Configuración que el cliente, git, un shell o un IDE ejecutan
  (`.mcp.json`, `.vscode/`, `.cargo/`, `.husky/`, `.envrc`, `.gitmodules`,
  archivos de inicio del shell y el resto de la lista de abajo): ningún
  perfil salvo `main` la escribe con Write, Edit, MultiEdit o NotebookEdit
  (`deny-subagent-client-config-writes`), y `main` necesita aprobación
  (`approval-main-client-config-writes`).
- `git push` requiere aprobación (ver abajo cómo se detecta).
- Un comando que no se puede analizar requiere aprobación.
- Un comando analizable requiere aprobación si alguna de sus palabras nombra
  `<raíz>/.claude`, `<raíz>/.git` u otra ruta de la lista de configuración
  (`approval-command-touches-protected-path`),
  una ruta fuera de la raíz (`approval-command-leaves-root`) o una
  herramienta de red común (`approval-command-uses-network`). Es defensa en
  profundidad, no un límite (ver abajo).
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

### `Bash` y `process:execute`

**Conceder `Bash` (`process:execute`) equivale a conceder todas las demás
capacidades.** El hook ve el texto del comando, no lo que el comando hace al
correr: un comando permitido puede escribir en cualquier archivo que el
usuario pueda escribir (incluidos `.claude/` y `.git/`), leer fuera de la
raíz del proyecto y usar la red sin `network:invoke`. Las reglas de rutas y
de red de este README se aplican a las herramientas que nombran una ruta o
una URL (Read, Write, Edit, Grep, Glob, NotebookEdit, WebFetch, WebSearch),
no a lo que hace un comando.

Por eso (GHSA-wg33-3h8v-xvqw) ningún perfil de subagente recibe
`process:execute` por defecto: `coder` edita archivos y la sesión principal
corre los comandos. La definición de ejemplo
[`agents/coder.md`](agents/coder.md) ya no incluye `Bash` en `tools:`.

**Configuración que se ejecuta.** Escribir un archivo puede bastar para
ejecutar: Claude Code lanza los servidores MCP de `.mcp.json` fuera del hook
y fuera del sandbox, y git, el shell, el IDE o el gestor de paquetes corren
lo que nombran sus archivos de configuración. Por eso (también
GHSA-wg33-3h8v-xvqw) el hook trata como protegidas las rutas que Claude Code
protege en sus modos de permiso
([lista](https://code.claude.com/docs/en/permission-modes#protected-paths)),
comparando componentes completos de la ruta, sin distinguir mayúsculas, en
cualquier lugar bajo la raíz:

- directorios: `.git`, `.config/git`, `.vscode`, `.idea`, `.husky`,
  `.cargo`, `.devcontainer`, `.yarn`, `.mvn`, `.claude`;
- archivos: `.gitconfig`, `.gitmodules`; `.bashrc`, `.bash_profile`,
  `.bash_login`, `.bash_aliases`, `.bash_logout`, `.zshrc`, `.zprofile`,
  `.zshenv`, `.zlogin`, `.zlogout`, `.profile`, `.envrc`; `.npmrc`,
  `.yarnrc`, `.yarnrc.yml`, `.pnp.cjs`, `.pnp.loader.mjs`, `.pnpmfile.cjs`,
  `bunfig.toml`, `.bunfig.toml`; `.bazelrc`, `.bazelversion`, `.bazeliskrc`;
  `.pre-commit-config.yaml`, `lefthook.yml`, `lefthook.yaml`,
  `.lefthook.yml`, `.lefthook.yaml`; `gradle-wrapper.properties`,
  `maven-wrapper.properties`; `.devcontainer.json`; `.ripgreprc`,
  `pyrightconfig.json`; `.mcp.json`, `.claude.json`.

Los archivos de esa página que no viven en el proyecto (los que se pasan con
`--settings`, `--mcp-config` o `--agents`, el destino de un settings que es
symlink, `~/.claude/dev-mods/`) quedan fuera, igual que los archivos que
convierten el directorio en un repositorio git bare (`HEAD`, `objects`,
`refs`, `config`), que el sandbox protege pero que aquí darían falsos
positivos con directorios comunes como `config/`.

**Ejecución indirecta.** Lo que escribe un subagente lo puede ejecutar
después la sesión principal: `build.rs`, un test, un script de
`package.json`, un `Makefile`. `CLAUDE.md` le da instrucciones a la sesión
principal. El hook no cierra ese camino: cuando `main` corre `cargo test`,
corre el código que escribió `coder`, con los permisos de `main`. Una lista
de archivos no lo cerraría (cualquier archivo de código puede ejecutarse) y
pediría aprobaciones en ediciones normales, así que no se agregó una regla
para `build.rs` y similares; los que la página de Claude Code lista
(`.cargo/`, `.envrc`, `.husky/`, `.vscode/`) ya están en la lista de arriba.
La mitigación real es ejecutar el `Bash` de `main` en el sandbox (abajo) y
revisar los cambios de un subagente antes de correr tests o builds.

**Estados existentes.** Un estado creado antes de este cambio conserva lo
que `init` emitió: `coder` sigue teniendo `process:execute`, y la policy no
trae las reglas `approval-command-*` ni las de configuración. Dos defensas
cubren ese caso sin re-emitir:

- el hook niega todo comando (`claude:exec`) a un perfil distinto de `main`,
  aunque su autoridad otorgue `process:execute`: lo evalúa como
  `unregistered`, con recibo firmado;
- en cada ejecución escribe una advertencia en stderr si el estado no tiene
  `project-root` o si un perfil distinto de `main` tiene `process:execute`.

Sin `project-root` no hay raíz contra la cual comparar: todo comando
analizable cuenta como fuera de la raíz y toda escritura como configuración.
Un `project-root` vacío, `/`, relativo, no canónico o que no es un
directorio existente hace fallar cerrado al hook. Para quitar
`process:execute` y tener las reglas nuevas, emitir un estado nuevo y dejar
el anterior para verificar sus recibos:

```sh
mv <proyecto>/.claude/praetore <proyecto>/.claude/praetore.anterior
<proyecto>/.claude/bin/praetore-claude-hook init <proyecto>/.claude/praetore --root <proyecto>
<proyecto>/.claude/bin/praetore-claude-hook verify <proyecto>/.claude/praetore.anterior
```

**Defensa en profundidad en el escáner, no un límite.** Para un comando
analizable, [`src/shell.rs`](src/shell.rs) toma cada palabra (argumentos,
valores de opciones tras `=`, destinos de redirecciones) como posible ruta y
el hook la resuelve contra la raíz dada en `init` (archivo `project-root` del
estado): de forma léxica (quitando `.` y `..`) y siguiendo symlinks. Marca
`protected_path` si alguna cae en una ruta de la lista de configuración
(incluidos `.claude` y `.git`), `leaves_root` si alguna cae fuera
de la raíz (o es `~...` o `$VAR`, cuyo valor no conoce; `/dev/null` y
similares no cuentan, ni el programa nombrado por ruta, como
`/usr/bin/git`), y `network` si alguna palabra es `curl`, `wget`, `nc`,
`ssh`, `scp`, `rsync`, `ftp`, `telnet` o `socat`. La policy pide aprobación
en cada caso con su propia regla. `Monitor` corre un comando de shell y
recibe el mismo escaneo. `PowerShell` no es shell POSIX y el escáner no lo
entiende, así que para `main` siempre pide aprobación
(`approval-unanalyzable-command`); los subagentes no tienen
`process:execute` y se les niegan los dos.

Se eligió `RequireApproval` y no `Deny` porque el escaneo es léxico y tiene
falsos positivos (`cat .git/HEAD`, `ls /`), y porque por defecto el único
perfil con `process:execute` es la sesión del usuario, que ya pide
aprobación para escribir en `.claude/` y para `git push`. Un subagente no
llega a estas reglas: se le niega `Bash` por falta de capacidad.

Este escaneo **se puede evadir** y no es un límite de seguridad: un script o
un `Makefile`, un alias o una función de shell definidos en otro lado, un
glob, una ruta armada en tiempo de ejecución, un comando codificado que otro
programa permitido decodifica, o cualquier programa que abra archivos o
conexiones por su cuenta hacen lo que el texto del comando no dice. Dos
casos comunes que no detecta: `git config`, que escribe `.git/config` sin
nombrarlo, y `git fetch`, `git clone`, `git pull` o `git submodule`, que
usan la red (`git` no está en la lista de herramientas de red).

**Ejecutar `Bash` confinado.** Claude Code tiene un sandbox para `Bash`
([documentación](https://code.claude.com/docs/en/sandboxing), y las claves en
[settings](https://code.claude.com/docs/en/settings-reference#sandbox-filesystem)),
en macOS, Linux y WSL2. Según esa documentación, los comandos confinados
escriben solo en el directorio de trabajo, en el temporal del usuario y en
los directorios agregados; dentro de ellos ya deniega escribir en los
archivos de configuración de `.claude` (`settings*.json`, `agents/`,
`hooks/`, `skills/`, `commands/`), en `.mcp.json`, en `.vscode/`, `.idea/`,
`.gitconfig` y los archivos de inicio del shell, y en `.git/hooks` y
`.git/config`; y la
red pasa por un proxy con dominios permitidos, que empiezan vacíos. Para
dejar además `.claude/` y `.git/` completos de solo lectura para `Bash`, en
`<proyecto>/.claude/settings.json` (las rutas `./` se resuelven contra la
raíz del proyecto):

```json
{
  "sandbox": {
    "enabled": true,
    "failIfUnavailable": true,
    "allowUnsandboxedCommands": false,
    "autoAllowBashIfSandboxed": false,
    "filesystem": { "denyWrite": ["./.claude", "./.git"] }
  }
}
```

Con `autoAllowBashIfSandboxed: false` (por defecto es `true`), un comando
confinado vuelve a pasar por los permisos normales. Se recomienda porque la
documentación dice que un `deny` de un hook `PreToolUse` se aplica antes
que las reglas de permiso, pero no dice si un `ask` del hook (`git push`,
`approval-command-*`) se sigue mostrando cuando el sandbox aprueba `Bash`
solo.

`allowUnsandboxedCommands: false` quita el reintento fuera del sandbox y
`failIfUnavailable: true` evita que corra sin sandbox si no puede iniciarlo.
Con `./.git` de solo lectura, `git commit` y similares fallan dentro del
sandbox; hacer commit fuera de Claude Code. Agregar `git` a
`excludedCommands` para evitarlo lo haría correr sin confinar del todo. En un
worktree enlazado, `./.git` es un archivo y el sandbox permite escribir en el
`.git` común del repositorio principal (salvo `hooks/` y `config`): ese
directorio no queda cubierto por `./.git` y hay que agregar su ruta absoluta
a `denyWrite` si también debe ser de solo lectura. El sandbox no cubre las
herramientas de archivos ni los hooks (el hook de PRÆTORE sigue corriendo
con acceso completo), ni los servidores MCP locales, y un comando en
`excludedCommands` corre sin confinar. Revisar esa documentación para la
versión de Claude Code en uso. La dirección a más largo plazo es que un
ejecutor confinado como el de T-013 B (`praetore-sandbox-fs`,
[#61](https://github.com/Mavericksantander/praetore/pull/61)) sea el que
abra archivos y ejecute, en vez de la herramienta de Claude Code.

## Probarlo

Desde la raíz de un clon:

```sh
./examples/claude-code-hook/demo.sh     # regenera bundle/ con 22 tool calls fijas
./examples/claude-code-hook/verify.sh   # verifica bundle/ solo con praetore-verify
```

El `bundle/` comprometido es anterior a GHSA-wg33-3h8v-xvqw y no se
regeneró en ese cambio: todavía muestra a `coder` ejecutando `Bash` (con
`allow-exec`) y los `git push` hechos como `coder`. `demo.sh` regenera hoy
otro resultado (`coder` sin `Bash`, los `git push` como `main`). Los sets de
`evidence/` también son históricos.

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
./examples/claude-code-hook/verify.sh <bundle>
```

Los subagentes de ejemplo (`agents/`) son `planner` (opus, solo lectura),
`coder` (sonnet, edita archivos pero no ejecuta comandos) y `explorer`
(haiku, solo lectura).

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
  escribir en `.claude/` con Write, Edit, MultiEdit o NotebookEdit, y la
  sesión principal necesita aprobación. Eso no vale para `Bash`: un perfil
  con `process:execute` puede cambiar `.claude/` (y con ello el registro del
  hook para las sesiones siguientes) desde un comando; ver
  [`Bash` y `process:execute`](#bash-y-processexecute). Además, según la
  [documentación de permisos](https://code.claude.com/docs/en/permissions#precedence-among-rules-hooks-and-mods),
  un *mod* de Claude Code que maneja `tool.check` responde después de los
  hooks `PreToolUse` y, sin managed settings ni un `/login` Team o
  Enterprise, puede aprobar una llamada que el hook bloqueó o para la que
  pidió aprobación. Una sesión iniciada con `claude --agent <nombre>` trae
  `agent_type` y se evalúa con el perfil de ese agente, no como `main`.
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
