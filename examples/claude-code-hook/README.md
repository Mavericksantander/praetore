# Ejemplo: PRÆTORE autoriza las tool calls de agentes de Claude Code

Un hook `PreToolUse` de Claude Code que pasa por PRÆTORE **las acciones de
herramientas que pasan por el hook**: lecturas, escrituras, comandos, red y
delegación, tanto de la sesión principal como de los subagentes. Lo que un
agente haga por otro camino queda fuera (ver Límites).

> Ejemplo independiente: no es miembro del workspace del repositorio y no
> forma parte del producto. Tiene su propio `Cargo.toml` y `Cargo.lock`.

## Qué hace

- `init` crea una clave Ed25519 por perfil de agente y una autoridad firmada
  por un emisor local que da solo las capacidades de ese perfil. La clave del
  emisor se descarta después de firmar; queda solo su pin público. También
  crea una clave de atestador para firmar los recibos.
- Por cada tool call, el hook arma un `AuthorizationRequest` firmado con la
  clave del perfil, lo evalúa con un motor `strict` contra una policy v2 que
  por defecto niega, firma la evidencia con el atestador y la agrega a
  `receipts.jsonl`.
- `Deny` → la tool call se bloquea. `RequireApproval` → Claude Code le
  pregunta al usuario. `Allow` → el hook no decide y siguen aplicando los
  permisos propios de Claude Code.

| Perfil | Capacidades |
| --- | --- |
| `main` (sesión principal, sin `agent_type`) | `fs:read`, `fs:write`, `process:execute`, `network:invoke`, `agent:delegate`, `tool:invoke` |
| `planner`, `explorer` | `fs:read` |
| `coder` | `fs:read`, `fs:write`, `process:execute` |
| `web-fetch` (lector web incorporado de Claude Code) | `network:invoke` |
| `unregistered` | ninguna |

Cualquier otro `agent_type`, incluidos agentes incorporados como
`general-purpose`, se evalúa con el perfil `unregistered`. Ese perfil no
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
./examples/claude-code-hook/demo.sh     # regenera bundle/ con 22 tool calls fijas
./examples/claude-code-hook/verify.sh   # verifica bundle/ solo con praetore-verify
```

`verify.sh` hace lo siguiente:

1. Compila `praetore-verify` con `--locked`.
2. Verifica cada recibo con
   `praetore-verify evidence --attester-pin ... --issuer-pins ... --require-intent`.
3. Comprueba que el `policy_digest` de cada recibo es igual al digest de la
   `policy.json` publicada.
4. Altera un byte de una copia y comprueba que la verificación falla.
5. Resume las decisiones por agente.

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
`coder` (sonnet) y `explorer` (haiku, solo lectura).

## Qué prueba un recibo y qué no

- **Prueba** que la evidencia no cambió desde que la firmó el atestador, que
  la intención la firmó la clave de ese **perfil de agente**, que la
  autoridad la emitió el emisor pineado para esa clave, y bajo qué policy se
  decidió.
- **No prueba qué agente fue.** Las claves de todos los perfiles y la del
  atestador viven en la misma cuenta de usuario que los agentes, así que la
  firma identifica el perfil, no aísla un agente de otro.
- **No prueba que la acción se ejecutó**, ni que no hubo acciones fuera del
  hook.

## Límites

- **Cooperativo.** Solo cubre las tool calls que pasan por el hook, y solo
  mientras el hook esté configurado. Por eso los subagentes no pueden
  escribir en `.claude/`, y la sesión principal necesita aprobación.
- **Lo que corre dentro de un comando permitido no se ve.** Un script
  (`./deploy.sh`), un `Makefile` o un alias de git definido en la
  configuración pueden hacer push sin que el comando lo diga.
- **Ventana entre el chequeo y el uso.** La ruta se resuelve cuando el hook
  evalúa, y la herramienta la abre después. Si en ese intervalo alguien
  cambia un directorio por un symlink, la herramienta puede abrir otra cosa.
- **macOS:** `/tmp` y `/var` son symlinks a `/private/...`. Una ruta como
  `/tmp/x` no se resuelve a sí misma, así que se niega bajo cualquier regla de
  ruta. Hay que usar rutas resueltas.
- **Raíz fija.** La raíz de la policy es la ruta absoluta dada en `init`.
  Mover el proyecto exige otro `init`.
