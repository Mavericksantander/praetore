# Mapa de implementación

Observación del 2026-11-17. Base leída: `main`
`27ceddbbd295162ca351ea5dfa47fe8bb37315a3`, mensaje
`Merge pull request #187 from Mavericksantander/release/praetore-mcp-0.3.6`.
La versión del workspace es `0.3.6` (`Cargo.toml`, clave `workspace.package.version`).

Este archivo no estaba en el árbol en ese commit. `git log --all -- '*IMPLEMENTATION_MAP*'`
no devolvió commits. La sección de abajo es la primera. No hay niveles de
madurez escritos en el repositorio, y este documento no calcula ninguno.

## Tag v0.3.6

`git tag --points-at HEAD` en el clon de la auditoría no imprimió tags: el
clon no los tenía. En origin sí. `git ls-remote --tags origin`:

| Ref | Objeto |
|---|---|
| `refs/tags/v0.3.6` | `89d9120b63f2b6becf8bb4ad7af7bf8bb7d1e92b` (tag anotado) |
| `refs/tags/v0.3.6^{}` | `27ceddbbd295162ca351ea5dfa47fe8bb37315a3` |

El tag descuelga en el merge de #187.

## PRs mergeados en esta base

Estado `MERGED` según `gh pr view`. El merge commit es el que devolvió esa
consulta. #177 y #178, y del #181 al #187. No se reescribe aquí qué hace
cada uno más allá del título.

| PR | Merge commit | Título |
|---|---|---|
| [#177](https://github.com/Mavericksantander/praetore/pull/177) | `fa903977a2a87841f431b585b466c1e2c0d68a82` | feat(praetore-mcp): session reports (JSON + PDF) when a wrap session ends |
| [#178](https://github.com/Mavericksantander/praetore/pull/178) | `1686672b3b4b38480e29efb9634aa03764fe9dcd` | praetore-mcp: copyable commands with absolute paths; approval expiry in local time |
| [#181](https://github.com/Mavericksantander/praetore/pull/181) | `a08d4a050392dc7869005aeb8212989411ee14e0` | praetore-mcp: download session reports from the dashboard |
| [#182](https://github.com/Mavericksantander/praetore/pull/182) | `81f9ff4f53fb26cdaa73a25840cdf53c404313b3` | docs(praetore-mcp): install instructions for v0.3.5 |
| [#183](https://github.com/Mavericksantander/praetore/pull/183) | `e43e37e1a217627104b9294602dd4cd5901c6299` | fix(praetore-mcp): expired approvals from the server; exact version checks |
| [#184](https://github.com/Mavericksantander/praetore/pull/184) | `1b4a88d26aa0ee08e7fbb2aaa64680c041c32db9` | fix(praetore-mcp): one expiry rule for pending approvals |
| [#185](https://github.com/Mavericksantander/praetore/pull/185) | `e76ab02e751a4f974d9acabac2acb458d7c145ac` | fix(praetore-mcp): Expiry::at only for display, enforced by clippy |
| [#186](https://github.com/Mavericksantander/praetore/pull/186) | `9a1b993ed03a84fe26b620c3c58791d0e025ffe7` | praetore-mcp: approval guards (n11, n12, H1), SIGTERM during report test, minors of #178 |
| [#187](https://github.com/Mavericksantander/praetore/pull/187) | `27ceddbbd295162ca351ea5dfa47fe8bb37315a3` | release: praetore-mcp 0.3.6 |

## T-006. Estado real de Assurance gates

Comando, el 2026-11-17:

`gh run list --branch main --workflow 'Assurance gates' --limit 20 --json databaseId,headSha,displayTitle,status,conclusion,event,createdAt,url,headBranch`

Workflow: `.github/workflows/assurance.yml`. Los dos jobs que el archivo
condiciona con `startsWith(github.ref, 'refs/tags/v')` son `Sign release checksums`
(`assurance.yml:900-901`) y `GitHub Release` (`assurance.yml:945-946`). Un
push a `main` no es un tag `v*`, así que esos dos salen skipped. Eso es lo
que se ve en el run de `27ceddbb`.

### Run de `27ceddbb` (v0.3.6)

| Campo | Valor |
|---|---|
| Run | https://github.com/Mavericksantander/praetore/actions/runs/43957926913 |
| Evento | `push` |
| Creado | `2026-11-16T21:13:49Z` |
| Head | `27ceddbbd295162ca351ea5dfa47fe8bb37315a3` |
| Conclusión del run | `success` |
| Jobs | 23 `success`, 2 `skipped`. Cero `failure`, cero `cancelled` |

`success`:

- G7 mutation test (classify removed from each entry point)
- Claude Code hook example (standalone)
- PostgreSQL replay guard integration
- macOS workspace link
- Claude Code hook evidence (sets 03, 04, 05)
- Rust tests, lint, and format
- Journal chains (sets 03, 04, 05) and tampered copies
- Python evidence verification
- Actions pinned by commit SHA
- Fuzz smoke
- Dependency advisory audit
- Offline verifiers build without receipt signing
- praetore-mcp x86_64-apple-darwin build and package
- G1 mutation test (gap check and rejected records removed)
- CycloneDX SBOM
- praetore-mcp x86_64-unknown-linux-gnu build and package
- Console page (language and local time)
- praetore-mcp aarch64-apple-darwin build and package
- praetore-mcp x86_64-unknown-linux-gnu smoke
- praetore-mcp x86_64-apple-darwin smoke
- praetore-mcp aarch64-apple-darwin smoke
- Release checksums
- Release signature (cosign verify-blob)

`skipped`: Sign release checksums, GitHub Release.

### Run anterior en `main`, merge de #186

No es el head. Queda aquí porque el run de ese push no está en verde, y
T-006 pide el estado real, no solo el último éxito.

| Campo | Valor |
|---|---|
| Run | https://github.com/Mavericksantander/praetore/actions/runs/43942169376 |
| Creado | `2026-11-16T19:42:42Z` |
| Head | `9a1b993ed03a84fe26b620c3c58791d0e025ffe7` |
| Conclusión del run | `failure` |
| Jobs | 16 `success`, 3 `cancelled`, 4 `skipped`. Ningún job con conclusión `failure` |

`cancelled`:

- praetore-mcp x86_64-apple-darwin build and package (`mcp-binaries`, `assurance.yml:719-720`)
- praetore-mcp aarch64-apple-darwin build and package (el mismo job, otra celda)
- macOS workspace link (`assurance.yml:184`)

`skipped`, con el nombre que devolvió `gh run view`:

- `praetore-mcp ${{ matrix.target }} smoke` (`assurance.yml:783`)
- Release checksums (`release-integrity`, `assurance.yml:835-841`, `needs: mcp-binaries` y `mcp-smoke`)
- Sign release checksums
- GitHub Release

La consulta no trae un job con conclusión `failure`. El run, aun así, está
marcado `failure`. No se atribuye aquí la causa de las cancelaciones.

### Runs de `main` devueltos por el mismo `gh run list` (límite 20)

Conclusión y head, del más nuevo al más viejo. El enlace es el `url` del JSON.

| Conclusión | Head | Run |
|---|---|---|
| success | `27ceddbbd295162ca351ea5dfa47fe8bb37315a3` | https://github.com/Mavericksantander/praetore/actions/runs/43957926913 |
| failure | `9a1b993ed03a84fe26b620c3c58791d0e025ffe7` | https://github.com/Mavericksantander/praetore/actions/runs/43942169376 |
| success | `e76ab02e751a4f974d9acabac2acb458d7c145ac` | https://github.com/Mavericksantander/praetore/actions/runs/43905011926 |
| success | `1b4a88d26aa0ee08e7fbb2aaa64680c041c32db9` | https://github.com/Mavericksantander/praetore/actions/runs/43820492339 |
| success | `e43e37e1a217627104b9294602dd4cd5901c6299` | https://github.com/Mavericksantander/praetore/actions/runs/43812084369 |
| success | `a08d4a050392dc7869005aeb8212989411ee14e0` | https://github.com/Mavericksantander/praetore/actions/runs/43807501142 |
| success | `81f9ff4f53fb26cdaa73a25840cdf53c404313b3` | https://github.com/Mavericksantander/praetore/actions/runs/43801974025 |
| success | `fa903977a2a87841f431b585b466c1e2c0d68a82` | https://github.com/Mavericksantander/praetore/actions/runs/43793540774 |
| success | `1686672b3b4b38480e29efb9634aa03764fe9dcd` | https://github.com/Mavericksantander/praetore/actions/runs/43783475323 |
| success | `b6d668acb8e153a47a9478fe96b92a0c9eafb423` | https://github.com/Mavericksantander/praetore/actions/runs/43769957805 |
| success | `fffbf1ff8b2a9ee17403819acb74bca46fad0574` | https://github.com/Mavericksantander/praetore/actions/runs/43765034724 |
| success | `56522b2f946da167ea985c65bc3e4b6b1e6d96c5` | https://github.com/Mavericksantander/praetore/actions/runs/43752129531 |
| success | `84f7db4f58807cd5008ae62597c3aa0dd6468621` | https://github.com/Mavericksantander/praetore/actions/runs/43752109153 |
| success | `b1ecdf1f3d57163afc8f2a4c6b78f309fee1345d` | https://github.com/Mavericksantander/praetore/actions/runs/43743091238 |
| success | `f5810d2ea3904c8467194a11d65dc8e8041ec2cf` | https://github.com/Mavericksantander/praetore/actions/runs/43742895391 |
| success | `040f813b9694fd9c0c71ba71781f3f309e354a09` | https://github.com/Mavericksantander/praetore/actions/runs/43672345936 |
| success | `5a6bc625fa0e1d952ba82b58746a47bae8eb4d1b` | https://github.com/Mavericksantander/praetore/actions/runs/43671566396 |
| success | `baa3a1354b79e1819cc76d0b67ba9c4d7275fd54` | https://github.com/Mavericksantander/praetore/actions/runs/43671550572 |
| success | `742953a92ff5fbdd46c043856c7d1a1694706f2c` | https://github.com/Mavericksantander/praetore/actions/runs/43671534901 |
| failure | `1f3eacc514cdccf17ddf84836924dc79285a79d9` | https://github.com/Mavericksantander/praetore/actions/runs/43656045372 |

De esos 20, 18 `success` y 2 `failure`. Solo el run de `27ceddbb` y el de
`9a1b993` tienen el desglose de jobs de arriba. El run
[43656045372](https://github.com/Mavericksantander/praetore/actions/runs/43656045372)
figura como `failure` en la lista. No se abrieron sus jobs en esta pasada.
