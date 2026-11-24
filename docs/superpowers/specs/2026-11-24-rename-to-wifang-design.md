# Design: Rename the project `wifit3` → `wifang`

Status: awaiting approval
Date: 2026-11-24

## Intent and why

This repo is a Linux-focused fork of derv82's `wifit3` whose reason to exist is
PCIe/M.2 and built-in-card support (the netdev / in-kernel-driver backend), a
path that cannot be made cross-platform. Sharing the upstream name causes
confusion. We rebrand to **`wifang`** — a name that still reads as a Wi-Fi
auditing tool (the `wi-` family, like `wifite`/`wifit3`) but is clearly its
own project. The PyPI slot `wifang` is free; the only same-name hit is a
dormant, unrelated 2-star hardware repo, which we have accepted.

## Goals

- Rename the project's **outward identity** everywhere: the PyPI/package name,
  the CLI entry point, the Python import package, env vars, config dir, docs,
  CI, and image-asset filenames.
- Leave the tree importable, lint-clean, and test-green after the rename.
- Preserve all attribution to upstream projects.

## Non-goals (explicitly out of scope)

- **The inherited `Wifite*` internal layer stays as-is.** `WifiteApp`, the
  `Wifite*Error` exception hierarchy, Textual's auto-derived
  `on_wifite_app_*` message handlers, and the `WiFFy` assistant / "Wifite on
  Netflix" easter-egg are internal lineage and are **not** renamed. This keeps
  the risky Textual class-name→handler-name coupling entirely out of the change.
- **No config/data migration.** Clean break: the app simply uses the new
  `~/.config/wifang/` location; existing users reconfigure. No old `wifit3`
  CLI alias is kept (see Builder calls).
- **No re-rendering of raster artwork.** Image files are renamed and all
  references rewired, but the pictures themselves (splash/scanner PNGs,
  `.ico`, demo GIF) still show the old name/UI until regenerated separately.

## Anti-goals (would make this a failure even if it "works")

- Rewriting upstream credits. References to `wifite2` / `@kimocoder` and the
  "matching upstream" GPL note must survive untouched (they use the string
  `wifite2`, not `wifit3`, so a scoped rename leaves them alone — verify).
- A half-renamed tree: a stray importable `wifit3` module, a dead
  `wifit3`-named asset reference, or CI still importing `wifit3`.
- Running `ruff format` (repo-wide ban) or otherwise reflowing code. All
  edits are name substitutions only.

## Constraints

- Code style and `chips/` rules per AGENTS.md; **never** `ruff format`.
- Human-facing `.md` edits are flagged for human wording review in the hand-off.
- Develop on branch `claude/gallant-clarke-fefdqs`; no push or PR unless asked.
- `git mv` for the module dir and asset files to preserve history.

## Scope / blast radius (measured)

- String occurrences: `wifit3` ×3970, `WIFIT3` ×65, `Wifit3` ×34 → `wifang`,
  `WIFANG`, `Wifang`. (`Wifite`/`wifite` ×138 all **stay**.)
- Module directory: `src/wifit3/` → `src/wifang/`.
- CLI entry point: `[project.scripts] wifit3 = "wifit3.__main__:main"`.
- Build/version: `[project].name`, `[tool.hatch.version].path`.
- PyInstaller: `wifit3.spec` (file + contents, incl. icon ref).
- Config dir: `user_config_dir("wifit3", ...)` in `persist/config.py` (single
  name-derived user location; `captures_dir` is user-set and untouched).
- Assets: `assets/wifit3-*.png`, `wifit3.ico`, `wifit3-demo.gif`,
  `wifit3-icon-source.png` → `wifang-*`, plus every reference.
- CI/meta: `.github/workflows/*.yml`, issue templates, `.gitignore`,
  `CONTRIBUTING.md`, `README.md`, `AGENTS.md`/`CLAUDE.md`, `docs/**`.
- Tests: all `from wifit3 ...` imports; `scripts/**` incl. filename
  `scripts/baseline/baseline_wifit3.py`.

## Approaches considered

1. **Pure find-and-replace of all `wifit3` + `git mv`** — mechanical sweep of
   the three case variants across the tree, plus directory/asset moves.
   *Chosen.* Lowest risk given "outward identity only": the substitution is
   unambiguous because the kept layer is spelled `wifite`, not `wifit3`.
2. **Full rebrand incl. `Wifite*` identifiers** — also rename the app class,
   exceptions, and forced Textual handlers. *Rejected by decision:* larger and
   introduces class→handler coupling (a missed handler silently stops event
   routing) for no outward benefit.
3. **Rename + regenerate artwork now** — *Rejected:* raster art can't be
   re-rendered well in-session; deferred to a follow-up.

Follow-on decisions (also settled): config = **clean break**; assets =
**rename files + rewire refs now**.

## How it gets built (the parts decided)

Staged commits on `claude/gallant-clarke-fefdqs`, each independently green:

1. **Module move** — `git mv src/wifit3 src/wifang`; fix `wifit3`→`wifang` in
   all Python imports/strings under `src/`, `tests/`, `scripts/` (all three
   case variants); rename `scripts/baseline/baseline_wifit3.py`.
2. **Packaging** — `pyproject.toml` (`name`, `[project.scripts]` →
   `wifang = "wifang.__main__:main"`, `hatch.version.path`); `git mv
   wifit3.spec wifang.spec` and update its contents.
3. **Assets** — `git mv` each `wifit3-*`/`wifit3.*` asset to `wifang-*`;
   rewire references in `README.md`, `pyproject`, spec, and code.
4. **CI + repo meta** — workflows, issue templates, `.gitignore`,
   `CONTRIBUTING.md`.
5. **Docs** — `README.md` H1 and body, `AGENTS.md`/`CLAUDE.md` (commands,
   example paths like `wifang.ui.app:WifiteApp` — module renamed, class kept),
   `docs/**` prose and historical planning/superpowers docs (mechanical
   substitution only). Preserve `wifite2`/`kimocoder` credits verbatim.

## Verification (gate before hand-off)

- `uv run ruff check src/` clean (lint only; no format).
- `uv run pytest` green.
- `uv run wifang` launches (smoke); `python -c "import wifang"` works and
  `import wifit3` fails (no leftover module).
- `git grep -In 'wifit3\|WIFIT3\|Wifit3'` returns **only** intended-historical
  doc mentions, if any — ideally zero; no code/packaging/CI hits.
- `git grep -In 'wifite2\|kimocoder'` unchanged (attribution intact).

## Builder calls (my calls, flag to veto)

- **No `wifit3` CLI alias.** Clean break per the config decision; single
  `wifang` command. (Veto → add a thin `wifit3` alias entry point.)
- **Env vars `WIFIT3_*` → `WIFANG_*`** as part of outward identity; users who
  set them update them (consistent with clean break).
- **Historical docs** (`docs/superpowers/plans/*`, `docs/planning/*`) get the
  mechanical substitution too, so example import paths stay valid, rather than
  being frozen with dead `wifit3` imports.

## Left to the builder (planning step)

Exact file list per commit, and the precise substitution commands (scoped so
`wifite`/`Wifite` is never touched). Produced by the writing-plans step.
