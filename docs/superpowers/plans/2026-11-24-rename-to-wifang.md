# Rename `wifit3` → `wifang` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the project's outward identity from `wifit3` to `wifang` across code, packaging, assets, CI, and docs, leaving the tree importable, lint-clean, and test-green.

**Architecture:** A scoped string/path substitution, not a behavior change. The three case variants `wifit3`/`WIFIT3`/`Wifit3` become `wifang`/`WIFANG`/`Wifang`. The inherited internal layer spelled `wifite`/`Wifite` (the `WifiteApp` class, `Wifite*Error`, `on_wifite_app_*` handlers, WiFFy easter-egg) is **never** touched — the substitution tokens are disjoint from it. Staged as independently-green commits on `claude/gallant-clarke-fefdqs`.

**Tech Stack:** Python 3.11+, `uv`, hatchling, Textual, PyInstaller, pytest, ruff.

**Spec:** `docs/superpowers/specs/2026-11-24-rename-to-wifang-design.md`

## Global Constraints

- Substitute only `wifit3`→`wifang`, `WIFIT3`→`WIFANG`, `Wifit3`→`Wifang`. Never alter `wifite`/`Wifite` (verify its count stays **138**).
- Never run `ruff format`; edits are name substitutions only (no reflow).
- Preserve `wifite2` / `@kimocoder` credits and the GPL "matching upstream" note verbatim.
- Config is a **clean break**: no migration code, no `wifit3` CLI alias.
- **Exclude from all content substitution** this rename's own meta-docs (they intentionally discuss both names): `docs/superpowers/specs/2026-11-24-rename-to-wifang-design.md` and `docs/superpowers/plans/2026-11-24-rename-to-wifang.md`. Never `sed` `uv.lock` — regenerate it.
- `git mv` for directory/file renames (preserve history).
- Develop on `claude/gallant-clarke-fefdqs`; no push or PR unless the user asks.
- **Decision (default = yes):** the GitHub repo will be renamed `K4kt00z/wifit3`→`K4kt00z/wifang`, so `K4kt00z/wifit3` URLs are swept like everything else (GitHub redirects the old path). If the user keeps the repo name, Task 4's note applies.

## Review Focus

- A missed import of the old package name → `ImportError` at collection/runtime. Pinned by Task 1 (full `uv run pytest` + zero-`wifit3` grep over `src/ tests/ scripts/`).
- The runtime `pkgutil` walk over `wifang.chips` in `device/manager.py` and `collect_submodules("wifang.chips")` in the spec — a stale `wifit3.chips` string makes chip drivers silently undiscovered (app launches, finds no interfaces). Pinned by Task 1's explicit chip-discovery check and Task 2's build-spec grep.
- `WIFANG_*` env vars read via `os.environ.get` vs. their documentation in chip `.md` files — a code/doc mismatch leaves a documented toggle silently dead. Pinned by Task 1's uniform uppercase sweep + grep across code and docs under `src/`.
- CI import line `from wifit3.ui.app import WifiteApp` and the release tag-gate reading `src/wifit3/__init__.py` — stale → CI red or release gate broken. Pinned by Task 4.
- The two rename meta-docs intentionally contain `wifit3`; a blanket sweep would corrupt them into `wifang → wifang`. Pinned by the Global-Constraints exclusion and Task 5's verification that only those two files still contain `wifit3`.

---

### Task 1: Rename the Python project (package, packaging metadata, lockfile)

Packaging metadata moves **with** the directory: a renamed `src/wifang/` while `pyproject.toml` still declares the `wifit3` package leaves the tree un-buildable (hatchling can't find the package), so `uv run` would fail. They land in one commit.

**Files:**
- Move: `src/wifit3/` → `src/wifang/` (whole tree); `scripts/baseline/baseline_wifit3.py` → `scripts/baseline/baseline_wifang.py`
- Modify: every `.py` and `src/**/*.md` under `src/`, `tests/`, `scripts/` containing a name token; `pyproject.toml`
- Regenerate: `uv.lock`
- Test: existing suite (`tests/`); no new unit tests (pure rename — proof is green suite + structural invariants)

**Interfaces:**
- Produces: importable package `wifang` (was `wifit3`), same public surface; console script `wifang = "wifang.__main__:main"`; distribution/metadata name `wifang`; `wifang.chips` as the runtime-discovered driver package; env vars `WIFANG_*`.

- [ ] **Step 1: Move the package and renamed script**

```bash
cd /home/user/wifit3
git mv src/wifit3 src/wifang
git mv scripts/baseline/baseline_wifit3.py scripts/baseline/baseline_wifang.py
```

- [ ] **Step 2: Substitute the three name tokens across code trees**

```bash
git grep -lIz -e wifit3 -e WIFIT3 -e Wifit3 -- src tests scripts \
  | xargs -0 sed -i 's/wifit3/wifang/g; s/WIFIT3/WIFANG/g; s/Wifit3/Wifang/g'
```

- [ ] **Step 3: Edit `pyproject.toml`** — set `name = "wifang"`, `[project.scripts]` to `wifang = "wifang.__main__:main"`, `[tool.hatch.version].path = "src/wifang/__init__.py"`, and any `[project.urls]` `wifit3`→`wifang`. (Leave `description = "Wireless Auditor TUI"`.)

- [ ] **Step 4: Regenerate the lockfile and reinstall**

Run: `uv lock && uv sync --group dev`
Expected: lock resolves with the package listed as `wifang`; sync succeeds.

- [ ] **Step 5: Verify imports, chip discovery, and the entry point**

Run:
```bash
uv run python -c "import pkgutil, wifang.chips as c; m=[x.name for x in pkgutil.iter_modules(c.__path__)]; assert m, 'no chips'; print('chips:', len(m))"
uv run python -c "import importlib.metadata as md; print('version', md.version('wifang')); assert any(e.name=='wifang' for e in md.entry_points(group='console_scripts')), 'no wifang script'"
uv run python -c "import wifit3" 2>/dev/null && echo "FAIL: wifit3 still importable" || echo "OK: no wifit3 module"
```
Expected: non-zero chip count; version prints and the `wifang` console script is registered; `OK: no wifit3 module`.

- [ ] **Step 6: Verify no old token remains, then run suite and lint**

Run: `git grep -nI -e wifit3 -e WIFIT3 -e Wifit3 -- src tests scripts pyproject.toml uv.lock` then `uv run pytest` and `uv run ruff check src/`
Expected: grep empty; pytest green; ruff clean.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "refactor: rename python project wifit3 -> wifang"
```

---

### Task 2: PyInstaller build spec

**Files:**
- Move: `wifit3.spec` → `wifang.spec`; Modify its contents

**Interfaces:**
- Consumes: the renamed package and packaging from Task 1 (`wifang`, `wifang.chips`, `src/wifang/__main__.py`, `assets/wifang.ico`).
- Produces: a build spec that emits a `wifang` binary.

- [ ] **Step 1: Rename and update the build spec**

```bash
git mv wifit3.spec wifang.spec
sed -i 's/wifit3/wifang/g; s/WIFIT3/WIFANG/g; s/Wifit3/Wifang/g' wifang.spec
```

(Updates `collect_data_files("wifang")`, `collect_submodules("wifang.chips")`, `["src/wifang/__main__.py"]`, `name="wifang"`, `assets/wifang.ico`, and comments.)

- [ ] **Step 2: Verify the spec is valid Python and token-clean**

Run: `uv run python -c "compile(open('wifang.spec').read(), 'wifang.spec', 'exec'); print('spec ok')"` then `git grep -nI -e wifit3 -e WIFIT3 -e Wifit3 -- wifang.spec`
Expected: `spec ok`; grep empty. (A true proof is a per-OS `uv run pyinstaller wifang.spec` build, which this container may not run — note it for release.)

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "build: rename PyInstaller spec to wifang"
```

---

### Task 3: Assets — rename image files and rewire every reference

**Files:**
- Move: `assets/wifit3-1-splash.png`, `wifit3-2-scanner.png`, `wifit3-3-focus-handshake.png`, `wifit3-3-focus-wpspbc.png`, `wifit3-demo.gif`, `wifit3-icon-source.png`, `wifit3.ico` → `wifang-*` / `wifang.ico`
- Modify: every reference to those filenames (README, `wifang.spec`, code, docs)

**Interfaces:**
- Consumes: the `assets/` tree.
- Produces: `assets/wifang-*` filenames; all references resolve. (Pixels unchanged — re-rendering artwork is a separate follow-up, per spec.)

- [ ] **Step 1: Rename the asset files**

```bash
cd assets
for f in wifit3-1-splash.png wifit3-2-scanner.png wifit3-3-focus-handshake.png \
         wifit3-3-focus-wpspbc.png wifit3-demo.gif wifit3-icon-source.png wifit3.ico; do
  git mv "$f" "${f/wifit3/wifang}"
done
cd ..
```

- [ ] **Step 2: Verify no reference still points at an old asset name**

Run: `git grep -nI 'wifit3-\|wifit3\.ico' -- . ':!docs/superpowers/specs/2026-11-24-rename-to-wifang-design.md' ':!docs/superpowers/plans/2026-11-24-rename-to-wifang.md'`
Expected: no output (asset refs in `wifang.spec` were updated in Task 2; any in README/docs are caught here — fix by `sed` on the listed files if present).

- [ ] **Step 3: Verify asset files exist under new names**

Run: `ls assets/wifang-1-splash.png assets/wifang.ico assets/wifang-demo.gif`
Expected: all present.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "assets: rename image files wifit3-* -> wifang-* and rewire references"
```

---

### Task 4: CI and repository metadata

**Files:**
- Modify: `.github/workflows/ci.yml`, `release.yml`, `update-fingerprint-data.yml`; `.github/ISSUE_TEMPLATE/*.yml`; `.gitignore`; `CONTRIBUTING.md`

**Interfaces:**
- Consumes: the renamed package (Task 1) and packaging (Task 2).
- Produces: workflows that import `wifang`, a release tag-gate reading `src/wifang/__init__.py`, and issue templates/links on the new name.

- [ ] **Step 1: Substitute tokens across CI and meta files**

```bash
git grep -lIz -e wifit3 -e WIFIT3 -e Wifit3 -- .github .gitignore CONTRIBUTING.md \
  | xargs -0 sed -i 's/wifit3/wifang/g; s/WIFIT3/WIFANG/g; s/Wifit3/Wifang/g'
```

(This also rewrites `K4kt00z/wifit3`→`K4kt00z/wifang` per the Global-Constraints decision. **If the user keeps the GitHub repo name**, restore those specific URL tokens: `git grep -lI 'K4kt00z/wifang' -- .github CONTRIBUTING.md | xargs sed -i 's#K4kt00z/wifang#K4kt00z/wifit3#g'`.)

- [ ] **Step 2: Verify the release tag-gate path and CI import were updated**

Run: `grep -n 'src/wifang/__init__.py' .github/workflows/release.yml` and `grep -n 'from wifang.ui.app import WifiteApp' .github/workflows/ci.yml`
Expected: both match (note the class stays `WifiteApp`).

- [ ] **Step 3: Verify YAML still parses and no stray token remains**

Run: `uv run python -c "import yaml,glob; [yaml.safe_load(open(f)) for f in glob.glob('.github/**/*.yml', recursive=True)]; print('yaml ok')"` then `git grep -nI -e wifit3 -e WIFIT3 -e Wifit3 -- .github .gitignore CONTRIBUTING.md`
Expected: `yaml ok`; the grep shows only intended-preserved `K4kt00z/wifit3` URLs if the user kept the repo name, otherwise nothing.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "ci: update workflows, issue templates, and repo metadata to wifang"
```

---

### Task 5: Documentation

**Files:**
- Modify: `README.md`, `AGENTS.md`, `CLAUDE.md`, `docs/**` (including historical `docs/planning/*` and `docs/superpowers/plans|specs/*`), `scripts/README.md`, `scripts/**/*.md`
- **Exclude:** `docs/superpowers/specs/2026-11-24-rename-to-wifang-design.md` and `docs/superpowers/plans/2026-11-24-rename-to-wifang.md`

**Interfaces:**
- Consumes: the renamed package/CLI/assets (Tasks 1–3), so example import paths and commands resolve.
- Produces: docs on the new name; `wifite2`/`kimocoder` credits untouched.

- [ ] **Step 1: Substitute tokens across docs, excluding this rename's meta-docs**

```bash
git grep -lIz -e wifit3 -e WIFIT3 -e Wifit3 -- '*.md' \
    ':!docs/superpowers/specs/2026-11-24-rename-to-wifang-design.md' \
    ':!docs/superpowers/plans/2026-11-24-rename-to-wifang.md' \
  | xargs -0 sed -i 's/wifit3/wifang/g; s/WIFIT3/WIFANG/g; s/Wifit3/Wifang/g'
```

(README H1 `# wifit3`→`# wifang`; AGENTS.md/CLAUDE.md commands and the `wifang.ui.app:WifiteApp` example — module renamed, **class kept**.)

- [ ] **Step 2: Verify attribution is intact**

Run: `grep -n 'wifite2\|kimocoder' README.md docs/CREDITS.md` and `git grep -cI 'wifite\|Wifite' | awk -F: '{s+=$2} END{print s}'`
Expected: credits present and unchanged; `wifite`/`Wifite` total still **138**.

- [ ] **Step 3: Verify only the two meta-docs still contain the old name**

Run: `git grep -lI -e wifit3 -e WIFIT3 -e Wifit3`
Expected: exactly the two excluded files (plus any `K4kt00z/wifit3` URLs only if the user kept the repo name).

- [ ] **Step 4: Full green re-check across the branch**

Run: `uv run pytest` and `uv run ruff check src/`
Expected: pytest green; ruff clean.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "docs: rename wifit3 -> wifang across documentation"
```

(Human-facing `.md` edits are agent-made — flag for a human wording review in the hand-off.)
