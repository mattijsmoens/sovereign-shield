# v2.4.0 Release Plan

## Issues Found

1. **Version mismatch**: `pyproject.toml` says `2.3.2`, `__init__.py` says `2.2.3`
2. **Package data missing**: `common_words.json` not included in `pyproject.toml` package-data — PyPI installs break
3. **SaaS API out of sync**: `saas-api/sovereign_shield/input_filter.py` doesn't have the base64/hex decode fix
4. **README needs update**: Layer 6.7 docs say "5 decoded variants" — now it's 7 (added base64 + hex)

## Changes for v2.4.0

### 1. Bump version
- `pyproject.toml`: `2.3.2` → `2.4.0`
- `__init__.py`: `2.2.3` → `2.4.0`

### 2. Fix package-data (common_words.json)
- `pyproject.toml` `[tool.setuptools.package-data]` must include `data/*.json`

### 3. Sync SaaS API
- Copy updated `input_filter.py` to `saas-api/sovereign_shield/`

### 4. Update README
- Layer 6.7: "7 decoded variants" (add base64 + hex)
- Add changelog entry for 2.4.0

### 5. Build & publish
- `python -m build`
- `twine upload dist/*`

### 6. Rebuild website.zip & deploy to Cloud Run
