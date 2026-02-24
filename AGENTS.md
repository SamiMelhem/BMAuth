# AGENTS.md

## Cursor Cloud specific instructions

### Overview

BMAuth is a Python library providing WebAuthn/FIDO2 biometric authentication for FastAPI apps. It is a single-package library (not a monorepo) installed via `pip install -e ".[dev]"`.

### Running the app

The bundled demo app (`tests/test_app.py`) requires Supabase credentials (`SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`). To run **without** external services, start uvicorn with in-memory storage:

```bash
python3 -c "
import uvicorn
from fastapi import FastAPI
from bmauth.auth import BMAuth

app = FastAPI(title='BMAuth Dev App')
auth = BMAuth(app, database={'provider': 'memory'}, host='localhost')

@app.get('/')
async def root():
    return {'message': 'BMAuth Dev App'}

uvicorn.run(app, host='0.0.0.0', port=8000)
"
```

### Lint / type-check commands

Configured in `pyproject.toml`. Add `$HOME/.local/bin` to `PATH` first if tools are not found.

- `black --check bmauth/ tests/` — formatting
- `flake8 bmauth/ tests/` — style (pre-existing E501 line-length warnings exist)
- `mypy bmauth/ --ignore-missing-imports` — type checking (use `--ignore-missing-imports`; `pyproject.toml` targets Python 3.8 but mypy requires >=3.9, so the configured `python_version` causes a warning)

### Tests

- `pytest` — no real test functions exist yet; `tests/test_app.py` is a demo app, not a pytest suite
- Running `pytest` will fail at collection because `test_app.py` hard-codes `provider: "supabase"` and crashes without credentials

### Gotchas

- `pip install -e ".[dev]"` installs to `~/.local/bin` (user install). Ensure `$HOME/.local/bin` is on `PATH`.
- WebAuthn biometric flows require a browser with platform authenticator support and HTTPS (or `localhost`). Full end-to-end biometric testing is not possible in headless/cloud environments.
