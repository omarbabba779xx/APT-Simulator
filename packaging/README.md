# Packaging

Build a single-file agent binary using PyInstaller.

## Windows

```powershell
.\packaging\build_agent.ps1
```

Output: `dist\apt-agent.exe`

## Linux / macOS

```bash
./packaging/build_agent.sh
```

Output: `dist/apt-agent`

## Requirements

- Project venv with dev deps: `pip install -e ".[dev]"`
- Run from the project root.

## Notes

- The spec excludes server-only dependencies (FastAPI, uvicorn, SQLAlchemy) to keep the binary small.
- Plugin auto-registration works in the frozen binary because `collect_submodules("ttps")` materializes every TTP module.
- Dev builds are NOT code-signed. Sign with `signtool` (Windows) or `codesign` (macOS) for production deployment.
- Strip + UPX are disabled by default. Enable in `agent.spec` if size matters more than build determinism.
- The `/enterprise/agent-packaging` endpoint exposes the Windows, Linux, and macOS packaging matrix used by the benchmark pack.
