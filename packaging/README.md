# Packaging

Build a single-file agent binary using PyInstaller.

## Windows

```powershell
.\packaging\build_agent.ps1
```

Output: `dist\apt-agent.exe`

Optional Windows service wrapper:

```powershell
.\packaging\windows\install_agent_service.ps1 -BinaryPath .\dist\apt-agent.exe
```

## Linux / macOS

```bash
./packaging/build_agent.sh
```

Output: `dist/apt-agent`

Optional Linux systemd unit:

```bash
sudo install -m 0644 packaging/linux/apt-agent.service /etc/systemd/system/apt-agent.service
sudo systemctl daemon-reload
```

Optional macOS launchd plist:

```bash
sudo cp packaging/macos/com.apt-simulator.agent.plist /Library/LaunchDaemons/
```

## Requirements

- Project venv with dev deps: `pip install -e ".[dev]"`
- Run from the project root.

## Notes

- The spec excludes server-only dependencies (FastAPI, uvicorn, SQLAlchemy) to keep the binary small.
- Plugin auto-registration works in the frozen binary because `collect_submodules("ttps")` materializes every TTP module.
- Dev builds are NOT code-signed. Sign with `signtool` (Windows) or `codesign` (macOS) for production deployment.
- Service wrappers are committed for enterprise lab deployment, but production rollout still requires local paths, user accounts, secrets, network boundaries, and change control.
- Strip + UPX are disabled by default. Enable in `agent.spec` if size matters more than build determinism.
- The `/enterprise/agent-packaging` endpoint exposes the Windows, Linux, and macOS packaging matrix used by the benchmark pack.
