# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for the APT Simulator agent.
# Build: pyinstaller packaging/agent.spec --clean --noconfirm

from PyInstaller.utils.hooks import collect_submodules

block_cipher = None

# Force inclusion of every TTP plugin so registry self-registration works
# in the frozen binary (PyInstaller cannot trace conditional imports).
hidden = (
    collect_submodules("ttps")
    + collect_submodules("orchestrator.core")
    + ["cryptography.hazmat.backends.openssl"]
)

a = Analysis(
    ["../agent/main.py"],
    pathex=[".."],
    binaries=[],
    datas=[],
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=["uvicorn", "fastapi", "starlette", "sqlalchemy", "sqlmodel"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="apt-agent",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
