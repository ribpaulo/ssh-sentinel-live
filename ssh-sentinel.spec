"""PyInstaller configuration for Linux and Windows."""

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules


project_root = Path(SPECPATH)

# Templates, CSS, and JavaScript are included in the internal bundle alongside
# the Python modules. PyInstaller exposes them at runtime in --onefile mode.
data_files = [
    (str(project_root / "templates"), "templates"),
    (str(project_root / "static"), "static"),
]

# Uvicorn loads protocol and loop implementations through import strings, so
# the submodules must be declared explicitly for PyInstaller.
hidden_imports = collect_submodules("uvicorn")

analysis = Analysis(
    [str(project_root / "launcher.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=data_files,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

python_archive = PYZ(analysis.pure)

executable = EXE(
    python_archive,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="ssh-sentinel",
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
