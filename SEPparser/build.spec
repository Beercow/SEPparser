# -*- mode: python ; coding: utf-8 -*-


block_cipher = None


SEPparser_a = Analysis(['SEPparser.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False)

SEPparser_pyz = PYZ(SEPparser_a.pure, SEPparser_a.zipped_data, cipher=block_cipher)

SEPparser_a.datas += [('helpers\\sep.ico', './helpers\\sep.ico', 'DATA')]

SEPparser_exe = EXE(SEPparser_pyz,
    SEPparser_a.scripts,
    SEPparser_a.binaries,
    SEPparser_a.zipfiles,
    SEPparser_a.datas,
    [],
    name='SEPparser',
    icon='./helpers/sep.ico',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None )

SEPparser_GUI_a = Analysis(['SEPparser_GUI.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False)

SEPparser_GUI_pyz = PYZ(SEPparser_GUI_a.pure, SEPparser_GUI_a.zipped_data, cipher=block_cipher)

SEPparser_GUI_a.datas += [('helpers\\sep.ico', './helpers\\sep.ico', 'DATA')]

SEPparser_GUI_exe = EXE(SEPparser_GUI_pyz,
    SEPparser_GUI_a.scripts,
    SEPparser_GUI_a.binaries,
    SEPparser_GUI_a.zipfiles,
    SEPparser_GUI_a.datas,
    [],
    name='SEPparser_GUI',
    icon='./helpers/sep.ico',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None )