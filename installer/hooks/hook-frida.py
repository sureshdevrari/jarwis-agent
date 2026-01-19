# -*- coding: utf-8 -*-
"""
PyInstaller hook for Frida

Ensures Frida native components are properly bundled.
"""

from PyInstaller.utils.hooks import collect_all, collect_dynamic_libs

# Collect all Frida components
datas, binaries, hiddenimports = collect_all('frida')

# Frida has native libraries
binaries += collect_dynamic_libs('frida')
binaries += collect_dynamic_libs('_frida')

# Hidden imports
hiddenimports += [
    'frida',
    'frida.core',
    '_frida',
]
