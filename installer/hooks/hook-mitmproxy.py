# -*- coding: utf-8 -*-
"""
PyInstaller hook for mitmproxy

Ensures mitmproxy and its dependencies are properly bundled.
"""

from PyInstaller.utils.hooks import collect_all, collect_data_files

# Collect all mitmproxy components
datas, binaries, hiddenimports = collect_all('mitmproxy')

# Additional data files
datas += collect_data_files('mitmproxy')
datas += collect_data_files('certifi')

# Hidden imports that might be missed
hiddenimports += [
    'mitmproxy',
    'mitmproxy.addons',
    'mitmproxy.options',
    'mitmproxy.proxy',
    'mitmproxy.tools',
    'mitmproxy.tools.dump',
    'mitmproxy.net',
    'mitmproxy.net.http',
    'mitmproxy.flow',
    'h2',
    'hpack',
    'hyperframe',
    'brotli',
    'zstandard',
    'kaitaistruct',
    'ldap3',
    'passlib',
    'pyasn1',
    'pyparsing',
    'ruamel',
    'ruamel.yaml',
    'sortedcontainers',
    'wsproto',
]
