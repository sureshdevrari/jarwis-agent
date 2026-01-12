#!/usr/bin/env python3
"""Update __init__.py files to export scanner classes."""

from pathlib import Path
import re

ATTACKS_DIR = Path(__file__).parent.parent / 'attacks'

def find_classes(filepath):
    content = filepath.read_text(encoding='utf-8')
    return re.findall(r'^class\s+(\w+)\s*[:\(]', content, re.MULTILINE)

def update_init(folder, desc):
    init_file = folder / '__init__.py'
    imports, exports = [], []
    for py_file in sorted(folder.glob('*.py')):
        if py_file.name.startswith('_'): continue
        classes = find_classes(py_file)
        if classes:
            imports.append(f'from .{py_file.stem} import {", ".join(classes)}')
            exports.extend(classes)
    if imports:
        content = f'"""\n{desc}\n"""\n\n' + '\n'.join(imports) + '\n\n__all__ = ' + str(exports) + '\n'
        init_file.write_text(content, encoding='utf-8')
        print(f'  Updated: {folder.name}')

print("=" * 60)
print("UPDATING __init__.py FILES")
print("=" * 60)

# Web OWASP categories
print("\n📁 Web OWASP categories:")
for d in sorted((ATTACKS_DIR / 'web').iterdir()):
    if d.is_dir() and d.name.startswith('a') and not d.name.startswith('_'):
        update_init(d, f'OWASP {d.name.upper()}')
    elif d.is_dir() and d.name in ['api', 'file_upload', 'other']:
        update_init(d, d.name.title())

# Cloud providers
print("\n☁️ Cloud providers:")
for d in sorted((ATTACKS_DIR / 'cloud').iterdir()):
    if d.is_dir() and not d.name.startswith('_'):
        update_init(d, f'Cloud {d.name.upper()}')

# Mobile phases
print("\n📱 Mobile phases:")
for d in sorted((ATTACKS_DIR / 'mobile').iterdir()):
    if d.is_dir() and not d.name.startswith('_'):
        if d.name == 'platform':
            for p in d.iterdir():
                if p.is_dir() and not p.name.startswith('_'):
                    update_init(p, f'Mobile {p.name.upper()}')
        else:
            update_init(d, f'Mobile {d.name.title()}')

# SAST functions
print("\n🔍 SAST functions:")
for d in sorted((ATTACKS_DIR / 'sast').iterdir()):
    if d.is_dir() and not d.name.startswith('_'):
        update_init(d, f'SAST {d.name.title()}')

print("\n" + "=" * 60)
print("COMPLETE")
print("=" * 60)
