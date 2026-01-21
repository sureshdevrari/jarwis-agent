#!/usr/bin/env python3
"""
Icon Generator for Jarwis Agent Installer

Converts PNG logos to platform-specific icon formats:
- Windows: .ico (multiple sizes: 16, 32, 48, 64, 128, 256)
- macOS: .icns (multiple sizes: 16, 32, 64, 128, 256, 512, 1024)

Requirements:
    pip install Pillow

Usage:
    python create_icons.py
"""

import os
import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("ERROR: Pillow is required. Install with: pip install Pillow")
    sys.exit(1)


def create_windows_ico(source_png: Path, output_ico: Path):
    """Create Windows .ico file with multiple sizes."""
    sizes = [16, 24, 32, 48, 64, 128, 256]
    
    img = Image.open(source_png)
    
    # Ensure RGBA mode for transparency
    if img.mode != 'RGBA':
        img = img.convert('RGBA')
    
    # Create resized versions
    icons = []
    for size in sizes:
        resized = img.resize((size, size), Image.Resampling.LANCZOS)
        icons.append(resized)
    
    # Save as ICO
    icons[0].save(
        output_ico,
        format='ICO',
        sizes=[(s, s) for s in sizes],
        append_images=icons[1:]
    )
    print(f"✓ Created Windows icon: {output_ico}")


def create_macos_icns(source_png: Path, output_icns: Path):
    """Create macOS .icns file with multiple sizes."""
    # macOS iconutil expects specific sizes in iconset folder
    sizes = {
        'icon_16x16.png': 16,
        'icon_16x16@2x.png': 32,
        'icon_32x32.png': 32,
        'icon_32x32@2x.png': 64,
        'icon_64x64.png': 64,
        'icon_64x64@2x.png': 128,
        'icon_128x128.png': 128,
        'icon_128x128@2x.png': 256,
        'icon_256x256.png': 256,
        'icon_256x256@2x.png': 512,
        'icon_512x512.png': 512,
        'icon_512x512@2x.png': 1024,
    }
    
    img = Image.open(source_png)
    if img.mode != 'RGBA':
        img = img.convert('RGBA')
    
    # Create iconset directory
    iconset_dir = output_icns.parent / f"{output_icns.stem}.iconset"
    iconset_dir.mkdir(parents=True, exist_ok=True)
    
    for filename, size in sizes.items():
        resized = img.resize((size, size), Image.Resampling.LANCZOS)
        resized.save(iconset_dir / filename, format='PNG')
    
    print(f"✓ Created macOS iconset: {iconset_dir}")
    print(f"  Run on macOS: iconutil -c icns {iconset_dir}")
    
    # If on macOS, try to convert
    if sys.platform == 'darwin':
        import subprocess
        try:
            subprocess.run(['iconutil', '-c', 'icns', str(iconset_dir)], check=True)
            print(f"✓ Created macOS icon: {output_icns}")
        except Exception as e:
            print(f"  Note: iconutil conversion failed: {e}")


def create_installer_bitmaps(source_png: Path, output_dir: Path):
    """Create WiX installer bitmap images."""
    img = Image.open(source_png)
    
    # Ensure RGB mode for BMP (no alpha)
    if img.mode == 'RGBA':
        # Create white background
        background = Image.new('RGB', img.size, (255, 255, 255))
        background.paste(img, mask=img.split()[3])
        img = background
    elif img.mode != 'RGB':
        img = img.convert('RGB')
    
    # WiX Banner: 493x58 pixels (top banner on wizard pages)
    banner = Image.new('RGB', (493, 58), (24, 32, 56))  # Dark blue background
    logo_height = 50
    logo_width = int(img.width * (logo_height / img.height))
    logo_small = img.resize((logo_width, logo_height), Image.Resampling.LANCZOS)
    banner.paste(logo_small, (10, 4))
    
    # Add gradient effect
    for x in range(493):
        for y in range(58):
            r, g, b = banner.getpixel((x, y))
            # Subtle gradient from left to right
            factor = 1 + (x / 493) * 0.3
            banner.putpixel((x, y), (min(int(r * factor), 255), min(int(g * factor), 255), min(int(b * factor), 255)))
    
    banner.save(output_dir / 'banner.bmp', format='BMP')
    print(f"✓ Created WiX banner: {output_dir / 'banner.bmp'}")
    
    # WiX Dialog: 493x312 pixels (welcome/completion page background)
    dialog = Image.new('RGB', (493, 312), (255, 255, 255))
    
    # Left side: Dark blue bar with logo
    for x in range(164):
        for y in range(312):
            # Gradient from dark blue to lighter blue
            gradient = int(24 + (x / 164) * 30)
            dialog.putpixel((x, y), (gradient, gradient + 8, gradient + 32))
    
    # Place logo in left panel
    logo_size = 120
    logo_resized = img.resize((logo_size, logo_size), Image.Resampling.LANCZOS)
    # Center in left panel
    x_pos = (164 - logo_size) // 2
    y_pos = (312 - logo_size) // 2
    
    # Paste with handling for non-RGBA
    if logo_resized.mode == 'RGBA':
        dialog.paste(logo_resized, (x_pos, y_pos), logo_resized)
    else:
        dialog.paste(logo_resized, (x_pos, y_pos))
    
    dialog.save(output_dir / 'dialog.bmp', format='BMP')
    print(f"✓ Created WiX dialog: {output_dir / 'dialog.bmp'}")


def create_inno_setup_images(source_png: Path, output_dir: Path):
    """Create Inno Setup wizard images."""
    img = Image.open(source_png)
    
    if img.mode == 'RGBA':
        background = Image.new('RGB', img.size, (255, 255, 255))
        background.paste(img, mask=img.split()[3])
        img = background
    elif img.mode != 'RGB':
        img = img.convert('RGB')
    
    # WizardImageFile: 164x314 pixels (left panel on large wizard pages)
    wizard_large = Image.new('RGB', (164, 314), (24, 32, 56))
    logo_size = 120
    logo_resized = img.resize((logo_size, logo_size), Image.Resampling.LANCZOS)
    x_pos = (164 - logo_size) // 2
    y_pos = 60
    wizard_large.paste(logo_resized, (x_pos, y_pos))
    wizard_large.save(output_dir / 'wizard_large.bmp', format='BMP')
    print(f"✓ Created Inno Setup wizard large: {output_dir / 'wizard_large.bmp'}")
    
    # WizardSmallImageFile: 55x55 pixels (top-right on small wizard pages)
    wizard_small = img.resize((55, 55), Image.Resampling.LANCZOS)
    wizard_small.save(output_dir / 'wizard_small.bmp', format='BMP')
    print(f"✓ Created Inno Setup wizard small: {output_dir / 'wizard_small.bmp'}")


def main():
    # Paths
    project_root = Path(__file__).parent.parent.parent
    output_dir = Path(__file__).parent
    
    # Try multiple possible logo locations
    possible_logos = [
        project_root / 'assets' / 'logos' / 'png' / 'PNG-01.png',
        output_dir / 'jarwis-logo.png',
        output_dir / 'jarwis-icon.png',
        output_dir.parent / 'jarwis-logo.png',
    ]
    
    source_logo = None
    for logo_path in possible_logos:
        if logo_path.exists():
            source_logo = logo_path
            break
    
    if source_logo is None:
        print(f"ERROR: Source logo not found. Searched:")
        for p in possible_logos:
            print(f"  - {p}")
        print(f"\nProject root: {project_root}")
        print(f"Output dir: {output_dir}")
        print(f"\nExisting files in {output_dir}:")
        for f in output_dir.iterdir():
            print(f"  - {f.name}")
        sys.exit(1)
    
    print(f"Source logo: {source_logo}")
    print(f"Output directory: {output_dir}")
    print()
    
    # Create directories
    (output_dir / 'icons').mkdir(exist_ok=True)
    (output_dir / 'bitmaps').mkdir(exist_ok=True)
    
    # Generate icons
    create_windows_ico(source_logo, output_dir / 'icons' / 'jarwis-agent.ico')
    create_macos_icns(source_logo, output_dir / 'icons' / 'jarwis-agent.icns')
    
    # Generate installer bitmaps
    create_installer_bitmaps(source_logo, output_dir / 'bitmaps')
    create_inno_setup_images(source_logo, output_dir / 'bitmaps')
    
    print()
    print("✓ All assets created successfully!")
    print()
    print("Next steps:")
    print("  1. Copy icons/jarwis-agent.ico to assets/logos/")
    print("  2. Copy icons/jarwis-agent.icns to assets/logos/ (or convert iconset on macOS)")
    print("  3. Copy bitmaps/*.bmp to installer build directory")


if __name__ == '__main__':
    main()
