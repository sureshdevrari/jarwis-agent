# Icon and Bitmap Generator for Jarwis Agent Installer
# Generates .ico, .icns, and installer bitmaps from PNG logo

from PIL import Image
import os
import struct
import sys

def create_windows_ico(source_png, output_ico):
    """Create Windows .ico file with multiple sizes"""
    img = Image.open(source_png)
    
    # Convert to RGBA if necessary
    if img.mode != 'RGBA':
        img = img.convert('RGBA')
    
    # Standard Windows icon sizes
    sizes = [16, 24, 32, 48, 64, 128, 256]
    
    # Create resized images
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
    print(f"Created: {output_ico}")

def create_macos_icns(source_png, output_icns):
    """Create macOS .icns file"""
    img = Image.open(source_png)
    
    if img.mode != 'RGBA':
        img = img.convert('RGBA')
    
    # macOS icon sizes (standard iconset)
    sizes = {
        'icon_16x16.png': 16,
        'icon_16x16@2x.png': 32,
        'icon_32x32.png': 32,
        'icon_32x32@2x.png': 64,
        'icon_128x128.png': 128,
        'icon_128x128@2x.png': 256,
        'icon_256x256.png': 256,
        'icon_256x256@2x.png': 512,
        'icon_512x512.png': 512,
        'icon_512x512@2x.png': 1024,
    }
    
    # Create iconset directory
    iconset_dir = output_icns.replace('.icns', '.iconset')
    os.makedirs(iconset_dir, exist_ok=True)
    
    for filename, size in sizes.items():
        resized = img.resize((size, size), Image.Resampling.LANCZOS)
        resized.save(os.path.join(iconset_dir, filename), 'PNG')
    
    print(f"Created iconset: {iconset_dir}")
    print("Run 'iconutil -c icns {iconset_dir}' on macOS to create .icns")

def create_installer_bitmaps(source_png, output_dir):
    """Create installer bitmaps for Inno Setup and WiX"""
    img = Image.open(source_png)
    
    if img.mode != 'RGBA':
        img = img.convert('RGBA')
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Inno Setup banner (164x314 or similar)
    banner_size = (164, 314)
    banner = Image.new('RGB', banner_size, (255, 255, 255))
    logo_size = min(banner_size[0] - 20, 140)
    logo = img.resize((logo_size, logo_size), Image.Resampling.LANCZOS)
    x = (banner_size[0] - logo_size) // 2
    y = 30
    banner.paste(logo, (x, y), logo if logo.mode == 'RGBA' else None)
    banner.save(os.path.join(output_dir, 'banner.bmp'), 'BMP')
    print(f"Created: {os.path.join(output_dir, 'banner.bmp')}")
    
    # Inno Setup wizard dialog (164x314)
    dialog = Image.new('RGB', (164, 314), (255, 255, 255))
    logo = img.resize((140, 140), Image.Resampling.LANCZOS)
    dialog.paste(logo, (12, 30), logo if logo.mode == 'RGBA' else None)
    dialog.save(os.path.join(output_dir, 'dialog.bmp'), 'BMP')
    print(f"Created: {os.path.join(output_dir, 'dialog.bmp')}")
    
    # WiX banner (493x58)
    wix_banner = Image.new('RGB', (493, 58), (255, 255, 255))
    logo = img.resize((50, 50), Image.Resampling.LANCZOS)
    wix_banner.paste(logo, (10, 4), logo if logo.mode == 'RGBA' else None)
    wix_banner.save(os.path.join(output_dir, 'wix_banner.bmp'), 'BMP')
    print(f"Created: {os.path.join(output_dir, 'wix_banner.bmp')}")
    
    # WiX dialog (493x312)
    wix_dialog = Image.new('RGB', (493, 312), (255, 255, 255))
    logo = img.resize((200, 200), Image.Resampling.LANCZOS)
    wix_dialog.paste(logo, (146, 50), logo if logo.mode == 'RGBA' else None)
    wix_dialog.save(os.path.join(output_dir, 'wix_dialog.bmp'), 'BMP')
    print(f"Created: {os.path.join(output_dir, 'wix_dialog.bmp')}")
    
    # Large wizard image (164x314)
    wizard_large = Image.new('RGB', (164, 314), (41, 128, 185))  # Jarwis blue
    logo = img.resize((140, 140), Image.Resampling.LANCZOS)
    wizard_large.paste(logo, (12, 87), logo if logo.mode == 'RGBA' else None)
    wizard_large.save(os.path.join(output_dir, 'wizard_large.bmp'), 'BMP')
    print(f"Created: {os.path.join(output_dir, 'wizard_large.bmp')}")
    
    # Small wizard image (55x58)
    wizard_small = Image.new('RGB', (55, 58), (255, 255, 255))
    logo = img.resize((48, 48), Image.Resampling.LANCZOS)
    wizard_small.paste(logo, (3, 5), logo if logo.mode == 'RGBA' else None)
    wizard_small.save(os.path.join(output_dir, 'wizard_small.bmp'), 'BMP')
    print(f"Created: {os.path.join(output_dir, 'wizard_small.bmp')}")

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    assets_dir = os.path.dirname(script_dir) if 'assets' in script_dir else script_dir
    
    # Find the source logo
    logo_paths = [
        os.path.join(assets_dir, '..', 'assets', 'logos', 'PNG-01.png'),
        os.path.join(assets_dir, '..', '..', 'assets', 'logos', 'PNG-01.png'),
        os.path.join(script_dir, 'PNG-01.png'),
    ]
    
    source_png = None
    for path in logo_paths:
        if os.path.exists(path):
            source_png = path
            break
    
    if not source_png:
        print("ERROR: Could not find PNG-01.png logo")
        print("Searched in:", logo_paths)
        sys.exit(1)
    
    print(f"Using source logo: {source_png}")
    
    # Output directories
    icons_dir = os.path.join(script_dir, 'icons')
    bitmaps_dir = os.path.join(script_dir, 'bitmaps')
    
    os.makedirs(icons_dir, exist_ok=True)
    os.makedirs(bitmaps_dir, exist_ok=True)
    
    # Generate all assets
    print("\n=== Generating Windows Icon ===")
    create_windows_ico(source_png, os.path.join(icons_dir, 'jarwis-agent.ico'))
    
    print("\n=== Generating macOS Iconset ===")
    create_macos_icns(source_png, os.path.join(icons_dir, 'jarwis-agent.icns'))
    
    print("\n=== Generating Installer Bitmaps ===")
    create_installer_bitmaps(source_png, bitmaps_dir)
    
    print("\n=== All assets generated successfully! ===")

if __name__ == '__main__':
    main()
