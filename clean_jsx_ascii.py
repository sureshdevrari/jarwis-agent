#!/usr/bin/env python3
"""Clean JSX files to use only ASCII-safe characters."""

import os
import re

def clean_to_ascii(content):
    """Replace non-ASCII characters with ASCII equivalents."""
    
    # Replace common problematic patterns with ASCII
    replacements = {
        # Smart quotes to regular quotes
        '\u201c': '"',   # left double quote
        '\u201d': '"',   # right double quote
        '\u2018': "'",   # left single quote
        '\u2019': "'",   # right single quote
        # Dashes
        '\u2013': '-',   # en-dash
        '\u2014': '-',   # em-dash
        # Arrows - replace with text
        '\u2190': '<-',  # left arrow
        '\u2192': '->',  # right arrow
        '\u2191': '^',   # up arrow
        '\u2193': 'v',   # down arrow
        '\u21d0': '<=',  # left double arrow
        '\u21d2': '=>',  # right double arrow
        # Checkmarks and X
        '\u2713': '*',   # check mark
        '\u2714': '*',   # heavy check mark
        '\u2715': 'x',   # multiplication x
        '\u2716': 'x',   # heavy multiplication x
        '\u2717': 'x',   # ballot x
        '\u2718': 'x',   # heavy ballot x
        '\u2705': '*',   # white heavy check mark emoji
        '\u274c': 'x',   # cross mark emoji
        '\u274e': 'x',   # cross mark
        # Bullets
        '\u2022': '*',   # bullet
        '\u2023': '>',   # triangular bullet
        '\u2043': '-',   # hyphen bullet
        '\u25cf': '*',   # black circle
        '\u25cb': 'o',   # white circle
        '\u25a0': '#',   # black square
        '\u25a1': '[]',  # white square
        # Ellipsis
        '\u2026': '...',
        # Spaces
        '\u00a0': ' ',   # non-breaking space
        '\u202f': ' ',   # narrow no-break space
        '\u2003': ' ',   # em space
        '\u2002': ' ',   # en space
        # Trademark/copyright
        '\u2122': '(TM)',
        '\u00a9': '(c)',
        '\u00ae': '(R)',
        # Math symbols
        '\u00d7': 'x',   # multiplication
        '\u00f7': '/',   # division
        '\u2260': '!=',  # not equal
        '\u2264': '<=',  # less than or equal
        '\u2265': '>=',  # greater than or equal
        # Stars
        '\u2605': '*',   # black star
        '\u2606': '*',   # white star
        '\u2b50': '*',   # star emoji
        # Hearts
        '\u2764': '<3',  # heart
        '\u2665': '<3',  # black heart suit
        # Sparkles
        '\u2728': '*',   # sparkles
        '\u2b55': 'o',   # heavy large circle
    }
    
    for old, new in replacements.items():
        content = content.replace(old, new)
    
    # Remove emojis (most are in ranges U+1F300-U+1FAFF and U+2600-U+27BF)
    emoji_pattern = re.compile(
        '['
        '\U0001F300-\U0001F9FF'  # Miscellaneous Symbols and Pictographs + Emoticons
        '\U0001FA00-\U0001FAFF'  # Extended-A symbols
        '\U00002600-\U000027BF'  # Misc symbols (sun, cloud, etc)
        '\U0001F600-\U0001F64F'  # Emoticons
        '\U0001F680-\U0001F6FF'  # Transport & Map symbols
        '\U0001F1E0-\U0001F1FF'  # Flags
        '\U0001F900-\U0001F9FF'  # Supplemental Symbols
        '\U0001FA70-\U0001FAFF'  # Symbols Extended-A
        '\U00002300-\U000023FF'  # Misc Technical
        '\U00002B00-\U00002BFF'  # Misc Symbols and Arrows
        ']+',
        flags=re.UNICODE
    )
    content = emoji_pattern.sub('', content)
    
    # Fix corrupted encoding patterns (Mojibake from UTF-8 read as Latin-1)
    mojibake_patterns = [
        (r'\u00c3\u00a2', ''),          # corrupted a
        (r'\u00c3\u0082', ''),          # corrupted A
        (r'\u00e2\u0080\u0099', "'"),   # corrupted apostrophe
        (r'\u00e2\u0080\u009c', '"'),   # corrupted left quote
        (r'\u00e2\u0080\u009d', '"'),   # corrupted right quote
        (r'\u00e2\u0080\u0093', '-'),   # corrupted en-dash
        (r'\u00e2\u0080\u0094', '-'),   # corrupted em-dash
        (r'\u00e2\u0080\u00a6', '...'), # corrupted ellipsis
        (r'\u00c2\u00a0', ' '),         # corrupted nbsp
        # Common corruption from the scripts
        (r'Ã¢', ''),
        (r'â', "'"),
        (r'€', ''),
        (r'™', '(TM)'),
        (r'œ', ''),
        (r'Â', ''),
        (r'ðŸ', ''),   # corrupted emoji prefix
        (r'ï¸', ''),   # corrupted emoji suffix
    ]
    
    for pattern, replacement in mojibake_patterns:
        content = re.sub(pattern, replacement, content)
    
    return content


def fix_broken_jsx_syntax(content):
    """Fix common broken JSX patterns from encoding corruption."""
    
    # Pattern: className="value""anotherValue" -> className="value">
    # This happens when encoding corruption removes closing tags
    content = re.sub(r'=""([a-z])', r'">\n', content)
    
    # Pattern: "value""space-y -> "value">\n<div className="space-y
    content = re.sub(r'""(space-y|grid|flex|bg-|text-|border-)', r'">\n', content)
    
    return content


def main():
    """Main function to clean all JSX/JS files."""
    
    jsx_dir = r"D:\jarwis-ai-pentest\jarwisfrontend\src"
    fixed_count = 0
    
    for root, dirs, files in os.walk(jsx_dir):
        # Skip node_modules
        if 'node_modules' in root:
            continue
        
        for filename in files:
            if filename.endswith(('.jsx', '.js')):
                filepath = os.path.join(root, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    cleaned = clean_to_ascii(content)
                    cleaned = fix_broken_jsx_syntax(cleaned)
                    
                    if cleaned != content:
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write(cleaned)
                        print(f"Cleaned: {filename}")
                        fixed_count += 1
                        
                except Exception as e:
                    print(f"Error in {filename}: {e}")
    
    print(f"\nTotal files cleaned: {fixed_count}")


if __name__ == "__main__":
    main()
