#!/usr/bin/env python3
"""Fix corrupted JSX patterns in frontend files."""

import re
import os
from pathlib import Path

def fix_double_quote_patterns(content):
    """Fix patterns like className="...""... where closing quote is corrupted."""
    
    # Pattern 1: Fix className="value""anotherClass -> className="value" className="anotherClass"
    # This is where the corruption removed closing bracket and className=
    
    # Pattern: "...""text-... => "`}>\n<ClassName className={`...${isDarkMode ? "text-...
    # Example: "text-gray-400 mr-3""flex items-start">
    # Should be: "text-gray-400 mr-3">✓</span><span>...</span></li>\n<li className="flex items-start">
    
    # Most common pattern: className="value""nextValue" - missing `}>\n<tag className={`
    # Let's fix these patterns
    
    lines = content.split('\n')
    fixed_lines = []
    i = 0
    
    while i < len(lines):
        line = lines[i]
        fixed_line = line
        
        # Fix pattern: "text-gray-400 mr-3""flex items-start">
        # Should add closing tags and proper structure
        fixed_line = re.sub(
            r'"text-gray-400 mr-3""flex items-start">',
            '">•</span><span>Item</span></li>\n              <li className="flex items-start">',
            fixed_line
        )
        
        # Fix pattern: ""text-xl - should be closing and new tag
        fixed_line = re.sub(
            r'""text-xl',
            '">\n          </div>\n\n          <div className="bg-gray-800 rounded-lg p-4 sm:p-6">\n            <h2 className="text-xl',
            fixed_line
        )
        
        # Fix pattern: "text-gray-200 text-sm sm:text-base""bg-... 
        fixed_line = re.sub(
            r'"text-gray-200 text-sm sm:text-base""bg-',
            '">\n            </p>\n          </div>\n\n          <div className="bg-',
            fixed_line
        )
        
        # Fix pattern: ""border-t border
        fixed_line = re.sub(
            r'""border-t border',
            '">\n            </p>\n          </div>\n\n          <div className="border-t border',
            fixed_line
        )
        
        # Fix pattern: "value""space-y-
        fixed_line = re.sub(
            r'""space-y-',
            '">\n              </div>\n              <div className="space-y-',
            fixed_line
        )
        
        # Fix pattern: "grid grid-cols - wrong double quote pattern
        fixed_line = re.sub(
            r'""grid grid-cols',
            '">\n          </div>\n        </div>\n\n        <div className="grid grid-cols',
            fixed_line
        )
        
        fixed_lines.append(fixed_line)
        i += 1
    
    return '\n'.join(fixed_lines)


def fix_jsx_files():
    """Main function to fix all JSX files."""
    
    frontend_path = Path(r"D:\jarwis-ai-pentest\jarwisfrontend\src")
    
    # Find files with issues
    problematic_files = [
        frontend_path / "pages/Privacy.jsx",
        frontend_path / "pages/RefundReturnPolicy.jsx",
        frontend_path / "pages/dashboard/JarwisChatbot.jsx",
        frontend_path / "pages/dashboard/JarwisDashboard.jsx",
        frontend_path / "pages/dashboard/Reports.jsx",
        frontend_path / "components/settings/SettingsPanel.jsx",
    ]
    
    for file_path in problematic_files:
        if file_path.exists():
            print(f"Processing: {file_path}")
            content = file_path.read_text(encoding='utf-8')
            
            # Fix the double quote patterns
            original_content = content
            
            # Fix all corrupted "" patterns
            content = re.sub(r'""([a-z])', r'" className="\1', content)
            
            if content != original_content:
                # Don't actually write - just report
                print(f"  Would fix patterns in {file_path}")
            else:
                print(f"  No simple fixes found in {file_path}")


if __name__ == "__main__":
    fix_jsx_files()
