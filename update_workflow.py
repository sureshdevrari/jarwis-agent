import re

# Read the workflow file
with open('.github/workflows/build-agent.yml', 'r', encoding='utf-8') as f:
    content = f.read()

print(f"Original file length: {len(content)}")

# The old step uses softprops action - we need to replace it
# Find the line "uses: softprops/action-gh-release@v1" and everything after it until the step ends

# New release step using GitHub CLI with retry logic
new_release_step = '''env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          VERSION="${{ github.ref_name }}"
          REPO="${{ github.repository }}"
          echo "Creating release $VERSION for $REPO"
          
          # Check if release already exists and delete it
          if gh release view "$VERSION" --repo "$REPO" > /dev/null 2>&1; then
            echo "Release $VERSION already exists, deleting..."
            gh release delete "$VERSION" --repo "$REPO" --yes || true
            sleep 10
          fi
          
          # Collect all artifact files  
          shopt -s nullglob
          FILES=(artifacts/windows-installer/* artifacts/macos-intel-installer/* artifacts/macos-arm64-installer/* artifacts/linux-installer/*)
          echo "Files to upload: ${FILES[*]}"
          
          # Create release with retry logic (5 attempts with increasing delays)
          for i in 1 2 3 4 5; do
            echo "Attempt $i to create release..."
            if gh release create "$VERSION" \\
              --repo "$REPO" \\
              --title "Jarwis Agent $VERSION" \\
              --generate-notes \\
              "${FILES[@]}"; then
              echo "Release $VERSION created successfully!"
              exit 0
            fi
            DELAY=$((i * 30))
            echo "Attempt $i failed, waiting $DELAY seconds..."
            sleep $DELAY
          done
          echo "Failed to create release after 5 attempts"
          exit 1'''

# Pattern: Replace from "uses: softprops/action-gh-release@v1" to "GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}"
# This includes the "with:" block and all its contents

pattern = r'uses: softprops/action-gh-release@v1\s+with:[\s\S]*?env:\s+GITHUB_TOKEN: \$\{\{ secrets\.GITHUB_TOKEN \}\}'

if re.search(pattern, content):
    print("Found the softprops action block")
    new_content = re.sub(pattern, new_release_step, content)
    print(f"New file length: {len(new_content)}")
    
    # Write the new content
    with open('.github/workflows/build-agent.yml', 'w', encoding='utf-8', newline='\n') as f:
        f.write(new_content)
    print("File updated successfully!")
else:
    print("Pattern not found - trying alternative approach")
    # Show what we have around softprops
    idx = content.find('softprops')
    print(f"Context: {content[idx-50:idx+500]}")
