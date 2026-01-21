import re

# Read the workflow file
with open('.github/workflows/build-agent.yml', 'r', encoding='utf-8') as f:
    content = f.read()

print(f"Original file length: {len(content)}")

# New release step - split approach: create release first, then upload files one by one
new_release_step = '''env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          VERSION="${{ github.ref_name }}"
          REPO="${{ github.repository }}"
          echo "=========================================="
          echo "Creating release $VERSION for $REPO"
          echo "=========================================="
          
          # Step 1: Delete existing release if it exists
          if gh release view "$VERSION" --repo "$REPO" > /dev/null 2>&1; then
            echo "Release $VERSION already exists, deleting..."
            gh release delete "$VERSION" --repo "$REPO" --yes || true
            sleep 5
          fi
          
          # Step 2: Create empty release first (small API call)
          echo ""
          echo "Step 1: Creating empty release..."
          for attempt in 1 2 3; do
            if gh release create "$VERSION" \\
              --repo "$REPO" \\
              --title "Jarwis Agent $VERSION" \\
              --notes "## Jarwis Security Agent $VERSION

### Installation

**Windows:** Download \`JarwisAgentSetup-GUI.exe\` (recommended) or \`.msi\` for enterprise deployment.

**macOS:** Download the \`.pkg\` or \`.dmg\` for your architecture (Intel or Apple Silicon).

**Linux:** Download \`.deb\` (Debian/Ubuntu) or \`.rpm\` (RHEL/CentOS).

See [INSTALLATION.md](https://github.com/$REPO/blob/main/installer/INSTALLATION.md) for detailed instructions.
"; then
              echo "Empty release created successfully!"
              break
            fi
            echo "Attempt $attempt failed, waiting 10 seconds..."
            sleep 10
          done
          
          # Step 3: Upload files one by one with delays
          echo ""
          echo "Step 2: Uploading assets one by one..."
          
          upload_file() {
            local file="$1"
            local filename=$(basename "$file")
            echo ""
            echo "Uploading: $filename ($(du -h "$file" | cut -f1))"
            
            for attempt in 1 2 3 4 5; do
              if gh release upload "$VERSION" "$file" --repo "$REPO" --clobber; then
                echo "  Uploaded successfully!"
                return 0
              fi
              delay=$((attempt * 15))
              echo "  Attempt $attempt failed, waiting ${delay}s..."
              sleep $delay
            done
            echo "  WARNING: Failed to upload $filename after 5 attempts"
            return 1
          }
          
          # Upload Windows artifacts
          echo ""
          echo "--- Windows Artifacts ---"
          for f in artifacts/windows-installer/*; do
            [ -f "$f" ] && upload_file "$f"
            sleep 3
          done
          
          # Upload macOS Intel artifacts
          echo ""
          echo "--- macOS Intel Artifacts ---"
          for f in artifacts/macos-intel-installer/*; do
            [ -f "$f" ] && upload_file "$f"
            sleep 3
          done
          
          # Upload macOS ARM artifacts
          echo ""
          echo "--- macOS ARM Artifacts ---"
          for f in artifacts/macos-arm64-installer/*; do
            [ -f "$f" ] && upload_file "$f"
            sleep 3
          done
          
          # Upload Linux artifacts
          echo ""
          echo "--- Linux Artifacts ---"
          for f in artifacts/linux-installer/*; do
            [ -f "$f" ] && upload_file "$f"
            sleep 3
          done
          
          echo ""
          echo "=========================================="
          echo "Release $VERSION completed!"
          echo "=========================================="
          gh release view "$VERSION" --repo "$REPO"'''

# Find and replace the old release step
# Pattern matches from "env:" after "Create GitHub Release" to "exit 1" at the end
old_pattern = r'env:\s+GITHUB_TOKEN: \$\{\{ secrets\.GITHUB_TOKEN \}\}\s+run: \|[\s\S]*?exit 1$'

if re.search(old_pattern, content, re.MULTILINE):
    print("Found the old release step pattern")
    new_content = re.sub(old_pattern, new_release_step, content, flags=re.MULTILINE)
    print(f"New file length: {len(new_content)}")
    
    # Write the new content
    with open('.github/workflows/build-agent.yml', 'w', encoding='utf-8', newline='\n') as f:
        f.write(new_content)
    print("File updated successfully!")
else:
    print("Pattern not found - showing context")
    idx = content.find('GITHUB_TOKEN')
    print(content[idx:idx+500])
