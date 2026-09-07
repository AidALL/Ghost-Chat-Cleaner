#!/usr/bin/env bash
set -euo pipefail

# Package an existing native release binary; never build or launch it here.
if [[ $# -gt 3 ]]; then
  echo "Usage: $0 [BINARY [OUTPUT_DIR [ARCHITECTURE]]]" >&2
  exit 2
fi
PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="${1:-$PROJECT_ROOT/target/release/ghost-chat-cleaner}"
OUTPUT_DIR="${2:-$PROJECT_ROOT/dist}"
ARCHITECTURE="${3:-$(uname -m)}"

if [[ ! -f "$BINARY" || ! -x "$BINARY" ]]; then
  echo "Release binary is missing or not executable: $BINARY. Run cargo build --locked --release first." >&2
  exit 1
fi
case "$ARCHITECTURE" in
  arm64|aarch64) ARCHITECTURE=aarch64 ;;
  x86_64) ;;
  *) echo "Unsupported architecture: $ARCHITECTURE" >&2; exit 2 ;;
esac
command -v ditto >/dev/null || { echo "macOS ditto is required." >&2; exit 1; }
FONT_NOTICES="$PROJECT_ROOT/assets/fonts/nanumgothic"
for DOCUMENT in OFL.txt PROVENANCE.md; do
  [[ -f "$FONT_NOTICES/$DOCUMENT" ]] || { echo "Required font notice missing: $FONT_NOTICES/$DOCUMENT" >&2; exit 1; }
done
VERSION="$(awk -F '\"' '/^version = \"/ { print $2; exit }' "$PROJECT_ROOT/Cargo.toml")"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Expected a numeric release version in Cargo.toml." >&2; exit 1; }
mkdir -p -- "$OUTPUT_DIR"
OUTPUT_DIR="$(cd -- "$OUTPUT_DIR" && pwd)"
ARCHIVE="$OUTPUT_DIR/ghost-chat-cleaner-$VERSION-macos-$ARCHITECTURE.app.zip"
[[ ! -e "$ARCHIVE" ]] || { echo "Archive already exists: $ARCHIVE" >&2; exit 1; }
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/ghost-chat-cleaner.XXXXXX")"
trap 'rm -rf -- "$STAGE"' EXIT
APP="$STAGE/Ghost Chat Cleaner.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp -- "$BINARY" "$APP/Contents/MacOS/ghost-chat-cleaner"
chmod 755 "$APP/Contents/MacOS/ghost-chat-cleaner"
cp -- "$PROJECT_ROOT/README.md" "$PROJECT_ROOT/README.ko.md" "$PROJECT_ROOT/LICENSE" "$APP/Contents/Resources/"
python3 "$PROJECT_ROOT/scripts/generate-notices.py" --target "$ARCHITECTURE-apple-darwin" --output "$APP/Contents/Resources/THIRD_PARTY_NOTICES.txt"
mkdir -p "$APP/Contents/Resources/licenses/nanumgothic"
cp -- "$FONT_NOTICES/OFL.txt" "$FONT_NOTICES/PROVENANCE.md" "$APP/Contents/Resources/licenses/nanumgothic/"
cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Ghost Chat Cleaner</string>
  <key>CFBundleDisplayName</key><string>Ghost Chat Cleaner</string>
  <key>CFBundleIdentifier</key><string>local.ghostalice.ghost-chat-cleaner</string>
  <key>CFBundleExecutable</key><string>ghost-chat-cleaner</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
EOF
ditto -c -k --sequesterRsrc --keepParent "$APP" "$STAGE/package.zip"
mv -- "$STAGE/package.zip" "$ARCHIVE"
echo "$ARCHIVE"
