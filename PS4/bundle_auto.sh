#!/bin/bash
# bundle_auto.sh - Bundle inject_auto.js with lapse_binloader.js
# Creates a single JS file that auto-runs jailbreak + binloader

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INJECT_AUTO="$SCRIPT_DIR/inject_auto.js"
PAYLOAD="$SCRIPT_DIR/payloads/lapse_binloader.js"
OUTPUT="$SCRIPT_DIR/inject_auto_bundle.js"

# Check files exist
if [ ! -f "$INJECT_AUTO" ]; then
    echo "ERROR: inject_auto.js not found at $INJECT_AUTO"
    exit 1
fi

if [ ! -f "$PAYLOAD" ]; then
    echo "ERROR: lapse_binloader.js not found at $PAYLOAD"
    exit 1
fi

echo "Bundling inject_auto.js + lapse_binloader.js..."

# Create temp file for the bundled output
TEMP_FILE=$(mktemp)

# Read inject_auto.js up to the marker
sed -n '1,/LAPSE_BINLOADER_PAYLOAD_START/p' "$INJECT_AUTO" > "$TEMP_FILE"

# Append the payload
cat "$PAYLOAD" >> "$TEMP_FILE"

# Append the rest of inject_auto.js after the end marker
sed -n '/LAPSE_BINLOADER_PAYLOAD_END/,$p' "$INJECT_AUTO" >> "$TEMP_FILE"

# Move to output
mv "$TEMP_FILE" "$OUTPUT"

# Get file sizes
INJECT_SIZE=$(wc -c < "$INJECT_AUTO")
PAYLOAD_SIZE=$(wc -c < "$PAYLOAD")
OUTPUT_SIZE=$(wc -c < "$OUTPUT")

echo "Done!"
echo "  inject_auto.js:      $INJECT_SIZE bytes"
echo "  lapse_binloader.js:  $PAYLOAD_SIZE bytes"
echo "  Output:              $OUTPUT_SIZE bytes"
echo ""
echo "Output: $OUTPUT"
