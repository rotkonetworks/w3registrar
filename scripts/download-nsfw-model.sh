#!/bin/bash
#
# Downloads the NSFW detection model for image verification
#

set -e

MODEL_DIR="models"
MODEL_FILE="$MODEL_DIR/nsfw-model.onnx"
NSFW_REPO="Fyko/nsfw"

# Check if model already exists
if [ -f "$MODEL_FILE" ]; then
    echo "✅ NSFW model already exists at $MODEL_FILE"
    exit 0
fi

echo "📥 Downloading NSFW detection model..."

# Create models directory if it doesn't exist
mkdir -p "$MODEL_DIR"

# Check if gh CLI is available
if command -v gh >/dev/null 2>&1; then
    echo "Using GitHub CLI to download model..."
    gh release download -R "$NSFW_REPO" --pattern "model.onnx" -O "$MODEL_FILE"
else
    echo "GitHub CLI not found. Downloading directly from GitHub releases..."
    # Get the latest release download URL
    DOWNLOAD_URL="https://github.com/$NSFW_REPO/releases/latest/download/model.onnx"
    curl -L "$DOWNLOAD_URL" -o "$MODEL_FILE"
fi

# Verify file exists and has reasonable size (should be ~10MB)
if [ ! -f "$MODEL_FILE" ]; then
    echo "❌ Failed to download model"
    exit 1
fi

FILE_SIZE=$(stat -f%z "$MODEL_FILE" 2>/dev/null || stat -c%s "$MODEL_FILE" 2>/dev/null)
if [ "$FILE_SIZE" -lt 1000000 ]; then
    echo "❌ Downloaded file seems too small ($FILE_SIZE bytes). Download may have failed."
    rm "$MODEL_FILE"
    exit 1
fi

echo "✅ NSFW model downloaded successfully ($FILE_SIZE bytes)"
echo "📍 Model location: $MODEL_FILE"
