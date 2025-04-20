#!/bin/bash

# Output directory
OUTDIR="bin"
mkdir -p $OUTDIR

# List of target platforms
PLATFORMS=(
    "windows/amd64"
    "linux/amd64"
    "darwin/amd64"
    "darwin/arm64"
)

# Name of your application
APP_NAME="verify_rsa"

# Build for each platform
for PLATFORM in "${PLATFORMS[@]}"; do
    OS=$(echo $PLATFORM | cut -d'/' -f1)
    ARCH=$(echo $PLATFORM | cut -d'/' -f2)
    OUTPUT="${OUTDIR}/${APP_NAME}_${OS}_${ARCH}"
    
    if [ $OS = "windows" ]; then
        OUTPUT="${OUTPUT}.exe"
    fi

    echo "Building for $OS/$ARCH..."
    env GOOS=$OS GOARCH=$ARCH go build -ldflags="-s -w" -o $OUTPUT .
    
    # Optional: Compress with upx (install upx first)
    # if command -v upx &> /dev/null; then
    #     upx $OUTPUT
    # fi
done

echo "Build complete. Binaries are in the $OUTDIR directory."