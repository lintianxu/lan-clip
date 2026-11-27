#!/bin/sh
set -eu

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
APP_NAME="局域网传文字"
VERSION="2.0.0"
BUILD_DIR="$DIR/build"
APP_BUNDLE="$BUILD_DIR/${APP_NAME}.app"
ZIP_PATH="$BUILD_DIR/LanClip-v${VERSION}-macOS-universal.zip"
ICONSET_DIR="$BUILD_DIR/AppIcon.iconset"
ICNS_PATH="$BUILD_DIR/AppIcon.icns"

INSTALL_LOCAL=0
for arg in "$@"; do
  if [ "$arg" = "--install" ]; then
    INSTALL_LOCAL=1
  fi
done

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR" "$ICONSET_DIR"

echo "1/4 生成应用图标..."
swift "$DIR/Sources/GenIcon.swift" "$ICONSET_DIR"
/usr/bin/iconutil -c icns "$ICONSET_DIR" -o "$ICNS_PATH"

echo "2/4 编译 Apple Silicon 与 Intel 双架构二进制..."
COMMON_FLAGS="-O -swift-version 5 -framework AppKit -framework Network -framework CryptoKit -framework Security"
swiftc $COMMON_FLAGS -target arm64-apple-macosx13.0 \
  "$DIR/Sources/Protocol.swift" "$DIR/Sources/NetworkEngine.swift" "$DIR/Sources/AppMain.swift" \
  -o "$BUILD_DIR/LanClip-arm64"

swiftc $COMMON_FLAGS -target x86_64-apple-macosx13.0 \
  "$DIR/Sources/Protocol.swift" "$DIR/Sources/NetworkEngine.swift" "$DIR/Sources/AppMain.swift" \
  -o "$BUILD_DIR/LanClip-x86_64"

/usr/bin/lipo -create \
  "$BUILD_DIR/LanClip-arm64" \
  "$BUILD_DIR/LanClip-x86_64" \
  -output "$BUILD_DIR/LanClip"

echo "3/4 组装并签名原生 .app 应用包..."
mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources"
cp "$BUILD_DIR/LanClip" "$APP_BUNDLE/Contents/MacOS/LanClip"
chmod +x "$APP_BUNDLE/Contents/MacOS/LanClip"
cp "$ICNS_PATH" "$APP_BUNDLE/Contents/Resources/AppIcon.icns"

cat > "$APP_BUNDLE/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>zh_CN</string>
	<key>CFBundleExecutable</key>
	<string>LanClip</string>
	<key>CFBundleIconFile</key>
	<string>AppIcon</string>
	<key>CFBundleIdentifier</key>
	<string>com.local.lanclip</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>局域网传文字</string>
	<key>CFBundleDisplayName</key>
	<string>局域网传文字</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>2.0.0</string>
	<key>CFBundleVersion</key>
	<string>1</string>
	<key>LSMinimumSystemVersion</key>
	<string>13.0</string>
	<key>NSHighResolutionCapable</key>
	<true/>
	<key>NSLocalNetworkUsageDescription</key>
	<string>用于在同一局域网内自动发现您的另一台 MacBook 并端到端加密传输剪贴板文字。</string>
	<key>NSBonjourServices</key>
	<array>
		<string>_lanclip._tcp</string>
	</array>
</dict>
</plist>
EOF

/usr/bin/codesign --force --deep --sign - "$APP_BUNDLE"
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "$APP_BUNDLE" "$ZIP_PATH"

if [ "$INSTALL_LOCAL" -eq 1 ]; then
  echo "4/4 安装到本机桌面与个人「应用程序」..."
  mkdir -p "$HOME/Applications"
  rm -rf "$HOME/Applications/${APP_NAME}.app" "$HOME/Desktop/${APP_NAME}.app"
  cp -R "$APP_BUNDLE" "$HOME/Applications/${APP_NAME}.app"
  cp -R "$APP_BUNDLE" "$HOME/Desktop/${APP_NAME}.app"
fi

rm -rf "$ICONSET_DIR" "$ICNS_PATH" "$BUILD_DIR/LanClip-arm64" "$BUILD_DIR/LanClip-x86_64" "$BUILD_DIR/LanClip"
echo "构建完成："
echo "  - 应用包：$APP_BUNDLE"
echo "  - 发行包：$ZIP_PATH"
