import AppKit
import Foundation

guard CommandLine.arguments.count >= 2 else {
    fputs("Usage: GenIcon <iconset_dir>\n", stderr)
    exit(1)
}

let outDir = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)

func renderIcon(px: Int) -> Data? {
    guard let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: px,
        pixelsHigh: px,
        bitsPerSample: 8,
        samplesPerPixel: 4,
        hasAlpha: true,
        isPlanar: false,
        colorSpaceName: .deviceRGB,
        bytesPerRow: 0,
        bitsPerPixel: 0
    ) else { return nil }

    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let ctx = NSGraphicsContext.current!.cgContext

    let s = CGFloat(px)
    let margin = s * 0.08
    let cardRect = CGRect(x: margin, y: margin, width: s - 2 * margin, height: s - 2 * margin)
    let cardPath = CGPath(roundedRect: cardRect, cornerWidth: s * 0.21, cornerHeight: s * 0.21, transform: nil)

    ctx.saveGState()
    ctx.addPath(cardPath)
    ctx.clip()

    let colors = [
        NSColor(calibratedRed: 0.14, green: 0.52, blue: 0.98, alpha: 1.0).cgColor,
        NSColor(calibratedRed: 0.05, green: 0.30, blue: 0.80, alpha: 1.0).cgColor
    ] as CFArray
    if let grad = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: colors, locations: [0.0, 1.0]) {
        ctx.drawLinearGradient(grad, start: CGPoint(x: 0, y: s), end: CGPoint(x: s, y: 0), options: [])
    }
    ctx.restoreGState()

    // Subtle white border highlight
    ctx.setStrokeColor(NSColor(white: 1.0, alpha: 0.22).cgColor)
    ctx.setLineWidth(max(1.0, s * 0.015))
    ctx.addPath(cardPath)
    ctx.strokePath()

    // Clipboard board body
    let boardW = s * 0.44
    let boardH = s * 0.54
    let boardX = s * 0.28
    let boardY = s * 0.20
    let boardRect = CGRect(x: boardX, y: boardY, width: boardW, height: boardH)
    let boardPath = CGPath(roundedRect: boardRect, cornerWidth: s * 0.06, cornerHeight: s * 0.06, transform: nil)
    ctx.setFillColor(NSColor(white: 1.0, alpha: 0.94).cgColor)
    ctx.addPath(boardPath)
    ctx.fillPath()

    // Clipboard top clip
    let clipW = s * 0.22
    let clipH = s * 0.09
    let clipRect = CGRect(x: (s - clipW) / 2, y: boardY + boardH - clipH * 0.45, width: clipW, height: clipH)
    let clipPath = CGPath(roundedRect: clipRect, cornerWidth: clipH * 0.45, cornerHeight: clipH * 0.45, transform: nil)
    ctx.setFillColor(NSColor(calibratedRed: 0.85, green: 0.93, blue: 1.0, alpha: 1.0).cgColor)
    ctx.addPath(clipPath)
    ctx.fillPath()

    // Blue text lines on clipboard
    ctx.setFillColor(NSColor(calibratedRed: 0.14, green: 0.46, blue: 0.90, alpha: 0.85).cgColor)
    for idx in 0..<3 {
        let lw = boardW * (idx == 2 ? 0.45 : 0.68)
        let lh = max(1.5, s * 0.042)
        let lx = boardX + boardW * 0.16
        let ly = boardY + boardH * (0.60 - CGFloat(idx) * 0.16)
        let linePath = CGPath(roundedRect: CGRect(x: lx, y: ly, width: lw, height: lh), cornerWidth: lh / 2, cornerHeight: lh / 2, transform: nil)
        ctx.addPath(linePath)
        ctx.fillPath()
    }

    // Small upward-right transmit arrow badge
    let arrow = CGMutablePath()
    let ax = s * 0.66
    let ay = s * 0.27
    let ar = s * 0.13
    ctx.setFillColor(NSColor(calibratedRed: 0.16, green: 0.80, blue: 0.46, alpha: 1.0).cgColor)
    ctx.fillEllipse(in: CGRect(x: ax - ar, y: ay - ar, width: ar * 2, height: ar * 2))
    arrow.move(to: CGPoint(x: ax - ar * 0.45, y: ay))
    arrow.addLine(to: CGPoint(x: ax + ar * 0.45, y: ay))
    arrow.move(to: CGPoint(x: ax + ar * 0.10, y: ay + ar * 0.35))
    arrow.addLine(to: CGPoint(x: ax + ar * 0.45, y: ay))
    arrow.addLine(to: CGPoint(x: ax + ar * 0.10, y: ay - ar * 0.35))
    ctx.setStrokeColor(NSColor.white.cgColor)
    ctx.setLineWidth(max(1.5, s * 0.032))
    ctx.setLineCap(.round)
    ctx.setLineJoin(.round)
    ctx.addPath(arrow)
    ctx.strokePath()

    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])
}

let sizes: [(String, Int)] = [
    ("icon_16x16.png", 16),
    ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32),
    ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128),
    ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256),
    ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512),
    ("icon_512x512@2x.png", 1024),
]

for (filename, px) in sizes {
    guard let png = renderIcon(px: px) else {
        fputs("Failed to render \(filename)\n", stderr)
        exit(1)
    }
    try png.write(to: outDir.appendingPathComponent(filename))
}
print("Iconset generated successfully")
