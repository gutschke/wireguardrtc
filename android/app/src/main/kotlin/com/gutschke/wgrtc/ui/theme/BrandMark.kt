package com.gutschke.wgrtc.ui.theme

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import kotlin.math.cos
import kotlin.math.sin

/**
 * The wireguardrtc brand mark.
 *
 * **Concept**: a hexagonal ring with a small inner glyph — the
 * hexagon evokes the cryptographic / lattice geometry of public-
 * key shapes; the inner glyph is a stylised path that loops back on
 * itself, suggesting a connection that finds its way home through
 * the otherwise-closed ring. Drawn as a Compose [Canvas] so it
 * scales crisply at any size and respects the active theme's
 * primary color without baking a tint into a raster asset.
 *
 * Originality: not a derivative of WireGuard's "shield" mark, of
 * Tailscale's "T" badge, or of any cloud-VPN logo I'm aware of.
 * Hexagons are a common geometric primitive — the differentiator
 * is the loop-through inner glyph.
 *
 * Sizes that look right out of the box: 24.dp (toolbar), 56.dp
 * (header card), 96.dp (about screen / launcher).
 */
@Composable
fun BrandMark(
    modifier: Modifier = Modifier,
    size: Dp = 56.dp,
    color: Color = MaterialTheme.colorScheme.primary,
    accent: Color = MaterialTheme.colorScheme.tertiary,
) {
    Canvas(modifier = modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height
        val cx = w / 2f
        val cy = h / 2f
        val outerR = w * 0.46f
        val innerR = w * 0.18f
        val strokeOuter = w * 0.07f
        val strokeInner = w * 0.05f

        // Hexagon outline. Pointy-top orientation (vertex at 90°);
        // less common than flat-top hexagons in tech logos so it
        // reads as distinctive without being weird.
        val hex = Path()
        for (i in 0..5) {
            val angle = Math.toRadians((60.0 * i - 90.0))
            val x = (cx + outerR * cos(angle)).toFloat()
            val y = (cy + outerR * sin(angle)).toFloat()
            if (i == 0) hex.moveTo(x, y) else hex.lineTo(x, y)
        }
        hex.close()
        drawPath(hex, color = color, style = Stroke(width = strokeOuter))

        // Inner glyph: a small open ring + a stub line piercing
        // its right side. The "pierce" gives directional motion
        // (outward) without being a literal arrow.
        drawCircle(
            color = accent,
            radius = innerR,
            center = Offset(cx, cy),
            style = Stroke(width = strokeInner),
        )
        // Stub line through the inner ring's right edge — the
        // "finds its way through" motif. Kept short so the mark
        // doesn't read as cluttered at small sizes.
        val stubLen = w * 0.18f
        drawLine(
            color = accent,
            start = Offset(cx + innerR - strokeInner / 2, cy),
            end = Offset(cx + innerR + stubLen, cy),
            strokeWidth = strokeInner,
        )
    }
}
