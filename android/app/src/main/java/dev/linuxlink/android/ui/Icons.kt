package dev.linuxlink.android.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.material3.LocalContentColor
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * The app's icon set, hand-drawn at runtime: material-icons-extended is not
 * in this build's offline dependency cache and ImageVector's builder API is
 * churny across Compose versions, so every glyph is a [DrawScope] routine on
 * a 24x24 viewport (scaled to the caller's size) using only stable canvas
 * primitives. If the artifact becomes available, delete this file and swap
 * the call sites 1:1. Glyphs draw in the tint they are given.
 */
@JvmInline
value class LlGlyph internal constructor(internal val draw: DrawScope.(Color) -> Unit)

private fun glyph(block: DrawScope.(Color) -> Unit): LlGlyph = LlGlyph(block)

private fun DrawScope.dot(c: Color, cx: Float, cy: Float, r: Float) = drawCircle(c, r, Offset(cx, cy))

private fun DrawScope.box(c: Color, l: Float, t: Float, r: Float, b: Float) =
    drawRect(c, Offset(l, t), Size(r - l, b - t))

private fun DrawScope.strokeBox(
    c: Color, l: Float, t: Float, r: Float, b: Float, w: Float = 2f,
) = drawRect(c, Offset(l, t), Size(r - l, b - t), style = Stroke(w))

private fun DrawScope.roundBox(
    c: Color, l: Float, t: Float, r: Float, b: Float, corner: Float, w: Float = 0f,
) {
    if (w > 0f) {
        drawRoundRect(
            color = c, topLeft = Offset(l, t), size = Size(r - l, b - t),
            cornerRadius = CornerRadius(corner), style = Stroke(w, cap = StrokeCap.Round),
        )
    } else {
        drawRoundRect(
            color = c, topLeft = Offset(l, t), size = Size(r - l, b - t),
            cornerRadius = CornerRadius(corner),
        )
    }
}

private fun DrawScope.line(
    c: Color, x1: Float, y1: Float, x2: Float, y2: Float, w: Float = 2f,
) = drawLine(c, Offset(x1, y1), Offset(x2, y2), w, StrokeCap.Round)

private fun DrawScope.ring(c: Color, cx: Float, cy: Float, r: Float, w: Float = 1.8f) =
    drawCircle(c, r, Offset(cx, cy), style = Stroke(w, cap = StrokeCap.Round))

private fun DrawScope.quad(
    c: Color, x1: Float, y1: Float, cx: Float, cy: Float, x2: Float, y2: Float, w: Float = 1.8f,
) = drawPath(
    path = Path().apply {
        moveTo(x1, y1)
        quadraticBezierTo(cx, cy, x2, y2)
    },
    color = c,
    style = Stroke(w, cap = StrokeCap.Round),
)

private fun DrawScope.ellipse(
    c: Color, cx: Float, cy: Float, rx: Float, ry: Float, w: Float = 1.6f,
) = drawPath(
    path = Path().apply {
        // circle approximation with 4 cubic segments (kappa), scaled to rx/ry
        val k = 0.5523f
        moveTo(cx, cy - ry)
        cubicTo(cx + rx * k, cy - ry, cx + rx, cy - ry * k, cx + rx, cy)
        cubicTo(cx + rx, cy + ry * k, cx + rx * k, cy + ry, cx, cy + ry)
        cubicTo(cx - rx * k, cy + ry, cx - rx, cy + ry * k, cx - rx, cy)
        cubicTo(cx - rx, cy - ry * k, cx - rx * k, cy - ry, cx, cy - ry)
        close()
    },
    color = c,
    style = Stroke(w, cap = StrokeCap.Round),
)

object LlIcons {
    val MoreVert: LlGlyph = glyph { c ->
        dot(c, 12f, 5f, 2f); dot(c, 12f, 12f, 2f); dot(c, 12f, 19f, 2f)
    }
    val Close: LlGlyph = glyph { c ->
        line(c, 6f, 6f, 18f, 18f, 2.4f)
        line(c, 18f, 6f, 6f, 18f, 2.4f)
    }
    val Check: LlGlyph = glyph { c ->
        line(c, 4.5f, 12.5f, 10f, 18f, 2.4f)
        line(c, 10f, 18f, 19.5f, 6f, 2.4f)
    }
    val ChevronRight: LlGlyph = glyph { c ->
        line(c, 9.5f, 5.5f, 16f, 12f, 2.2f)
        line(c, 16f, 12f, 9.5f, 18.5f, 2.2f)
    }
    val ArrowBack: LlGlyph = glyph { c ->
        line(c, 20f, 12f, 4.5f, 12f, 2.2f)
        line(c, 11f, 5f, 4f, 12f, 2.2f)
        line(c, 4f, 12f, 11f, 19f, 2.2f)
    }
    val Settings: LlGlyph = glyph { c ->
        line(c, 4f, 7f, 20f, 7f, 1.8f)
        dot(c, 15f, 7f, 2.4f)
        line(c, 4f, 12f, 20f, 12f, 1.8f)
        dot(c, 8f, 12f, 2.4f)
        line(c, 4f, 17f, 20f, 17f, 1.8f)
        dot(c, 17f, 17f, 2.4f)
    }
    val Add: LlGlyph = glyph { c ->
        line(c, 12f, 4.5f, 12f, 19.5f, 2.4f)
        line(c, 4.5f, 12f, 19.5f, 12f, 2.4f)
    }
    val Delete: LlGlyph = glyph { c ->
        line(c, 4f, 6.5f, 20f, 6.5f, 2f)
        line(c, 10f, 4f, 14f, 4f, 2f)
        strokeBox(c, 6f, 7.5f, 18f, 20f, 1.8f)
        line(c, 10f, 10.5f, 10f, 17f, 1.6f)
        line(c, 14f, 10.5f, 14f, 17f, 1.6f)
    }
    val Desktop: LlGlyph = glyph { c ->
        strokeBox(c, 2.5f, 4f, 21.5f, 16f, 1.8f)
        line(c, 12f, 16f, 12f, 18f, 2f)
        line(c, 8f, 19.5f, 16f, 19.5f, 2f)
    }
    val Monitor: LlGlyph = glyph { c ->
        strokeBox(c, 3f, 3.5f, 21f, 15.5f, 1.8f)
        line(c, 12f, 15.5f, 12f, 20f, 2f)
        line(c, 8f, 20f, 16f, 20f, 2f)
    }
    val Keyboard: LlGlyph = glyph { c ->
        strokeBox(c, 2.5f, 7f, 21.5f, 17f, 1.8f)
        for (i in 0 until 5) dot(c, 5.5f + i * 3.3f, 10.5f, 0.9f)
        roundBox(c, 8.5f, 13f, 15.5f, 15f, 1f, 1.4f)
    }
    val Mouse: LlGlyph = glyph { c ->
        roundBox(c, 7f, 3f, 17f, 21f, 5f, 1.8f)
        line(c, 12f, 6f, 12f, 10f, 1.8f)
    }
    val Touch: LlGlyph = glyph { c ->
        dot(c, 12f, 12f, 2.6f)
        ring(c, 12f, 12f, 5.5f)
        ring(c, 12f, 12f, 8.5f)
    }
    val Wifi: LlGlyph = glyph { c ->
        dot(c, 12f, 18.5f, 1.8f)
        quad(c, 7.5f, 14.5f, 12f, 10.5f, 16.5f, 14.5f)
        quad(c, 4.5f, 11.5f, 12f, 5.5f, 19.5f, 11.5f)
    }
    val Lan: LlGlyph = glyph { c ->
        strokeBox(c, 9.5f, 3f, 14.5f, 8f, 1.6f)
        strokeBox(c, 2.5f, 14f, 7.5f, 19f, 1.6f)
        strokeBox(c, 16.5f, 14f, 21.5f, 19f, 1.6f)
        line(c, 12f, 8f, 12f, 11f, 1.6f)
        line(c, 5f, 11f, 19f, 11f, 1.6f)
        line(c, 5f, 11f, 5f, 14f, 1.6f)
        line(c, 19f, 11f, 19f, 14f, 1.6f)
    }
    val Lock: LlGlyph = glyph { c ->
        drawArc(
            color = c,
            startAngle = 180f,
            sweepAngle = 180f,
            useCenter = false,
            topLeft = Offset(8f, 4.5f),
            size = Size(8f, 8f),
            style = Stroke(2f, cap = StrokeCap.Round),
        )
        roundBox(c, 5.5f, 10.5f, 18.5f, 20f, 2.5f, 2f)
        dot(c, 12f, 15.5f, 1.5f)
    }
    val Power: LlGlyph = glyph { c ->
        drawArc(
            color = c,
            startAngle = 300f,
            sweepAngle = 300f,
            useCenter = false,
            topLeft = Offset(6f, 7f),
            size = Size(12f, 12f),
            style = Stroke(2f, cap = StrokeCap.Round),
        )
        line(c, 12f, 3.5f, 12f, 12f, 2.4f)
    }
    val Volume: LlGlyph = glyph { c ->
        drawPath(
            path = Path().apply {
                moveTo(4f, 9f)
                lineTo(8f, 9f)
                lineTo(13f, 4.5f)
                lineTo(13f, 19.5f)
                lineTo(8f, 15f)
                lineTo(4f, 15f)
                close()
            },
            color = c,
        )
        quad(c, 16f, 9f, 19.5f, 12f, 16f, 15f)
    }
    val Mic: LlGlyph = glyph { c ->
        roundBox(c, 9.5f, 2.5f, 14.5f, 12f, 2.5f)
        quad(c, 5.5f, 10.5f, 12f, 19.5f, 18.5f, 10.5f)
        line(c, 12f, 16f, 12f, 21f, 1.8f)
        line(c, 8.5f, 21f, 15.5f, 21f, 1.8f)
    }
    val Pin: LlGlyph = glyph { c ->
        drawPath(
            path = Path().apply {
                moveTo(12f, 2.5f)
                lineTo(15.5f, 6f)
                lineTo(14f, 8f)
                lineTo(17.5f, 11.5f)
                lineTo(15.5f, 13.5f)
                lineTo(12f, 10f)
                lineTo(10f, 12f)
                lineTo(12f, 8f)
                lineTo(8.5f, 6f)
                close()
            },
            color = c,
        )
        line(c, 6.5f, 14.5f, 3f, 21f, 1.8f)
    }
    val Notifications: LlGlyph = glyph { c ->
        drawPath(
            path = Path().apply {
                moveTo(12f, 2.5f)
                quadraticBezierTo(17f, 4f, 17f, 10.5f)
                lineTo(19f, 16.5f)
                lineTo(5f, 16.5f)
                lineTo(7f, 10.5f)
                quadraticBezierTo(7f, 4f, 12f, 2.5f)
                close()
            },
            color = c,
        )
        dot(c, 12f, 19.5f, 1.8f)
    }
    val Clipboard: LlGlyph = glyph { c ->
        strokeBox(c, 5f, 4f, 19f, 21f, 1.8f)
        roundBox(c, 9f, 2f, 15f, 6f, 1.2f)
        line(c, 8.5f, 10.5f, 15.5f, 10.5f, 1.6f)
        line(c, 8.5f, 14f, 15.5f, 14f, 1.6f)
    }
    val Eye: LlGlyph = glyph { c ->
        quad(c, 2.5f, 12f, 12f, 4.5f, 21.5f, 12f)
        quad(c, 2.5f, 12f, 12f, 19.5f, 21.5f, 12f)
        dot(c, 12f, 12f, 2.6f)
    }
    val Language: LlGlyph = glyph { c ->
        ring(c, 12f, 12f, 9.2f, 1.6f)
        ellipse(c, 12f, 12f, 4.2f, 9.2f, 1.4f)
        line(c, 3.4f, 9.5f, 20.6f, 9.5f, 1.4f)
        line(c, 3.4f, 14.5f, 20.6f, 14.5f, 1.4f)
    }
    val Sun: LlGlyph = glyph { c ->
        ring(c, 12f, 12f, 4f, 2f)
        for (i in 0 until 8) {
            val a = Math.PI / 4 * i
            line(
                c,
                (12f + Math.cos(a) * 7f).toFloat(), (12f + Math.sin(a) * 7f).toFloat(),
                (12f + Math.cos(a) * 9.6f).toFloat(), (12f + Math.sin(a) * 9.6f).toFloat(),
                1.8f,
            )
        }
    }
    val Moon: LlGlyph = glyph { c ->
        drawPath(
            path = Path().apply {
                addArc(Rect(3.5f, 3.5f, 20.5f, 20.5f), 110f, 140f)
                quadraticBezierTo(16.5f, 14f, 12f, 3.6f)
                close()
            },
            color = c,
        )
    }
    val History: LlGlyph = glyph { c ->
        ring(c, 12f, 12f, 8.5f, 1.8f)
        line(c, 12f, 12f, 12f, 7.5f, 1.8f)
        line(c, 12f, 12f, 15.5f, 13.5f, 1.8f)
    }
    val Pip: LlGlyph = glyph { c ->
        strokeBox(c, 2.5f, 4.5f, 21.5f, 17.5f, 1.8f)
        box(c, 12f, 10.5f, 19.5f, 16f)
    }
    val Info: LlGlyph = glyph { c ->
        ring(c, 12f, 12f, 9f, 1.8f)
        dot(c, 12f, 7.6f, 1.3f)
        line(c, 12f, 11f, 12f, 16.5f, 2.2f)
    }
}

/**
 * Draws one of [LlIcons] at [size], tinted with [tint] (or the ambient
 * content color when unset), like material3's Icon does for the library set.
 */
@Composable
fun LlIcon(
    glyph: LlGlyph,
    contentDescription: String?,
    modifier: Modifier = Modifier,
    tint: Color = Color.Unspecified,
    size: Dp = 24.dp,
) {
    val color = if (tint != Color.Unspecified) tint else LocalContentColor.current
    var mod = modifier.size(size)
    if (contentDescription != null) {
        mod = mod.semantics { this.contentDescription = contentDescription }
    }
    Canvas(modifier = mod) {
        val s = minOf(this.size.width, this.size.height) / 24f
        scale(s) { glyph.draw.invoke(this, color) }
    }
}
