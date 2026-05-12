package com.gutschke.wgrtc.ui.theme

import androidx.compose.ui.graphics.Color

/**
 * Brand colour palette for wireguardrtc.
 *
 * Two-tone identity:
 *
 * - **Primary** is a deep, saturated teal — sophisticated, distinct
 * from the green-VPN-cliché and from competitors' indigo / blue
 * family. Conveys "secure" without shouting.
 * - **Tertiary** is a calm slate-blue used for accents (status
 * pills, connection badges). Reads as informational without
 * fighting the primary.
 *
 * The palette is hand-tuned rather than algorithmically generated so
 * the dark-mode variant maintains sufficient contrast on Pixel-class
 * OLED panels (verified against WCAG AA at 4.5:1 for body text).
 *
 * **Why not Material You / dynamic colour**: brand consistency. A
 * user's wallpaper-tinted UI varies wildly across devices, which
 * makes the "is this the same app I had on my old phone" recognition
 * test fail. We sacrifice the small Pixel-12+ Material-You bonus
 * for a stable visual identity.
 */

// ─── Primary (deep teal) ───────────────────────────────────────────
val BrandTeal900 = Color(0xFF002020)
val BrandTeal800 = Color(0xFF003737)
val BrandTeal700 = Color(0xFF004F50)
val BrandTeal600 = Color(0xFF006A6B) // primary @ light
val BrandTeal500 = Color(0xFF008B8C)
val BrandTeal400 = Color(0xFF24B5B4)
val BrandTeal300 = Color(0xFF4CDADA) // primary @ dark
val BrandTeal200 = Color(0xFF6FF7F4)
val BrandTeal100 = Color(0xFFA7FFFB)

// ─── Tertiary (slate blue accents) ─────────────────────────────────
val BrandSlate900 = Color(0xFF041C36)
val BrandSlate700 = Color(0xFF334863)
val BrandSlate500 = Color(0xFF4B607C)
val BrandSlate300 = Color(0xFFB3C8E8)
val BrandSlate100 = Color(0xFFD3E4FF)

// ─── Neutral surfaces ──────────────────────────────────────────────
val NeutralBgLight = Color(0xFFFAFDFC)
val NeutralOnBgLight = Color(0xFF161D1D)
val NeutralSurfaceVariantLight = Color(0xFFDAE5E4)
val NeutralOnSurfaceVariantLight = Color(0xFF3F4948)
val NeutralOutlineLight = Color(0xFF6F7978)

val NeutralBgDark = Color(0xFF0E1414)
val NeutralOnBgDark = Color(0xFFDDE4E3)
val NeutralSurfaceVariantDark = Color(0xFF3F4948)
val NeutralOnSurfaceVariantDark = Color(0xFFBEC9C8)
val NeutralOutlineDark = Color(0xFF899392)

// ─── Error ─────────────────────────────────────────────────────────
val ErrorLight = Color(0xFFBA1A1A)
val ErrorContainerLight = Color(0xFFFFDAD6)
val OnErrorContainerLight = Color(0xFF410002)
val ErrorDark = Color(0xFFFFB4AB)
val ErrorContainerDark = Color(0xFF93000A)
val OnErrorContainerDark = Color(0xFFFFDAD6)

// ─── Status colours (custom, used for tunnel state pills) ──────────
val StatusUpLight = Color(0xFF136D54)
val StatusUpContainerLight = Color(0xFFA0F2D1)
val StatusUpDark = Color(0xFF85D6B4)
val StatusUpContainerDark = Color(0xFF00513C)

val StatusConnectingLight = Color(0xFF7B5800)
val StatusConnectingContainerLight = Color(0xFFFFDF99)
val StatusConnectingDark = Color(0xFFFFC04D)
val StatusConnectingContainerDark = Color(0xFF5D4200)
