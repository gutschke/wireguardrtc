package com.gutschke.wgrtc.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

/**
 * App-wide Compose theme. Wrap the root composable with
 * [WgrtcTheme] — the rest of the app reads colours / typography
 * from [MaterialTheme] as usual.
 *
 * Status bar gets the brand surface tint so the top edge of the
 * screen feels integrated rather than the system's default white
 * strip. We deliberately don't use edge-to-edge styling — the
 * existing screens use Scaffold + TopAppBar which already handles
 * the inset; converting all of them would mean revisiting every
 * existing layout.
 */

private val WgrtcLightColors = lightColorScheme(
    primary = BrandTeal600,
    onPrimary = NeutralBgLight,
    primaryContainer = BrandTeal200,
    onPrimaryContainer = BrandTeal900,
    secondary = BrandTeal700,
    onSecondary = NeutralBgLight,
    secondaryContainer = BrandTeal100,
    onSecondaryContainer = BrandTeal800,
    tertiary = BrandSlate500,
    onTertiary = NeutralBgLight,
    tertiaryContainer = BrandSlate100,
    onTertiaryContainer = BrandSlate900,
    error = ErrorLight,
    onError = NeutralBgLight,
    errorContainer = ErrorContainerLight,
    onErrorContainer = OnErrorContainerLight,
    background = NeutralBgLight,
    onBackground = NeutralOnBgLight,
    surface = NeutralBgLight,
    onSurface = NeutralOnBgLight,
    surfaceVariant = NeutralSurfaceVariantLight,
    onSurfaceVariant = NeutralOnSurfaceVariantLight,
    outline = NeutralOutlineLight,
    inverseSurface = BrandTeal800,
    inverseOnSurface = NeutralBgLight,
    inversePrimary = BrandTeal300,
)

private val WgrtcDarkColors = darkColorScheme(
    primary = BrandTeal300,
    onPrimary = BrandTeal800,
    primaryContainer = BrandTeal700,
    onPrimaryContainer = BrandTeal200,
    secondary = BrandTeal200,
    onSecondary = BrandTeal800,
    secondaryContainer = BrandTeal700,
    onSecondaryContainer = BrandTeal100,
    tertiary = BrandSlate300,
    onTertiary = BrandSlate900,
    tertiaryContainer = BrandSlate700,
    onTertiaryContainer = BrandSlate100,
    error = ErrorDark,
    onError = ErrorContainerDark,
    errorContainer = ErrorContainerDark,
    onErrorContainer = OnErrorContainerDark,
    background = NeutralBgDark,
    onBackground = NeutralOnBgDark,
    surface = NeutralBgDark,
    onSurface = NeutralOnBgDark,
    surfaceVariant = NeutralSurfaceVariantDark,
    onSurfaceVariant = NeutralOnSurfaceVariantDark,
    outline = NeutralOutlineDark,
    inverseSurface = NeutralOnBgDark,
    inverseOnSurface = NeutralBgDark,
    inversePrimary = BrandTeal600,
)

@Composable
fun WgrtcTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val colors = if (darkTheme) WgrtcDarkColors else WgrtcLightColors

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = colors.surface.toArgb()
            WindowCompat.getInsetsController(window, view)
                .isAppearanceLightStatusBars = !darkTheme
        }
    }

    MaterialTheme(
        colorScheme = colors,
        typography = WgrtcTypography,
        content = content,
    )
}
