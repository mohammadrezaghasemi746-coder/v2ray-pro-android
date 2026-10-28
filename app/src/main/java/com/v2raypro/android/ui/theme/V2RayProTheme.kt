package com.v2raypro.android.ui.theme

import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.ui.graphics.Color

object V2RayProColors {
    val DeepSpaceBg = Color(0xFF070B19)
    val CardGlassSurface = Color(0xCC0F172A)
    val NeonCyan = Color(0xFF00F2FE)
    val ElectricBlue = Color(0xFF4FACFE)
    val NeonPurple = Color(0xFF8B5CF6)
    val EmeraldConnected = Color(0xFF10B981)
    val TextPrimary = Color(0xFFF8FAFC)
    val TextSecondary = Color(0xFF94A3B8)
}

object IosSpringSpecs {
    // Matches iOS UISpringTimingParameters(dampingRatio: 0.78, frequencyResponse: 0.38)
    val InteractiveSpring = spring<Float>(
        dampingRatio = 0.78f,
        stiffness = Spring.StiffnessMediumLow
    )
    val BouncyOrbSpring = spring<Float>(
        dampingRatio = Spring.DampingRatioLowBouncy,
        stiffness = Spring.StiffnessLow
    )
}
