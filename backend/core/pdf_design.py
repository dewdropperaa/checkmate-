"""PDF report design constants.

Extracted from the Checkmate product UI (extension popup.html) to ensure
brand consistency across all report formats. These constants define the
authoritative color palette, typography scale, and severity color coding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

# RGB color type (used by fpdf2)
RGB = Tuple[int, int, int]


@dataclass(frozen=True)
class Colors:
    """Brand color palette from Checkmate extension CSS variables."""

    # Primary backgrounds (dark theme)
    BG_DARK: RGB = (10, 13, 11)  # --bg: #0a0d0b
    PANEL: RGB = (14, 19, 16)  # --panel: #0e1310
    PANEL_ALT: RGB = (12, 21, 18)  # --panel-alt: #0c1512

    # Header/brand background (dark navy from HTML report)
    HEADER_BG: RGB = (15, 23, 42)  # #0f172a - slate-900

    # Borders
    BORDER: RGB = (28, 43, 34)  # --border: #1c2b22
    BORDER_BRIGHT: RGB = (43, 69, 52)  # --border-bright: #2b4534

    # Text colors
    FG_PRIMARY: RGB = (203, 216, 207)  # --fg: #cbd8cf
    FG_DIM: RGB = (110, 132, 120)  # --fg-dim: #6e8478
    FG_FAINT: RGB = (71, 89, 78)  # --fg-faint: #47594e
    FG_LIGHT: RGB = (248, 250, 252)  # #f8fafc - slate-50 (for dark bg)
    FG_MUTED: RGB = (148, 163, 184)  # #94a3b8 - slate-400

    # Accent colors
    ACCENT: RGB = (61, 220, 132)  # --accent: #3ddc84
    ACCENT_BRIGHT: RGB = (125, 255, 176)  # --accent-bright: #7dffb0

    # Severity colors - WCAG AA compliant against white backgrounds
    CRITICAL: RGB = (185, 28, 28)  # #b91c1c - red-700 (contrast 5.6:1)
    HIGH: RGB = (180, 83, 9)  # #b45309 - amber-700 (contrast 4.8:1)
    MEDIUM: RGB = (133, 77, 14)  # #854d0e - yellow-800 (contrast 5.1:1)
    LOW: RGB = (29, 78, 216)  # #1d4ed8 - blue-700 (contrast 4.7:1)
    INFO: RGB = (75, 85, 99)  # #4b5563 - gray-600 (contrast 5.9:1)

    # Severity badge backgrounds (lighter variants for badges)
    CRITICAL_LIGHT: RGB = (254, 226, 226)  # #fee2e2 - red-100
    HIGH_LIGHT: RGB = (254, 243, 199)  # #fef3c7 - amber-100
    MEDIUM_LIGHT: RGB = (254, 249, 195)  # #fef9c3 - yellow-100
    LOW_LIGHT: RGB = (219, 234, 254)  # #dbeafe - blue-100
    INFO_LIGHT: RGB = (243, 244, 246)  # #f3f4f6 - gray-100

    # Semantic colors
    SUCCESS: RGB = (34, 197, 94)  # #22c55e - green-500
    WARNING: RGB = (234, 179, 8)  # #eab308 - yellow-500
    ERROR: RGB = (239, 68, 68)  # #ef4444 - red-500

    # Card/section backgrounds
    CARD_BG: RGB = (255, 255, 255)  # White card background
    AI_CARD_BG: RGB = (248, 251, 255)  # #f8fbff - light blue tint for AI content
    AI_CARD_BORDER: RGB = (147, 197, 253)  # #93c5fd - blue-300
    GOOD_TO_KNOW_BG: RGB = (240, 253, 244)  # #f0fdf4 - green-50
    GOOD_TO_KNOW_BORDER: RGB = (134, 239, 172)  # #86efac - green-300

    # Risk gauge gradient stops
    GAUGE_LOW: RGB = (34, 197, 94)  # Green
    GAUGE_MID: RGB = (234, 179, 8)  # Yellow
    GAUGE_HIGH: RGB = (239, 68, 68)  # Red


# Singleton instance
COLORS = Colors()


@dataclass(frozen=True)
class Typography:
    """Typography scale for PDF reports (in points)."""

    # Font families (fpdf2 built-in)
    FONT_SANS: str = "Helvetica"
    FONT_MONO: str = "Courier"

    # Size scale
    SIZE_TITLE: int = 22  # Report title
    SIZE_H1: int = 16  # Section headers (Critical, High, etc.)
    SIZE_H2: int = 14  # Subsection headers
    SIZE_H3: int = 12  # Finding titles
    SIZE_BODY: int = 10  # Body text, descriptions
    SIZE_SMALL: int = 9  # Technical details, captions
    SIZE_TINY: int = 8  # Page numbers, timestamps

    # Line heights (multiplier)
    LINE_HEIGHT_TIGHT: float = 1.2
    LINE_HEIGHT_NORMAL: float = 1.5
    LINE_HEIGHT_RELAXED: float = 1.8


# Singleton instance
TYPOGRAPHY = Typography()


@dataclass(frozen=True)
class Spacing:
    """Spacing constants for PDF layout (in mm)."""

    # Page margins
    MARGIN_TOP: float = 15.0
    MARGIN_BOTTOM: float = 20.0  # Extra space for footer
    MARGIN_LEFT: float = 15.0
    MARGIN_RIGHT: float = 15.0

    # Section spacing
    SECTION_GAP: float = 8.0
    SUBSECTION_GAP: float = 5.0

    # Card/element spacing
    CARD_PADDING: float = 8.0
    CARD_GAP: float = 4.0

    # Header/footer heights
    HEADER_HEIGHT: float = 25.0
    FOOTER_HEIGHT: float = 12.0

    # Cover page elements
    COVER_LOGO_SIZE: float = 35.0
    COVER_TITLE_OFFSET: float = 60.0


# Singleton instance
SPACING = Spacing()


def severity_color(severity: str) -> RGB:
    """Get the primary color for a severity level."""
    severity_map = {
        "critical": COLORS.CRITICAL,
        "high": COLORS.HIGH,
        "medium": COLORS.MEDIUM,
        "low": COLORS.LOW,
        "info": COLORS.INFO,
    }
    return severity_map.get(severity.lower(), COLORS.INFO)


def severity_light_color(severity: str) -> RGB:
    """Get the light/background color for a severity level."""
    severity_map = {
        "critical": COLORS.CRITICAL_LIGHT,
        "high": COLORS.HIGH_LIGHT,
        "medium": COLORS.MEDIUM_LIGHT,
        "low": COLORS.LOW_LIGHT,
        "info": COLORS.INFO_LIGHT,
    }
    return severity_map.get(severity.lower(), COLORS.INFO_LIGHT)


def confidence_color(status: str) -> RGB:
    """Get color for verification/confidence status."""
    status_lower = status.lower()
    if status_lower == "confirmed":
        return COLORS.SUCCESS
    if status_lower in ("unconfirmed", "likely_false_positive"):
        return COLORS.FG_DIM
    if status_lower == "unverified":
        return COLORS.WARNING
    return COLORS.FG_DIM


def risk_score_color(score: float) -> RGB:
    """Get color for an overall risk score (0-10)."""
    if score >= 7.0:
        return COLORS.CRITICAL
    if score >= 4.0:
        return COLORS.HIGH
    if score >= 2.0:
        return COLORS.MEDIUM
    if score > 0:
        return COLORS.LOW
    return COLORS.SUCCESS


def hex_to_rgb(hex_color: str) -> RGB:
    """Convert hex color string to RGB tuple."""
    hex_color = hex_color.lstrip("#")
    return (
        int(hex_color[0:2], 16),
        int(hex_color[2:4], 16),
        int(hex_color[4:6], 16),
    )


def rgb_to_hex(rgb: RGB) -> str:
    """Convert RGB tuple to hex color string."""
    return f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"
