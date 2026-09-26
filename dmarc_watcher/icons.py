"""Tray icons drawn at runtime with Pillow, so there are no binary assets.

Glyphs are drawn as vector strokes rather than text: a font at 16x16 turns to
mush, and this keeps the icon readable at tray size on any DPI.
"""

from __future__ import annotations

from PIL import Image, ImageDraw

SIZE = 64

COLORS = {
    "ok":      ((34, 139, 84), (255, 255, 255)),    # green
    "problem": ((197, 48, 48), (255, 255, 255)),    # red
    "unknown": ((110, 116, 124), (255, 255, 255)),  # grey
    "error":   ((191, 128, 24), (255, 255, 255)),   # amber
}


def _rounded_bg(draw: ImageDraw.ImageDraw, color: tuple[int, int, int]) -> None:
    draw.rounded_rectangle([2, 2, SIZE - 3, SIZE - 3], radius=14, fill=color + (255,))


def _check(draw, fg):
    draw.line([(18, 33), (28, 44), (46, 21)], fill=fg + (255,), width=7,
              joint="curve")


def _bang(draw, fg):
    draw.rounded_rectangle([29, 15, 35, 38], radius=3, fill=fg + (255,))
    draw.ellipse([28, 43, 36, 51], fill=fg + (255,))


def _dash(draw, fg):
    draw.rounded_rectangle([19, 29, 45, 35], radius=3, fill=fg + (255,))


def _cross(draw, fg):
    draw.line([(21, 21), (43, 43)], fill=fg + (255,), width=7)
    draw.line([(43, 21), (21, 43)], fill=fg + (255,), width=7)


_GLYPHS = {"ok": _check, "problem": _bang, "unknown": _dash, "error": _cross}


def make_icon(state: str) -> Image.Image:
    bg, fg = COLORS.get(state, COLORS["unknown"])
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    _rounded_bg(draw, bg)
    _GLYPHS.get(state, _dash)(draw, fg)
    return img


def all_icons() -> dict[str, Image.Image]:
    """Pre-render every state once; swapping icons then costs nothing."""
    return {state: make_icon(state) for state in COLORS}
