#!/usr/bin/env python3
"""
generate_word_seeds.py — Generate word-image seeds for the Tesseract fuzzer corpus.

Motivation
----------
The image-bytes fuzzer (fuzzer-api-image) stalls before reaching Tesseract's
dictionary/word-correction layer because random byte mutations rarely produce
images with recognizable text.  Adding images that already contain valid words
— especially words with ambiguous ell/one/eye characters — gives libFuzzer
starting points whose byte-close mutations have a much higher chance of
surviving the Leptonica decode + LSTM recognition stage and entering the
post-processing path where bugs like CVE-2021-36081 (one_ell_conflict) live.

Output
------
Files are written to the same directory as this script (corpus/).
Naming convention:  word_<word>_<font_tag>_<size>[_noisy].<ext>
Example:            word_illegal_arial_36.png
                    word_illegal_arial_36_noisy.jpg

Usage
-----
    python3 corpus/generate_word_seeds.py
"""

import os
import random
import sys

try:
    from PIL import Image, ImageDraw, ImageFilter, ImageFont
except ImportError:
    sys.exit("Pillow is not installed.  Run: pip3 install Pillow")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Words chosen for high ell / one / eye density — the characters that trigger
# one_ell_conflict() in the Tesseract dictionary-correction path.
WORDS = [
    "illegal", "ill", "fill", "bill", "will", "still",
    "lull", "llama", "all", "tall", "call",
    "1llegal", "ill1", "B111", "l0ll",
]

# System TTF fonts confirmed present on macOS ARM64.
FONTS = {
    "arial":  "/Library/Fonts/Arial Unicode.ttf",
    "mono":   "/System/Library/Fonts/SFNSMono.ttf",
    "geneva": "/System/Library/Fonts/Geneva.ttf",
}

# Point sizes covering the range Tesseract's LSTM is trained on.
SIZES = [24, 36, 48]

# Output formats — each exercises a different Leptonica decoder path.
# (ext, save_kwargs)
FORMATS = [
    ("png",  {}),
    ("jpg",  {"quality": 95}),
    ("bmp",  {}),
    ("tiff", {}),
]

# Padding around the rendered text (pixels on each side).
PADDING = 20

# Probability that a pixel is flipped when generating a noisy variant.
NOISE_PROB = 0.01

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def load_font(path: str, size: int) -> ImageFont.FreeTypeFont:
    """Load a TTF font, falling back to the Pillow default if the path is missing."""
    if os.path.exists(path):
        return ImageFont.truetype(path, size)
    print(f"  WARNING: font not found at {path}, using Pillow default", file=sys.stderr)
    return ImageFont.load_default()


def make_word_image(word: str, font: ImageFont.FreeTypeFont) -> Image.Image:
    """Render *word* in black on a white grayscale canvas, auto-sized to fit."""
    # Measure text bounding box using a temporary draw surface.
    dummy = Image.new("L", (1, 1))
    bbox = ImageDraw.Draw(dummy).textbbox((0, 0), word, font=font)
    text_w = bbox[2] - bbox[0]
    text_h = bbox[3] - bbox[1]

    canvas_w = text_w + 2 * PADDING
    canvas_h = text_h + 2 * PADDING

    img = Image.new("L", (canvas_w, canvas_h), color=255)  # white background
    draw = ImageDraw.Draw(img)
    draw.text((PADDING - bbox[0], PADDING - bbox[1]), word, font=font, fill=0)
    return img


def add_noise(img: Image.Image) -> Image.Image:
    """Apply a light Gaussian blur then flip ~1% of pixels at random."""
    img = img.filter(ImageFilter.GaussianBlur(radius=0.5))
    pixels = list(img.get_flattened_data())
    rng = random.Random(42)  # fixed seed for reproducibility
    pixels = [
        (255 - p if rng.random() < NOISE_PROB else p)
        for p in pixels
    ]
    noisy = Image.new("L", img.size)
    noisy.putdata(pixels)
    return noisy


def save_image(img: Image.Image, path: str, save_kwargs: dict) -> None:
    """Save *img* to *path*, converting mode as needed for the format."""
    ext = os.path.splitext(path)[1].lower()
    # BMP and JPEG do not support palette or 'P' mode; PNG handles 'L' fine.
    # TIFF also handles 'L'.  No conversion needed for grayscale ('L').
    img.save(path, **save_kwargs)


# ---------------------------------------------------------------------------
# Main generation loop
# ---------------------------------------------------------------------------

def main() -> None:
    generated = 0
    skipped = 0

    for font_tag, font_path in FONTS.items():
        for size in SIZES:
            font = load_font(font_path, size)

            for word in WORDS:
                base_img = make_word_image(word, font)

                for ext, kwargs in FORMATS:
                    # Clean variant
                    clean_name = f"word_{word}_{font_tag}_{size}.{ext}"
                    clean_path = os.path.join(SCRIPT_DIR, clean_name)
                    save_image(base_img, clean_path, kwargs)
                    generated += 1

                # Noisy variant — PNG only (lossless, so noise is preserved exactly)
                noisy_img = add_noise(base_img)
                noisy_name = f"word_{word}_{font_tag}_{size}_noisy.png"
                noisy_path = os.path.join(SCRIPT_DIR, noisy_name)
                save_image(noisy_img, noisy_path, {})
                generated += 1

    print(f"Done. Generated {generated} seed images in {SCRIPT_DIR}/")
    print(f"      Skipped  {skipped} (already existed)")
    print()
    print("Next step — copy to live corpus:")
    print(f"  cp {SCRIPT_DIR}/word_*.* "
          f"{os.path.join(os.path.dirname(SCRIPT_DIR), 'build-fuzz', 'fuzz_corpus')}/")


if __name__ == "__main__":
    main()
