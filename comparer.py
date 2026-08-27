"""Screenshot and text comparison used by the risk scorer."""

from __future__ import annotations

import asyncio
import io
import re

from PIL import Image


def _words(value: str) -> set[str]:
    return {word for word in re.findall(r"[\wÀ-ž]{3,}", value.lower()) if not word.isdigit()}


def _difference_hash(image_bytes: bytes) -> int:
    """A dependency-free perceptual hash (9×8 grayscale image)."""
    image = Image.open(io.BytesIO(image_bytes)).convert("L").resize((9, 8))
    pixels = list(image.getdata())
    result = 0
    for row in range(8):
        offset = row * 9
        for column in range(8):
            result = (result << 1) | int(pixels[offset + column] > pixels[offset + column + 1])
    return result


async def capture(page, url: str) -> dict:
    await page.goto(url, {"waitUntil": "networkidle2", "timeout": 30000})
    await asyncio.sleep(1)
    image = await page.screenshot({"type": "png"})
    title, text = await page.evaluate("""() => [document.title, document.body?.innerText?.slice(0, 12000) || '']""")
    return {
        "image": image,
        "hash": _difference_hash(image),
        "words": _words(f"{title} {text}"),
        "title": title,
    }


async def compare(page, url: str, reference: dict) -> tuple[int, int, bytes, str]:
    target = await capture(page, url)
    visual = max(0, round((1 - ((reference["hash"] ^ target["hash"]).bit_count() / 64)) * 100))
    union = reference["words"] | target["words"]
    textual = round(100 * len(reference["words"] & target["words"]) / len(union)) if union else 0
    return visual, textual, target["image"], target["title"]
