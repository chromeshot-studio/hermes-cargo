#!/usr/bin/env python3
"""Generate the HERMES icon set (ico / icns / png / svg) from primitives.

    python tools/gen_icons.py     ->  assets/icons/

Everything is drawn in code from circles, squares and triangles - no traced
artwork, no fonts, no third-party assets - so the whole set is as licensable as
the source file it lives in. The Rust binary embeds the results with
include_bytes!, so `hermes install-system` needs no installer.

Design rules:

* One silhouette per file type, so they stay apart at 16px where colour is
  nearly useless: circle = .origin (a source), square = .foiled (a plan),
  triangle = the app itself.
* A second, simplified master is drawn for sizes below 32px. Shrinking the
  detailed art that far turns three overlapping shapes into grey mush, so small
  sizes get their own drawing with fewer elements and heavier strokes.
* Rounded tile, because every current desktop draws icons on one.
"""
import io
import math
import os
import struct

from PIL import Image, ImageChops, ImageDraw

OUT = os.path.join(os.path.dirname(__file__), "..", "assets", "icons")
os.makedirs(OUT, exist_ok=True)

S = 2048              # supersample canvas, downscaled with LANCZOS
TILE_RADIUS = 0.22    # of the canvas

BG = (23, 23, 23, 255)
INK_DIM = (72, 72, 78, 255)
INK_MID = (108, 108, 114, 255)
INK_HI = (168, 168, 172, 255)
PAPER = (232, 232, 232, 255)
ORIGIN_ACCENT = (94, 200, 224, 255)   # cool: a source
FOILED_ACCENT = (226, 166, 90, 255)   # warm: a sealed plan

SMALL_CUTOFF = 32     # below this, use the simplified master


def canvas():
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(img).rounded_rectangle(
        [0, 0, S - 1, S - 1], radius=int(S * TILE_RADIUS), fill=BG)
    return img


def clip_to_tile(img):
    """Keep the art inside the rounded tile."""
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [0, 0, S - 1, S - 1], radius=int(S * TILE_RADIUS), fill=255)
    img.putalpha(ImageChops.multiply(img.getchannel("A"), mask))
    return img


def triangle(draw, cx, cy, r, fill=None, outline=None, width=0):
    points = [(cx + r * math.cos(math.radians(a)), cy + r * math.sin(math.radians(a)))
              for a in (-90, 30, 150)]
    draw.polygon(points, fill=fill, outline=outline, width=width)


def box(x0, y0, x1, y1):
    return [x0 * S, y0 * S, x1 * S, y1 * S]


# ---------------------------------------------------------------------------
# The three marks
# ---------------------------------------------------------------------------

def hermes_detailed():
    """App icon: the original composition, circle -> square -> triangle, kept
    inside a margin so nothing looks like it fell off the tile."""
    img = canvas()
    d = ImageDraw.Draw(img)
    d.ellipse(box(0.16, 0.46, 0.56, 0.86), fill=INK_DIM)
    d.rectangle(box(0.26, 0.28, 0.70, 0.72), fill=INK_MID)
    triangle(d, 0.57 * S, 0.47 * S, 0.21 * S, fill=PAPER)
    return clip_to_tile(img)


def hermes_simple():
    img = canvas()
    d = ImageDraw.Draw(img)
    d.rectangle(box(0.20, 0.26, 0.64, 0.70), fill=INK_MID)
    triangle(d, 0.58 * S, 0.52 * S, 0.26 * S, fill=PAPER)
    return clip_to_tile(img)


def origin_detailed():
    """.origin - a source. The circle carries the silhouette; the frame and the
    triangle stay inside it so the mark reads as one object."""
    img = canvas()
    d = ImageDraw.Draw(img)
    d.rectangle(box(0.22, 0.22, 0.78, 0.78), outline=INK_MID, width=int(0.030 * S))
    d.ellipse(box(0.26, 0.44, 0.62, 0.80), fill=ORIGIN_ACCENT)
    triangle(d, 0.60 * S, 0.44 * S, 0.19 * S, fill=PAPER)
    return clip_to_tile(img)


def origin_simple():
    img = canvas()
    d = ImageDraw.Draw(img)
    d.ellipse(box(0.16, 0.40, 0.64, 0.88), fill=ORIGIN_ACCENT)
    triangle(d, 0.62 * S, 0.40 * S, 0.24 * S, fill=PAPER)
    return clip_to_tile(img)


def foiled_detailed():
    """.foiled - a sealed plan: a document with a folded corner, wrapped by a
    band of foil. The band overhangs symmetrically, so it reads as a seal
    around the page rather than a stripe behind it."""
    img = canvas()
    d = ImageDraw.Draw(img)
    d.rectangle(box(0.28, 0.18, 0.76, 0.82), fill=PAPER)
    # Folded top-right corner: knock the corner out, then shade the fold.
    d.polygon([(0.62 * S, 0.18 * S), (0.76 * S, 0.18 * S), (0.76 * S, 0.32 * S)], fill=BG)
    d.polygon([(0.62 * S, 0.18 * S), (0.76 * S, 0.32 * S), (0.62 * S, 0.32 * S)], fill=INK_DIM)
    d.rectangle(box(0.20, 0.46, 0.84, 0.58), fill=FOILED_ACCENT)
    return clip_to_tile(img)


def foiled_simple():
    img = canvas()
    d = ImageDraw.Draw(img)
    d.rectangle(box(0.26, 0.16, 0.74, 0.84), fill=PAPER)
    d.rectangle(box(0.12, 0.42, 0.88, 0.60), fill=FOILED_ACCENT)
    return clip_to_tile(img)


MARKS = {
    "hermes": (hermes_detailed, hermes_simple),
    "origin": (origin_detailed, origin_simple),
    "foiled": (foiled_detailed, foiled_simple),
}

# ---------------------------------------------------------------------------
# Encoders
# ---------------------------------------------------------------------------


def render(masters, size):
    detailed, simple = masters
    source = simple if size < SMALL_CUTOFF else detailed
    return source.resize((size, size), Image.LANCZOS)


def png_bytes(image):
    buf = io.BytesIO()
    image.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def bmp_entry(image):
    """A 32bpp BMP ICO entry: BITMAPINFOHEADER, bottom-up BGRA, then AND mask.

    Windows renders small sizes from BMP entries more predictably than from
    PNG ones, so anything under 256px is written this way.
    """
    w, h = image.size
    header = struct.pack("<IiiHHIIiiII", 40, w, h * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    rows = []
    pixels = image.load()
    for y in range(h - 1, -1, -1):
        row = bytearray()
        for x in range(w):
            r, g, b, a = pixels[x, y]
            row += bytes((b, g, r, a))
        rows.append(bytes(row))
    xor = b"".join(rows)
    # AND mask: one bit per pixel, rows padded to 4 bytes. Alpha already
    # carries transparency, so the mask is all-zero (fully opaque).
    stride = ((w + 31) // 32) * 4
    and_mask = b"\x00" * (stride * h)
    return header + xor + and_mask


def write_ico(path, masters, sizes=(16, 20, 24, 32, 48, 64, 128, 256)):
    entries = []
    for size in sizes:
        image = render(masters, size)
        payload = png_bytes(image) if size >= 256 else bmp_entry(image)
        entries.append((size, payload))

    header = struct.pack("<HHH", 0, 1, len(entries))
    offset = len(header) + 16 * len(entries)
    directory, blobs = b"", b""
    for size, payload in entries:
        dim = 0 if size >= 256 else size
        directory += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32,
                                 len(payload), offset)
        offset += len(payload)
        blobs += payload
    with open(path, "wb") as f:
        f.write(header + directory + blobs)


def write_icns(path, masters):
    # PNG-backed chunks, understood by macOS 10.7+.
    chunks = {b"ic11": 32, b"ic12": 64, b"ic07": 128, b"ic13": 256,
              b"ic08": 256, b"ic14": 512, b"ic09": 512, b"ic10": 1024}
    body = b""
    for tag, size in chunks.items():
        data = png_bytes(render(masters, size))
        body += tag + struct.pack(">I", len(data) + 8) + data
    with open(path, "wb") as f:
        f.write(b"icns" + struct.pack(">I", len(body) + 8) + body)


SVG_TEMPLATE = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="100" height="100">
  <rect width="100" height="100" rx="22" ry="22" fill="#171717"/>
{shapes}
</svg>
"""

SVG_SHAPES = {
    "hermes": '  <circle cx="39" cy="61" r="19" fill="#3a3a3e"/>\n'
              '  <rect x="26" y="28" width="44" height="44" fill="#6c6c72"/>\n'
              '  <polygon points="57,26 75,58 39,58" fill="#e8e8e8"/>',
    "origin": '  <rect x="23.5" y="23.5" width="53" height="53" fill="none" stroke="#6c6c72" stroke-width="3"/>\n'
              '  <circle cx="44" cy="62" r="18" fill="#5ec8e0"/>\n'
              '  <polygon points="60,25 76,53 44,53" fill="#e8e8e8"/>',
    "foiled": '  <path d="M28 18 H62 L76 32 V82 H28 Z" fill="#e8e8e8"/>\n'
              '  <polygon points="62,18 76,32 62,32" fill="#3a3a3e"/>\n'
              '  <rect x="20" y="46" width="64" height="12" fill="#e2a65a"/>',
}

PNG_SIZES = [16, 22, 24, 32, 48, 64, 128, 256, 512]


def main():
    for name, funcs in MARKS.items():
        masters = (funcs[0](), funcs[1]())

        render(masters, 1024).save(os.path.join(OUT, f"{name}.png"), optimize=True)
        for size in PNG_SIZES:
            with open(os.path.join(OUT, f"{name}_{size}.png"), "wb") as f:
                f.write(png_bytes(render(masters, size)))

        write_ico(os.path.join(OUT, f"{name}.ico"), masters)
        write_icns(os.path.join(OUT, f"{name}.icns"), masters)
        with open(os.path.join(OUT, f"{name}.svg"), "w", encoding="utf-8") as f:
            f.write(SVG_TEMPLATE.format(shapes=SVG_SHAPES[name]))
        print(f"generated {name}: png/ico/icns/svg")

    # Contact sheet, so a design change can be eyeballed at real sizes.
    strip_sizes = [16, 24, 32, 48, 64, 128]
    pad, width = 12, sum(strip_sizes) + 12 * (len(strip_sizes) + 1)
    sheet = Image.new("RGBA", (width, 3 * (128 + pad) + pad), (245, 245, 247, 255))
    for row, name in enumerate(MARKS):
        masters = (MARKS[name][0](), MARKS[name][1]())
        x = pad
        for size in strip_sizes:
            y = pad + row * (128 + pad) + (128 - size)
            sheet.paste(render(masters, size), (x, y), render(masters, size))
            x += size + pad
    sheet.save(os.path.join(OUT, "contact-sheet.png"))
    print("generated contact-sheet.png")


if __name__ == "__main__":
    main()
