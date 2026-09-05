#!/usr/bin/env python3
"""Build the HERMES icon set from the source artwork.

    python tools/gen_icons.py     ->  assets/icons/

Sources (1000x1000 PNG, edit these to change the icons):

    assets/hermes.png       the application  - crescent
    assets/originfile.png   .origin          - anchor, the trust anchor
    assets/foiledfile.png   .foiled          - the update plan

Everything else is derived: Windows .ico, macOS .icns, and the PNG sizes the
FreeDesktop hicolor theme wants. The Rust binary embeds the results with
include_bytes!, so `hermes install-system` needs no installer.

Two details that matter for how these actually look on a desktop:

* ICO entries below 256px are written as 32bpp BMP rather than PNG. The Windows
  shell renders BMP entries more predictably at small sizes, and PNG-in-ICO is
  only reliably supported from Vista onward.
* The source art is a flat shape on an opaque plate, so a straight Lanczos
  downscale is right: there is no transparent background to fringe against and
  no gradient for sRGB averaging to muddy.
"""
import io
import os
import struct

from PIL import Image

HERE = os.path.dirname(__file__)
ASSETS = os.path.join(HERE, "..", "assets")
OUT = os.path.join(ASSETS, "icons")
os.makedirs(OUT, exist_ok=True)

SOURCES = {
    "hermes": "hermes.png",
    "origin": "originfile.png",
    "foiled": "foiledfile.png",
}

PNG_SIZES = [16, 22, 24, 32, 48, 64, 128, 256, 512]
ICO_SIZES = [16, 20, 24, 32, 48, 64, 128, 256]
ICNS_CHUNKS = {b"ic11": 32, b"ic12": 64, b"ic07": 128, b"ic13": 256,
               b"ic08": 256, b"ic14": 512, b"ic09": 512, b"ic10": 1024}


def load(name):
    path = os.path.join(ASSETS, name)
    image = Image.open(path).convert("RGBA")
    if image.width != image.height:
        raise SystemExit(f"{name} is {image.width}x{image.height}; icons must be square")
    return image


def resize(image, size):
    if image.size == (size, size):
        return image.copy()
    return image.resize((size, size), Image.LANCZOS)


def png_bytes(image):
    buf = io.BytesIO()
    image.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def bmp_entry(image):
    """A 32bpp BMP ICO entry: BITMAPINFOHEADER, bottom-up BGRA, then AND mask."""
    w, h = image.size
    header = struct.pack("<IiiHHIIiiII", 40, w, h * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    pixels = image.load()
    rows = []
    for y in range(h - 1, -1, -1):
        row = bytearray()
        for x in range(w):
            r, g, b, a = pixels[x, y]
            row += bytes((b, g, r, a))
        rows.append(bytes(row))
    # Alpha already carries transparency, so the 1bpp mask is all zeros.
    stride = ((w + 31) // 32) * 4
    return header + b"".join(rows) + b"\x00" * (stride * h)


def write_ico(path, source):
    entries = []
    for size in ICO_SIZES:
        image = resize(source, size)
        entries.append((size, png_bytes(image) if size >= 256 else bmp_entry(image)))

    header = struct.pack("<HHH", 0, 1, len(entries))
    offset = len(header) + 16 * len(entries)
    directory, blobs = b"", b""
    for size, payload in entries:
        dim = 0 if size >= 256 else size          # 0 means 256 in an ICO
        directory += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(payload), offset)
        offset += len(payload)
        blobs += payload
    with open(path, "wb") as f:
        f.write(header + directory + blobs)


def write_icns(path, source):
    body = b""
    for tag, size in ICNS_CHUNKS.items():
        data = png_bytes(resize(source, size))
        body += tag + struct.pack(">I", len(data) + 8) + data
    with open(path, "wb") as f:
        f.write(b"icns" + struct.pack(">I", len(body) + 8) + body)


def contact_sheet(images):
    """A strip per icon at real sizes, so a change can be eyeballed."""
    sizes = [16, 24, 32, 48, 64, 128]
    pad = 12
    width = sum(sizes) + pad * (len(sizes) + 1)
    height = len(images) * (128 + pad) + pad
    sheet = Image.new("RGBA", (width, height), (245, 245, 247, 255))
    for row, source in enumerate(images):
        x = pad
        for size in sizes:
            scaled = resize(source, size)
            y = pad + row * (128 + pad) + (128 - size)
            sheet.paste(scaled, (x, y), scaled)
            x += size + pad
    sheet.save(os.path.join(OUT, "contact-sheet.png"))


def main():
    rendered = []
    for name, filename in SOURCES.items():
        source = load(filename)
        rendered.append(source)

        resize(source, 1024).save(os.path.join(OUT, f"{name}.png"), optimize=True)
        for size in PNG_SIZES:
            with open(os.path.join(OUT, f"{name}_{size}.png"), "wb") as f:
                f.write(png_bytes(resize(source, size)))

        write_ico(os.path.join(OUT, f"{name}.ico"), source)
        write_icns(os.path.join(OUT, f"{name}.icns"), source)
        print(f"  {name:<7} <- {filename}   ico, icns, {len(PNG_SIZES)} png sizes")

    contact_sheet(rendered)
    print("  contact-sheet.png")


if __name__ == "__main__":
    main()
