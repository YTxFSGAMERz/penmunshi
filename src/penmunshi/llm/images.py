from __future__ import annotations

import io


def prepare_image(data: bytes, max_side: int = 1600) -> bytes:
    """Downscale big screenshots so the vision pass stays fast on a laptop GPU.

    Returns PNG bytes (lossless keeps small text legible). Falls back to the original
    bytes if Pillow cannot read the file.
    """
    try:
        from PIL import Image

        with Image.open(io.BytesIO(data)) as im:
            im = im.convert("RGB")
            if max(im.size) > max_side:
                im.thumbnail((max_side, max_side))
            buf = io.BytesIO()
            im.save(buf, format="PNG", optimize=True)
            return buf.getvalue()
    except Exception:
        return data
