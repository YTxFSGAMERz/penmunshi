import io

import pytest
from PIL import Image

from penmunshi.verify.catalog import Catalog


@pytest.fixture(scope="session")
def catalog() -> Catalog:
    return Catalog.load()


@pytest.fixture()
def png_bytes() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (64, 32), (10, 20, 30)).save(buf, format="PNG")
    return buf.getvalue()
