"""Make a small test PNG for the live HTTP test."""
import io
import sys
from pathlib import Path
import numpy as np
from PIL import Image

arr = np.random.default_rng(42).integers(0, 255, (256, 256, 3), dtype=np.uint8)
out = Path(sys.argv[1] if len(sys.argv) > 1 else "test_image.png")
Image.fromarray(arr).save(out, format="PNG")
print(f"wrote {out} ({out.stat().st_size} bytes)")
