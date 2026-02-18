#!/usr/bin/env bash
#
# fetch-freedoom.sh - Download Freedoom WADs from GitHub releases
#
# Usage: scripts/kairos.sh deps freedoom

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/third_party/freedoom"
OUT_WAD="${OUT_DIR}/doom1.wad"

mkdir -p "$OUT_DIR"
export OUT_DIR

python3 - <<'PY'
import io
import json
import os
import sys
import urllib.request
import zipfile

repo = "https://api.github.com/repos/freedoom/freedoom/releases/latest"
with urllib.request.urlopen(repo) as resp:
    data = json.load(resp)

assets = data.get("assets", [])
zip_asset = None
for asset in assets:
    name = asset.get("name", "")
    if name.endswith(".zip") and "freedoom" in name:
        zip_asset = asset
        break

if not zip_asset:
    print("freedoom: no zip asset found in latest release", file=sys.stderr)
    sys.exit(1)

url = zip_asset.get("browser_download_url")
if not url:
    print("freedoom: missing download url", file=sys.stderr)
    sys.exit(1)

print(f"freedoom: downloading {zip_asset['name']}")
with urllib.request.urlopen(url) as resp:
    blob = resp.read()

zf = zipfile.ZipFile(io.BytesIO(blob))

wanted = {
    "freedoom1.wad": "doom1.wad",
    "freedoom2.wad": "doom2.wad",
    "freedm.wad": "freedm.wad",
}

out_dir = os.environ.get("OUT_DIR")
if not out_dir:
    print("freedoom: OUT_DIR not set", file=sys.stderr)
    sys.exit(1)

found = False
for name in zf.namelist():
    base = os.path.basename(name)
    if base in wanted:
        out_path = os.path.join(out_dir, wanted[base])
        with zf.open(name) as src, open(out_path, "wb") as dst:
            dst.write(src.read())
        print(f"freedoom: wrote {out_path}")
        if base == "freedoom1.wad":
            found = True

if not found:
    print("freedoom: freedoom1.wad not found in zip", file=sys.stderr)
    sys.exit(1)
PY
