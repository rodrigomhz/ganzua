#!/usr/bin/env python3
"""Genera fixtures ZIP cifrados con WinZip AES usando pyzipper.

Uso: gen_aes.py <out_dir> <specs_json>
Cada spec: {file, entry, method: store|deflate, nbits, password, content}
"""
import json
import os
import sys

try:
    import pyzipper
except ImportError:
    sys.stderr.write(
        "ganzua(fixtures): falta pyzipper. Instálalo con:\n"
        "  pip install --break-system-packages pyzipper\n"
    )
    sys.exit(3)

def main():
    out_dir = sys.argv[1]
    specs = json.loads(sys.argv[2])
    os.makedirs(out_dir, exist_ok=True)
    for s in specs:
        comp = pyzipper.ZIP_DEFLATED if s["method"] == "deflate" else pyzipper.ZIP_STORED
        dest = os.path.join(out_dir, s["file"])
        with pyzipper.AESZipFile(dest, "w", compression=comp, encryption=pyzipper.WZ_AES) as z:
            z.setpassword(s["password"].encode("utf-8"))
            z.setencryption(pyzipper.WZ_AES, nbits=int(s.get("nbits", 256)))
            z.writestr(s["entry"], s["content"].encode("utf-8"))
    print(f"gen_aes.py: {len(specs)} fixtures AES en {out_dir}")

if __name__ == "__main__":
    main()
