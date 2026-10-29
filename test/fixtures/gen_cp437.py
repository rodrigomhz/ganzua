#!/usr/bin/env python3
"""Genera un ZIP ZipCrypto cuya contraseña está codificada en CP437.

Node no puede pasar un byte 0xa4 suelto por argv (lo re-codifica a UTF-8), pero
Python sí acepta argv en bytes en POSIX, así que la contraseña llega tal cual.

Uso: gen_cp437.py <out_dir>
Contraseña: "contraseña" en CP437 -> b"contrase\xa4a".
"""
import os
import subprocess
import sys
import tempfile

def main():
    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)
    pw = b"contrase\xa4a"  # "contraseña" en CP437 (ñ = 0xa4)
    tmp = tempfile.mkdtemp()
    src = os.path.join(tmp, "cp437.txt")
    with open(src, "wb") as f:
        f.write("contenido con contrasena CP437\n".encode("utf-8"))
    dest = os.path.join(out_dir, "zipcrypto-cp437.zip")
    if os.path.exists(dest):
        os.remove(dest)
    # argv en bytes: 0xa4 se preserva.
    subprocess.run(
        [b"zip", b"-q", b"-0", b"-e", b"-j", b"-P", pw, dest.encode(), src.encode()],
        check=True,
    )
    print(f"gen_cp437.py: creado {dest}")

if __name__ == "__main__":
    main()
