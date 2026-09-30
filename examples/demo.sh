#!/usr/bin/env bash
# Demo de ganzua: crea ZIP cifrados reales (7-Zip / Info-ZIP), los ROMPE sin
# conocer la contraseña y OBTIENE los ficheros, verificando que el contenido
# recuperado coincide con el original.
#
# Requiere: node, y para crear los fixtures 7z / zip. Uso autorizado únicamente.
set -u
GZ="$(cd "$(dirname "$0")/.." && pwd)/ganzua.js"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT; cd "$WORK"
pass=0; fail=0
ok(){ echo "  ✔ $1"; pass=$((pass+1)); }
ko(){ echo "  ✗ $1"; fail=$((fail+1)); }

# Contenido original (variado para que comprima)
printf 'Documento secreto de la empresa.\nDatos: %s\n' "$(seq 1 40 | tr '\n' ' ')" > original.txt
ORIG_SHA=$(sha256sum original.txt | cut -d' ' -f1)

demo_crack(){ # $1=desc $2=zipfile $3=passwordEsperada
  echo "== $1 =="
  # ROMPER (sin decir la contraseña)
  got=$(node "$GZ" romper --json "$2" 2>/dev/null | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{console.log(JSON.parse(s).contrasena||"")}catch{console.log("")}})')
  if [ "$got" = "$3" ]; then ok "romper encontró la contraseña: «$got»"; else ko "romper: esperaba «$3», obtuvo «$got»"; return; fi
  # EXTRAER y comparar el contenido
  rm -rf out; mkdir out
  node "$GZ" extrae "$2" "$got" --salida out >/dev/null 2>&1
  if [ "$(sha256sum out/original.txt 2>/dev/null | cut -d' ' -f1)" = "$ORIG_SHA" ]; then ok "extrae recuperó el fichero idéntico al original"; else ko "el contenido extraído no coincide"; fi
}

if command -v 7z >/dev/null 2>&1; then
  7z a -tzip -mem=AES256   -mm=Deflate -pBarcelona2024 aes_deflate.zip original.txt >/dev/null 2>&1
  7z a -tzip -mem=AES256   -mm=BZip2   -pBarcelona2024 aes_bzip2.zip   original.txt >/dev/null 2>&1
  7z a -tzip -mem=AES256   -mm=LZMA    -pBarcelona2024 aes_lzma.zip     original.txt >/dev/null 2>&1
  7z a -tzip -mem=ZipCrypto -mm=Deflate -pBarcelona2024 zc_deflate.zip  original.txt >/dev/null 2>&1
  demo_crack "7-Zip · ZIP AES-256 · DEFLATE" aes_deflate.zip Barcelona2024
  demo_crack "7-Zip · ZIP AES-256 · BZIP2"   aes_bzip2.zip   Barcelona2024
  demo_crack "7-Zip · ZIP AES-256 · LZMA"    aes_lzma.zip    Barcelona2024
  demo_crack "7-Zip · ZIP ZipCrypto · DEFLATE" zc_deflate.zip Barcelona2024
else
  echo "(7z no disponible: se omiten los ejemplos de 7-Zip)"
fi

if command -v zip >/dev/null 2>&1; then
  zip -q -e -P password123 infozip_zc.zip original.txt
  demo_crack "Info-ZIP · ZipCrypto" infozip_zc.zip password123
fi

# ATAQUE DE TEXTO PLANO (Biham-Kocher nativo): sin contraseña, con texto plano
# conocido de una entrada STORE.
if command -v zip >/dev/null 2>&1; then
  echo "== ZipCrypto · ataque de texto plano (sin contraseña) =="
  head -c 400 /dev/urandom > known.bin
  cp known.bin conocido.bin
  zip -q -0 -e -P "una-clave-larguisima-imposible-de-fuerza-bruta-9Z" tp.zip known.bin
  rm -rf out; mkdir out
  node "$GZ" textoplano tp.zip --plano conocido.bin --salida out >/dev/null 2>&1
  if cmp -s known.bin out/known.bin; then ok "textoplano recuperó el contenido sin la contraseña"; else ko "textoplano falló"; fi
fi

# RESCATE SIN DESCIFRAR: reconstruye el contenido de una entrada pequeña desde
# el CRC-32 en claro, sin la contraseña y sin descifrar ni un byte.
if command -v zip >/dev/null 2>&1; then
  echo "== ZipCrypto · rescate por CRC-32 (sin descifrar) =="
  printf 'PIN' > pin.txt
  zip -q -0 -e -j -P "clave-larguisima-irrelevante-para-el-CRC-9Z" crc.zip pin.txt
  rm -rf out; mkdir out
  node "$GZ" rescata crc.zip --salida out >/dev/null 2>&1
  if [ "$(cat out/pin.txt 2>/dev/null)" = "PIN" ]; then ok "rescata reconstruyó el contenido por CRC-32 sin la contraseña"; else ko "rescata falló"; fi
fi

echo "== RESULTADO: $pass OK, $fail fallos =="
[ "$fail" -eq 0 ]
