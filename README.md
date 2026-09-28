# ganzua

> ZIP encryption analyzer and attack tool — AES-256 & ZipCrypto

CLI for forensic analysis of encrypted ZIP archives. Supports encryption detection, material extraction for hashcat, candidate verification, and pattern-based search.

## Commands

| Command    | What it does |
|------------|-------------|
| `analiza`  | Detects encryption method (ZipCrypto vs AES-256), reports salt + verifier bytes |
| `material` | Extracts AES salt and verifier for use with hashcat mode 13600 |
| `verifica` | Tests a single password candidate against the archive (~2.8k checks/s) |
| `busca`    | Pattern or wordlist search (e.g. `Palabra_Palabra_YYYY` space) |

## Usage

```bash
node ganzua.js analiza   archivo.zip
node ganzua.js material  archivo.zip > hash.txt
node ganzua.js verifica  archivo.zip "Candidata_2024"
node ganzua.js busca     archivo.zip wordlist.txt
node ganzua.js busca     archivo.zip --patron "Palabra_%s_%d"
```

## Why it exists

`zip2json` + hashcat mode 13600 fails silently on ZIPs with central directory entries > 8 MB — the tool emits a `ZFILE` token that hashcat cannot process.

ganzua works around this by:
1. Parsing the ZIP local file header directly (bypasses zip2john's size limit)
2. Extracting only the AES salt (16 B) + verifier (10 B) — enough to test candidates without full decryption
3. Wrapping hashcat with a patched verifier-only kernel and `--self-test-disable`

## Technical notes

- **AES-256 (WinZip AES / AE-2)**: PBKDF2-SHA1 key derivation; verifier = HMAC-SHA1 of known plaintext. Salt + verifier is all you need to reject wrong passwords in ~microseconds.
- **ZipCrypto**: classical 96-bit PRNG; plaintext attack viable with ≥12 known bytes of a stored file.
- Hashcat kernel cache must be cleared after patching (`kernels\` directory).

## Requirements

- Node.js 18+
- hashcat (optional, for GPU acceleration)

---

*Built for forensic and CTF use. Intended for archives you own or are authorized to analyze.*
