# ganzua

> Recupera la contraseña de un ZIP cifrado cuando **no la tienes** — WinZip
> AES-256 y ZipCrypto.

`ganzua` es una CLI centrada en una sola cosa: **romper** un ZIP protegido del
que no conoces la contraseña, para archivos **propios o cuyo análisis estés
autorizado a realizar**. Detecta el cifrado, prueba automáticamente contraseñas
comunes y patrones típicos, y si no lo consigue te dice exactamente qué intentar
después.

> ⚠️ **Uso autorizado únicamente.** Usa `ganzua` solo contra archivos que te
> pertenezcan o para los que tengas permiso explícito. Recuperar contraseñas de
> archivos ajenos sin autorización es ilegal en la mayoría de jurisdicciones.
> Este aviso es parte del proyecto, no un trámite.

## Empezar

```bash
node ganzua.js romper archivo.zip
```

Eso es todo lo que necesitas para el caso habitual. `romper`:

1. Detecta el método de cifrado (WinZip AES-256 o ZipCrypto).
2. Prueba una **wordlist de contraseñas comunes incluida** más **patrones
   típicos**: palabra tal cual, capitalizada, `palabra+año`,
   `mayúscula+número`, `año+sufijo`.
3. Si encuentra la contraseña, la muestra. Si no, te indica cómo seguir.

```text
$ node ganzua.js romper archivo.zip
  cifrado: WinZip AES-256 (AE-2, STORE) — entrada "nota.txt"
  probando wordlist común + patrones típicos (~11000 candidatas)…

  ✔ CONTRASEÑA ENCONTRADA: «Barcelona2024»
    (7421 candidatas en 5.6 s)
```

### Obtener el contenido

`extrae` va un paso más allá: **descifra y vuelca los ficheros**. Si no le das la
contraseña, la recupera primero (como `romper`) y luego extrae:

```bash
node ganzua.js extrae archivo.zip --salida ./salida           # rompe y extrae todo
node ganzua.js extrae archivo.zip "Barcelona2024" --salida .  # con contraseña conocida
```

Descomprime **STORE, DEFLATE, BZIP2 y LZMA** (los métodos que mete 7-Zip en un
`.zip`), verifica el CRC-32 de cada fichero y protege contra _path traversal_
(zip slip). Hay una demo completa en [`examples/demo.sh`](examples/demo.sh) que
rompe ZIP reales y recupera los ficheros idénticos al original.

### ZipCrypto: ataque de texto plano (sin contraseña)

El cifrado clásico **ZipCrypto está roto**: con ~12 bytes de texto plano conocido
(8 contiguos) de una entrada se recuperan las claves internas y se descifra
**todo el archivo, sea cual sea la longitud de la contraseña**. ganzua incluye
una **implementación propia del ataque de Biham-Kocher** (port del algoritmo de
[`bkcrack`](https://github.com/kimci86/bkcrack)) — no necesita ninguna
herramienta externa:

```bash
# Conoces parte del contenido de una entrada (STORE: el contenido; DEFLATE: los
# bytes comprimidos). El ataque recupera las claves y extrae TODO sin la clave:
node ganzua.js textoplano archivo.zip --entrada 0 --plano cabecera_conocida.bin --salida ./out

# O, si ya recuperaste las claves internas, extrae directamente sin contraseña:
node ganzua.js extrae archivo.zip --claves 12345678:9abcdef0:0f1e2d3c --salida ./out
```

**El texto plano puede deducirse solo.** No hace falta darlo a mano:

```bash
# --auto: lo deduce por el tipo de fichero (cabeceras conocidas). Ideal para
# discos/appliances guardados SIN comprimir dentro del zip:
node ganzua.js textoplano vm.zip --entrada 0 --auto --salida ./out

# --conocido: tienes una copia del contenido SIN comprimir; si la entrada va en
# DEFLATE, ganzua la recomprime a varios niveles y prueba cada uno:
node ganzua.js textoplano archivo.zip --entrada 0 --conocido copia_del_fichero --salida ./out
```

`--auto` cubre cabeceras de **máquinas virtuales** (OVF/OVA, VMDK, VDI, VHD,
QCOW2) y otros formatos (PNG, OOXML…). Solo aplica a entradas **STORE** (sin
comprimir): ahí la cabecera en claro es texto plano del flujo cifrado. Como
suele aportar pocos bytes (12–40), el ataque es más lento; si tienes una copia
del contenido, `--conocido` da más texto plano y va más rápido.

> **Sobre DEFLATE.** `--conocido` recomprime el contenido conocido para casar el
> flujo comprimido, pero el deflate de cada herramienta (7-Zip, Info-ZIP) y hasta
> de cada versión de zlib difiere byte a byte, así que solo funciona si el
> archivo se creó con un deflate idéntico. Cuando no casa, usa una entrada STORE,
> o aporta los bytes comprimidos exactos con `--plano`.

**Motores del ataque.** Por defecto se usa el motor JS (paralelizado con
`worker_threads`). Si compilas el **addon nativo en C++** (N-API), el ataque se
acelera varias veces y se usa automáticamente:

```bash
npm run build:native   # compila el addon C++ (requiere compilador + node-gyp)
```

El addon es **opcional**: si no está compilado, ganzua sigue funcionando con el
motor JS. Con `--js` fuerzas el motor JS aunque el addon esté disponible, y con
`--bkcrack` delegas en `bkcrack` (si está en el `PATH`). Cuanto más texto plano
conocido (de alta entropía) proporciones, más rápido converge el ataque.

#### Atacar un ZIP enorme sin moverlo: la «sonda»

El ataque de texto plano solo necesita la cabecera de cifrado (12 B) y un trozo
del cuerpo. Así, un ZIP de **varios GB** (p. ej. con una máquina virtual) se
puede atacar compartiendo apenas **unos KB**: exportas una _sonda_ en la máquina
que tiene el archivo, la llevas a otra (o se la pasas a quien hace el ataque),
se recuperan las claves y vuelves a descifrar el archivo entero en su sitio.

```bash
# 1) En la máquina con el ZIP: exporta la sonda (metadatos + un trozo cifrado).
node ganzua.js sonda enorme.zip --bytes 4096 --salida sonda.json

# 2) Donde se hace el ataque (sin el ZIP): recupera las claves desde la sonda.
node ganzua.js ataca-sonda sonda.json --auto          # o --conocido / --plano-hex
#    → claves ZipCrypto: a1b2c3d4 e5f6a7b8 c9d0e1f2

# 3) De vuelta en la máquina con el ZIP: descifra TODO sin contraseña.
node ganzua.js extrae enorme.zip --claves a1b2c3d4:e5f6a7b8:c9d0e1f2 --salida ./out
```

### Sin descifrar nada: rescatar contenido sin contraseña

Un ZIP filtra información aunque esté cifrado, y a veces **el contenido entero
sin gastar ni un intento de contraseña**. `rescata` obtiene todo lo que el
archivo entrega sin descifrar:

- **Entradas sin cifrar.** Muchos archivos «cifrados» mezclan entradas sin
  proteger (una carpeta, un `readme`, una miniatura). Se extraen directamente.
- **Reconstrucción por CRC-32.** El directorio central guarda el CRC-32 del
  contenido **en claro** de cada entrada, aunque esté cifrada (ZipCrypto
  siempre; WinZip AES solo en su variante AE-1). Para entradas pequeñas ese CRC
  basta para reconstruir el contenido por fuerza bruta del texto plano — **sin
  tocar la contraseña ni el flujo cifrado, aunque sea AES-256**. El CRC-32 sobre
  entradas de ≤ 4 bytes es inyectivo, así que el contenido recuperado es único.

```bash
# Mapa de lo obtenible sin contraseña (no escribe nada):
node ganzua.js rescata archivo.zip --listar

# Vuelca todo lo rescatable sin contraseña (sin cifrar + reconstruible por CRC):
node ganzua.js rescata archivo.zip --salida ./out

# Alfabeto/limite para la reconstrucción por CRC-32 de entradas algo mayores:
node ganzua.js rescata archivo.zip --charset digits --maxbytes 6 --salida ./out
```

`analiza` marca, entrada por entrada, qué es obtenible sin contraseña. Esta vía
no descifra nada: no pierde tiempo probando claves.

Cuando no la encuentra con los valores por defecto:

```text
  ✗ no encontrada (11000 candidatas en 8.4 s)
  Prueba a continuación:
    • wordlist más grande:  ganzua romper archivo.zip --wordlist grande.txt
    • modo agresivo:        ganzua romper archivo.zip --agresivo
    • patrón a medida:      ganzua romper archivo.zip --patron "Palabra_%s_%d"
    • GPU / hashcat:        ganzua material archivo.zip > hash.txt   (modo 13600)
```

### Modo agresivo

`--agresivo` amplía el rango de años y añade muchos más sufijos comunes
(`123`, `!`, año actual, `00`–`99`…) sin que tengas que construir el patrón a
mano:

```bash
node ganzua.js romper archivo.zip --agresivo
```

### Reglas de mutación

`--reglas` añade transformaciones tipo hashcat sobre cada palabra: **leet**
(`secreto`→`53cr370`), **MAYÚSCULAS**, **reverso** y **separadores**
(`palabra_2024`, `palabra-123`):

```bash
node ganzua.js romper archivo.zip --reglas            # combinable con --agresivo
```

### Contraseñas con acentos (ZIP antiguos, CP437)

Los ZIP modernos usan UTF-8, pero los antiguos (Info-ZIP / Windows OEM) suelen
codificar la contraseña en **CP437**. Si una contraseña con acentos o `ñ` no
aparece, reintenta con `--cp437`:

```bash
node ganzua.js romper archivo.zip --cp437
node ganzua.js verifica --cp437 archivo.zip "contraseña"
```

### Tu propia wordlist

```bash
node ganzua.js romper archivo.zip --wordlist rockyou.txt
```

Los patrones se siguen aplicando sobre las palabras de tu wordlist. Para listas
grandes de calidad, [SecLists](https://github.com/danielmiessler/SecLists)
(licencia MIT) es un buen punto de partida.

### Patrones a medida

`--patron` genera candidatas desde una plantilla con marcadores:

| Marcador | Expande a              |
| -------- | ---------------------- |
| `%s`     | palabra de la wordlist |
| `%c`     | palabra capitalizada   |
| `%y`     | año (rango del modo)   |
| `%n`     | dígito `0`–`9`         |
| `%D`     | número `00`–`99`       |

```bash
node ganzua.js romper archivo.zip --patron "Empresa_%s_%y"
```

### Ataque por máscara

`--mascara` prueba todas las combinaciones de una máscara estilo hashcat, útil
cuando conoces la estructura de la contraseña:

| Token | Conjunto         |
| ----- | ---------------- |
| `?l`  | `a`–`z`          |
| `?u`  | `A`–`Z`          |
| `?d`  | `0`–`9`          |
| `?s`  | símbolos         |
| `?a`  | todo lo anterior |
| `??`  | literal `?`      |

El resto de caracteres son literales:

```bash
node ganzua.js romper archivo.zip --mascara "Casa?d?d?d?d"   # Casa0000…Casa9999
```

### Búsquedas largas: checkpoint y Ctrl+C

Para ataques largos, `--checkpoint <fichero>` guarda el progreso periódicamente
y reanuda desde ahí si vuelves a lanzarlo con el mismo fichero. **Ctrl+C**
detiene la búsqueda de forma limpia, muestra un resumen (candidatas probadas,
posición, tiempo) y guarda el checkpoint:

```bash
node ganzua.js romper archivo.zip --agresivo --checkpoint progreso.json
# … Ctrl+C …
#   ⏸ interrumpida: 84000 candidatas probadas (posición 84000) en 35.2 s
#   checkpoint guardado en progreso.json — reanuda con: --checkpoint progreso.json
node ganzua.js romper archivo.zip --agresivo --checkpoint progreso.json  # reanuda
```

## Otros formatos (7-Zip, RAR)

ganzua ataca **ZIP** de forma nativa (AES-256 por fuerza bruta y ZipCrypto por
Biham-Kocher). Para **7-Zip** y **RAR** —que requieren un parser propio fuera del
alcance nativo— `formato` identifica el archivo y te da la vía establecida:

```bash
node ganzua.js formato archivo.7z
#   7-Zip (AES-256). Extrae el hash y crackea con hashcat modo 11600:
#     7z2john archivo.7z > hash.txt && hashcat -m 11600 hash.txt wordlist.txt
```

| Formato | Cifrado   | Vía                                 |
| ------- | --------- | ----------------------------------- |
| ZIP     | AES-256   | **nativo** (`romper` / `extrae`)    |
| ZIP     | ZipCrypto | **nativo** (`romper`, `textoplano`) |
| 7-Zip   | AES-256   | `7z2john` + `hashcat -m 11600`      |
| RAR5    | AES-256   | `rar2john` + `hashcat -m 13000`     |
| RAR3    | AES-128   | `rar2john` + `hashcat -m 12500`     |

Si pasas un no-ZIP a `romper`/`extrae`, ganzua detecta el formato y te indica
qué usar en vez de fallar sin más.

## Comandos

`romper` es el comando principal. El resto son de **apoyo y depuración**:

| Comando       | Para qué sirve                                                           |
| ------------- | ------------------------------------------------------------------------ |
| **`romper`**  | **Encuentra la contraseña sin conocerla (wordlist + patrones).**         |
| **`extrae`**  | **Descifra y vuelca el contenido** (rompe primero si hace falta).        |
| `textoplano`  | Ataque de texto plano ZipCrypto (Biham-Kocher **nativo**).               |
| `sonda`       | Exporta un paquete mínimo (KB) para atacar un ZIP enorme sin moverlo.    |
| `ataca-sonda` | Recupera las claves ZipCrypto desde una sonda (sin el ZIP completo).     |
| **`rescata`** | **Obtiene contenido SIN contraseña** (entradas sin cifrar + CRC-32).     |
| `formato`     | Identifica el formato (ZIP/7z/RAR/…) e indica cómo atacarlo.             |
| `analiza`     | Cifrado, salt/verificador/auth y qué es obtenible sin contraseña.        |
| `material`    | Emite el hash `$zip2$` para `hashcat -m 13600` / John `zip2john`.        |
| `verifica`    | Prueba una única contraseña candidata contra el archivo.                 |
| `busca`       | Búsqueda de bajo nivel: como `romper`, pero exige wordlist o `--patron`. |

```bash
node ganzua.js analiza  archivo.zip
node ganzua.js material archivo.zip > hash.txt
node ganzua.js verifica archivo.zip "Candidata_2024"
node ganzua.js busca    archivo.zip wordlist.txt
```

Todos aceptan `--json` para salida estructurada, `--entrada N` para elegir la
entrada a atacar, `--todas` para operar sobre todas las entradas cifradas
(`verifica`/`material`; en `romper` indica qué entradas abre la contraseña
encontrada), y `--help` / `--version`.

## Cómo funciona

- **WinZip AES (AE-1/AE-2), 128/192/256 bits**: derivación de clave
  PBKDF2-HMAC-SHA1 (1000 iteraciones). ganzua descarta contraseñas erróneas
  comparando el verificador
  de 2 bytes (rechazo en microsegundos) y confirma la correcta con el código de
  autenticación HMAC-SHA1 de 10 bytes — sin necesidad de descifrar todo el
  contenido. Cero falsos positivos.
- **ZipCrypto** (PKWARE tradicional): keystream de 96 bits. Rechazo rápido por
  el _check byte_ de la cabecera (12 bytes) y confirmación definitiva
  descifrando el cuerpo y comparando el CRC-32. Además, ataque de **texto plano
  conocido (Biham-Kocher) nativo** que recupera las claves internas y descifra
  todo sin la contraseña (ver arriba).
- Parsea la cabecera local del ZIP directamente, usando el directorio central
  como fuente autoritativa de tamaños y flags (fiable incluso con _data
  descriptor_).

El cuello de botella en AES-256 es PBKDF2 (~1k intentos/s por hilo, según la
CPU). `romper` y `busca` **paralelizan con `worker_threads`** por defecto: usan
tantos hilos como CPUs y escalan casi linealmente (≈3× en 4 núcleos). Ajusta
con `--hilos N` o desactiva con `--secuencial`.

### hashcat (GPU)

Para ir más rápido con GPU, `--hashcat` delega en hashcat (modo 13600) si está
en el `PATH`, y si no, recurre automáticamente al motor propio:

```bash
node ganzua.js romper archivo.zip --hashcat                 # diccionario+patrones
node ganzua.js romper archivo.zip --hashcat --mascara "Casa?d?d?d?d"
```

La sintaxis de `--mascara` de ganzua es la misma que la de hashcat, así que la
máscara se pasa tal cual. También puedes generar el hash y usar hashcat a mano:
`ganzua material archivo.zip > hash.txt && hashcat -m 13600 hash.txt rockyou.txt`.

## Requisitos

- Node.js 18+. Dependencias en tiempo de ejecución mínimas: `seek-bzip` y
  `lzma` (para descomprimir BZIP2/LZMA al extraer; el resto es nativo de Node).
- Para regenerar los fixtures de test: Python 3 con
  [`pyzipper`](https://pypi.org/project/pyzipper/) y el comando `zip` del
  sistema.
- `hashcat` es opcional, solo para acelerar por GPU con la salida de `material`.
- El **addon nativo en C++** (acelera el ataque de texto plano ZipCrypto) es
  opcional: para compilarlo hacen falta un compilador de C++ y `node-gyp`
  (`npm run build:native`). Sin él, ganzua usa el motor JS.

## Desarrollo y tests

```bash
npm test                 # motor JS
npm run build:native && npm test   # además, ejercita el addon C++ (e2e nativo)
```

`pretest` regenera los fixtures cifrados con `pyzipper` y el `zip` del sistema.
Si falta `pyzipper`:

```bash
pip install --break-system-packages pyzipper
```

El test **`test/blind-crack.test.js`** es la línea roja del proyecto: genera una
contraseña aleatoria nueva en cada ejecución y comprueba que `romper` la
encuentra sin que se le diga cuál es. Si ese test se rompe, la herramienta ha
dejado de cumplir su función principal.

## Licencia

Código bajo licencia **MIT** (ver [`LICENSE`](LICENSE)). La wordlist incluida
está en **dominio público (CC0)**; su origen se documenta en
[`data/wordlist-comunes.README.md`](data/wordlist-comunes.README.md).

---

_Hecho para uso forense y CTF. Solo para archivos que te pertenezcan o cuyo
análisis estés autorizado a realizar._
