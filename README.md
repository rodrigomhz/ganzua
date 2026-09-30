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

## Comandos

`romper` es el comando principal. El resto son de **apoyo y depuración**:

| Comando      | Para qué sirve                                                           |
| ------------ | ------------------------------------------------------------------------ |
| **`romper`** | **Encuentra la contraseña sin conocerla (wordlist + patrones).**         |
| `analiza`    | Detecta el cifrado y muestra salt, verificador y auth por entrada.       |
| `material`   | Emite el hash `$zip2$` para `hashcat -m 13600` / John `zip2john`.        |
| `verifica`   | Prueba una única contraseña candidata contra el archivo.                 |
| `busca`      | Búsqueda de bajo nivel: como `romper`, pero exige wordlist o `--patron`. |

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
  descifrando el cuerpo y comparando el CRC-32.
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

- Node.js 18+ (sin dependencias de terceros en tiempo de ejecución).
- Para regenerar los fixtures de test: Python 3 con
  [`pyzipper`](https://pypi.org/project/pyzipper/) y el comando `zip` del
  sistema.
- `hashcat` es opcional, solo para acelerar por GPU con la salida de `material`.

## Desarrollo y tests

```bash
npm test
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
