# wordlist-comunes.txt — origen y licencia

## Qué es

Una lista compacta (~350 entradas) de contraseñas muy comunes, orientada a
recuperar archivos ZIP propios o cuyo análisis estés autorizado a realizar.
Combina:

- Secuencias numéricas y de teclado clásicas (`123456`, `qwerty`, `1q2w3e4r`…).
- Palabras y nombres frecuentes en **español e inglés** (`contraseña`, `admin`,
  `password`, nombres de pila comunes, equipos, meses, estaciones…).
- Términos culturales y de marca habituales en contraseñas reales.

Es deliberadamente pequeña para que `ganzua romper` la recorra en segundos como
primer intento. Para ataques serios usa una wordlist grande con
`ganzua romper archivo.zip --wordlist grande.txt` (por ejemplo, listas de
[SecLists](https://github.com/danielmiessler/SecLists), licencia MIT).

## Origen

Compilada **desde cero por el proyecto ganzua**. Las entradas son hechos de
dominio público bien documentados en análisis de filtraciones y estudios de
contraseñas más usadas (por ejemplo, los rankings anuales de contraseñas más
comunes). No se ha copiado ningún archivo de un tercero: es una recopilación
propia de cadenas que aparecen de forma recurrente en cualquier análisis de
este tipo.

## Licencia

Dominio público — **CC0 1.0 Universal**
(<https://creativecommons.org/publicdomain/zero/1.0/>).

Puedes usar, modificar y redistribuir esta lista sin restricción. Se ofrece
"tal cual", sin garantías.

## Formato

Una contraseña candidata por línea. Las líneas vacías se ignoran. No hay
sintaxis de comentarios: cada línea se prueba literalmente, de modo que
cualquier contraseña es representable (incluidas las que empezarían por `#`).
