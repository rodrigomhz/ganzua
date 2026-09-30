'use strict';

// Codificación de contraseñas a bytes. Los ZIP modernos usan UTF-8, pero los
// antiguos (Info-ZIP / Windows OEM) suelen usar CP437, así que una contraseña
// con caracteres no-ASCII (acentos, ñ…) puede necesitar CP437 para acertar.

// Mitad alta de CP437 (bytes 128..255) en Unicode.
const CP437_HIGH =
  'ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ';

const CP437_REV = (() => {
  const m = new Map();
  for (let i = 0; i < CP437_HIGH.length; i++) m.set(CP437_HIGH[i], 128 + i);
  return m;
})();

// Codifica una cadena a bytes CP437, o null si algún carácter no es representable.
function encodeCp437(str) {
  const bytes = [];
  for (const ch of str) {
    const cp = ch.codePointAt(0);
    if (cp < 128) {
      bytes.push(cp);
      continue;
    }
    const b = CP437_REV.get(ch);
    if (b === undefined) return null;
    bytes.push(b);
  }
  return Buffer.from(bytes);
}

// Decodifica bytes CP437 a una cadena Unicode (los <128 son ASCII).
function decodeCp437(buf) {
  let out = '';
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    out += b < 128 ? String.fromCharCode(b) : CP437_HIGH[b - 128];
  }
  return out;
}

// Decodifica el nombre de una entrada ZIP: UTF-8 si el bit 11 (EFS) está activo;
// si no, CP437 (el valor por defecto del APPNOTE para nombres no-EFS). Para
// nombres ASCII ambas dan lo mismo.
function decodeZipName(buf, flags) {
  if (flags & 0x800) return buf.toString('utf8');
  // ¿Todo ASCII? entonces da igual.
  let ascii = true;
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] >= 128) {
      ascii = false;
      break;
    }
  }
  return ascii ? buf.toString('latin1') : decodeCp437(buf);
}

// Convierte una contraseña a bytes según la codificación. Un Buffer se devuelve
// tal cual. Para 'cp437' no representable, cae a UTF-8.
function toBytes(password, encoding = 'utf8') {
  if (Buffer.isBuffer(password)) return password;
  if (encoding === 'cp437') {
    const b = encodeCp437(password);
    return b || Buffer.from(password, 'utf8');
  }
  return Buffer.from(password, 'utf8');
}

module.exports = { encodeCp437, decodeCp437, decodeZipName, toBytes, CP437_HIGH };
