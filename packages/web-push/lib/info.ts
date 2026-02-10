import { concatBytes, utf8Encode } from './encoding.js';
import { encodeUint16BE } from './utils.js';

export function createInfo(
  clientPublic: Uint8Array,
  serverPublic: Uint8Array,
  type: 'aesgcm' | 'nonce',
) {
  return concatBytes([
    utf8Encode(`Content-Encoding: ${type}\0`),
    utf8Encode('P-256\0'),
    encodeUint16BE(clientPublic.byteLength),
    clientPublic,
    encodeUint16BE(serverPublic.byteLength),
    serverPublic,
  ]);
}

export function createAuthInfo() {
  return utf8Encode('Content-Encoding: auth\0');
}
