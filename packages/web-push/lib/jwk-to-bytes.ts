import { base64UrlDecode } from './encoding.js';
import { invariant } from './utils.js';

export function ecJwkToBytes(jwk: JsonWebKey) {
  invariant(jwk.x, 'jwk.x is missing');
  invariant(jwk.y, 'jwk.y is missing');

  const xBytes = base64UrlDecode(jwk.x);
  const yBytes = base64UrlDecode(jwk.y);

  // ANSI X9.62 point encoding - 0x04 for uncompressed
  const result = new Uint8Array(1 + xBytes.length + yBytes.length);
  result[0] = 0x04;
  result.set(xBytes, 1);
  result.set(yBytes, 1 + xBytes.length);
  return result;
}
