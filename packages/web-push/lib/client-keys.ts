import { base64UrlDecode, base64UrlEncode } from './encoding.js';
import { crypto } from './isomorphic-crypto.js';
import type { PushSubscription } from './types.js';
import { invariant } from './utils.js';

export async function deriveClientKeys(sub: PushSubscription) {
  const bytes = base64UrlDecode(sub.keys.p256dh);

  invariant(
    bytes.byteLength === 65,
    `Invalid p256dh key: expected 65 bytes (uncompressed P-256 point), got ${bytes.byteLength}`,
  );

  const authSecretBytes = base64UrlDecode(sub.keys.auth);

  invariant(
    authSecretBytes.byteLength === 16,
    `Invalid auth secret: expected 16 bytes, got ${authSecretBytes.byteLength}`,
  );

  const publicJwk = {
    kty: 'EC',
    crv: 'P-256',
    x: base64UrlEncode(bytes.slice(1, 33)),
    y: base64UrlEncode(bytes.slice(33, 65)),
    ext: true,
  } satisfies JsonWebKey;

  return {
    publicKeyBytes: new Uint8Array(bytes),
    publicKey: await crypto.subtle.importKey(
      'jwk',
      publicJwk,
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      [],
    ),
    authSecretBytes,
  };
}
