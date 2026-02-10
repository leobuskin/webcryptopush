import { stringToUint8Array } from 'uint8array-extras';
import { objectToBase64UrlSafe, toBase64UrlSafe } from './base64.js';
import { crypto } from './isomorphic-crypto.js';

const ES256 = {
  name: 'ECDSA',
  namedCurve: 'P-256',
  hash: { name: 'SHA-256' },
} as const;

interface JwtHeader {
  typ: 'JWT';
  alg: 'ES256';
  [key: string]: unknown;
}

type JwtPayload = {
  /** Issuer */
  iss?: string;

  /** Subject */
  sub?: string;

  /** Audience */
  aud?: string | string[];

  /** Expiration Time */
  exp?: number;

  /** Not Before */
  nbf?: number;

  /** Issued At */
  iat?: number;

  /** JWT ID */
  jti?: string;

  [key: string]: unknown;
};

export async function sign(payload: JwtPayload, key: CryptoKey) {
  const headerStr = objectToBase64UrlSafe<JwtHeader>({
    typ: 'JWT',
    alg: 'ES256',
  });

  const payloadStr = objectToBase64UrlSafe<JwtPayload>({
    iat: Math.floor(Date.now() / 1000),
    ...payload,
  });

  const dataStr = `${headerStr}.${payloadStr}`;

  const signature = await crypto.subtle.sign(
    ES256,
    key,
    stringToUint8Array(dataStr),
  );

  return `${dataStr}.${toBase64UrlSafe(signature)}`;
}
