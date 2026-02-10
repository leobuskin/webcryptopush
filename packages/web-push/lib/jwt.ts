import { base64UrlEncode, jsonToBase64Url, utf8Encode } from './encoding.js';
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
  const headerStr = jsonToBase64Url({
    typ: 'JWT',
    alg: 'ES256',
  } satisfies JwtHeader);

  const payloadStr = jsonToBase64Url({
    iat: Math.floor(Date.now() / 1000),
    ...payload,
  } satisfies JwtPayload);

  const dataStr = `${headerStr}.${payloadStr}`;

  const signature = await crypto.subtle.sign(
    ES256,
    key,
    utf8Encode(dataStr),
  );

  return `${dataStr}.${base64UrlEncode(new Uint8Array(signature))}`;
}
