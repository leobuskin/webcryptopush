import { stringToUint8Array } from 'uint8array-extras';
import { objectToBase64UrlSafe, toBase64UrlSafe } from './base64.js';
import { crypto } from './isomorphic-crypto.js';
export type JwtAlgorithm =
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'HS256'
  | 'HS384'
  | 'HS512'
  | 'RS256'
  | 'RS384'
  | 'RS512';

export const algorithms: Record<JwtAlgorithm, AlgorithmIdentifier> = {
  ES256: { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } },
  ES384: { name: 'ECDSA', namedCurve: 'P-384', hash: { name: 'SHA-384' } },
  ES512: { name: 'ECDSA', namedCurve: 'P-521', hash: { name: 'SHA-512' } },
  HS256: { name: 'HMAC', hash: { name: 'SHA-256' } },
  HS384: { name: 'HMAC', hash: { name: 'SHA-384' } },
  HS512: { name: 'HMAC', hash: { name: 'SHA-512' } },
  RS256: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
  RS384: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-384' } },
  RS512: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-512' } },
};

interface JwtHeader {
  typ: 'JWT';
  alg: JwtAlgorithm;
  kid?: string;
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

export async function sign(
  payload: JwtPayload,
  key: CryptoKey,
  options: {
    algorithm: JwtAlgorithm;
    kid?: string;
  },
) {
  const headerStr = objectToBase64UrlSafe<JwtHeader>({
    typ: 'JWT',
    alg: options.algorithm,
    ...(options.kid && { kid: options.kid }),
  });

  const payloadStr = objectToBase64UrlSafe<JwtPayload>({
    iat: Math.floor(Date.now() / 1000),
    ...payload,
  });

  const dataStr = `${headerStr}.${payloadStr}`;

  const signature = await crypto.subtle.sign(
    algorithms[options.algorithm],
    key,
    stringToUint8Array(dataStr),
  );

  return `${dataStr}.${toBase64UrlSafe(signature)}`;
}
