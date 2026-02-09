// Minimal ambient types for the Web Crypto API.
// These replace the triple-slash references that were removed to keep
// the package isomorphic with `"types": []` in tsconfig.

// Use a permissive algorithm type to support ECDH, ECDSA, AES-GCM, HMAC, etc.
// without enumerating every possible algorithm parameter interface.
type AlgorithmIdentifier = { name: string; [key: string]: unknown } | string;
type BufferSource = ArrayBufferView | ArrayBuffer;
type KeyFormat = 'jwk' | 'pkcs8' | 'raw' | 'spki';
type KeyType = 'private' | 'public' | 'secret';
type KeyUsage =
  | 'decrypt'
  | 'deriveBits'
  | 'deriveKey'
  | 'encrypt'
  | 'sign'
  | 'unwrapKey'
  | 'verify'
  | 'wrapKey';

interface JsonWebKey {
  alg?: string;
  crv?: string;
  d?: string;
  dp?: string;
  dq?: string;
  e?: string;
  ext?: boolean;
  k?: string;
  key_ops?: string[];
  kty?: string;
  n?: string;
  oth?: { d?: string; r?: string; t?: string }[];
  p?: string;
  q?: string;
  qi?: string;
  use?: string;
  x?: string;
  x5c?: string[];
  x5t?: string;
  y?: string;
}

declare class CryptoKey {
  readonly algorithm: { name: string; [key: string]: unknown };
  readonly extractable: boolean;
  readonly type: KeyType;
  readonly usages: KeyUsage[];
}

interface CryptoKeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

interface SubtleCrypto {
  decrypt(
    algorithm: AlgorithmIdentifier,
    key: CryptoKey,
    data: BufferSource,
  ): Promise<ArrayBuffer>;
  deriveBits(
    algorithm: AlgorithmIdentifier,
    baseKey: CryptoKey,
    length: number,
  ): Promise<ArrayBuffer>;
  encrypt(
    algorithm: AlgorithmIdentifier,
    key: CryptoKey,
    data: BufferSource,
  ): Promise<ArrayBuffer>;
  exportKey(format: 'jwk', key: CryptoKey): Promise<JsonWebKey>;
  exportKey(
    format: Exclude<KeyFormat, 'jwk'>,
    key: CryptoKey,
  ): Promise<ArrayBuffer>;
  generateKey(
    algorithm: AlgorithmIdentifier,
    extractable: boolean,
    keyUsages: readonly KeyUsage[],
  ): Promise<CryptoKeyPair>;
  importKey(
    format: 'jwk',
    keyData: JsonWebKey,
    algorithm: AlgorithmIdentifier,
    extractable: boolean,
    keyUsages: readonly KeyUsage[],
  ): Promise<CryptoKey>;
  importKey(
    format: Exclude<KeyFormat, 'jwk'>,
    keyData: BufferSource,
    algorithm: AlgorithmIdentifier,
    extractable: boolean,
    keyUsages: readonly KeyUsage[],
  ): Promise<CryptoKey>;
  sign(
    algorithm: AlgorithmIdentifier,
    key: CryptoKey,
    data: BufferSource,
  ): Promise<ArrayBuffer>;
}

interface Crypto {
  getRandomValues<T extends ArrayBufferView | null>(array: T): T;
  readonly subtle: SubtleCrypto;
}

declare var crypto: Crypto;

// Minimal URL type for vapid.ts
declare class URL {
  constructor(input: string, base?: string | URL);
  readonly origin: string;
  readonly hostname: string;
  readonly pathname: string;
  readonly href: string;
}

// Allow dynamic import of node:crypto without type errors
declare module 'node:crypto' {
  const webcrypto: {
    subtle: SubtleCrypto;
    getRandomValues<T extends ArrayBufferView | null>(array: T): T;
    CryptoKey: typeof CryptoKey;
  };
  const subtle: SubtleCrypto;
  function getRandomValues<T extends ArrayBufferView | null>(array: T): T;
}
