const impl = globalThis.crypto
  ? globalThis.crypto
  : await import('node:crypto');

const hasWebcrypto = 'webcrypto' in impl;
const wc = hasWebcrypto ? (impl as { webcrypto: Crypto }).webcrypto : undefined;

// we only export the values we use to keep things simple, we dont need a fully
// cross platform compatible crypto library
export const crypto: {
  getRandomValues: <T extends Uint8Array>(array: T) => T;
  subtle: SubtleCrypto;
} = {
  getRandomValues: <T extends Uint8Array>(array: T) =>
    wc ? wc.getRandomValues(array) : impl.getRandomValues(array),
  subtle: wc ? wc.subtle : impl.subtle,
};
