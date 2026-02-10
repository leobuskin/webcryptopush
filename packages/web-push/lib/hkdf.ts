import { crypto } from './isomorphic-crypto.js';

function createHMAC(data: BufferSource) {
  const keyData = data.byteLength === 0 ? new Uint8Array(32) : data;

  const keyPromise = crypto.subtle.importKey(
    'raw',
    keyData,
    {
      name: 'HMAC',
      hash: 'SHA-256',
    },
    false,
    ['sign'],
  );

  return {
    hash: async (input: BufferSource) => {
      const k = await keyPromise;
      return crypto.subtle.sign('HMAC', k, input);
    },
  };
}

export async function hkdf(salt: BufferSource, ikm: BufferSource) {
  const prkhPromise = createHMAC(salt)
    .hash(ikm)
    .then((prk) => createHMAC(prk));

  return {
    expand: async (info: BufferSource, len: number) => {
      const infoBytes =
        info instanceof Uint8Array ? info : new Uint8Array(info as ArrayBuffer);
      const input = new Uint8Array(infoBytes.length + 1);
      input.set(infoBytes);
      input[infoBytes.length] = 1;
      const prkh = await prkhPromise;
      const hash = await prkh.hash(input);
      return hash.slice(0, len);
    },
  };
}
