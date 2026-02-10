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
      return new Uint8Array(await crypto.subtle.sign('HMAC', k, input));
    },
  };
}

export async function hkdf(salt: BufferSource, ikm: BufferSource) {
  const prkhPromise = createHMAC(salt)
    .hash(ikm)
    .then((prk) => createHMAC(prk));

  return {
    expand: async (info: Uint8Array, len: number) => {
      const input = new Uint8Array(info.length + 1);
      input.set(info);
      input[info.length] = 1;
      const prkh = await prkhPromise;
      const hash = await prkh.hash(input);
      return hash.subarray(0, len);
    },
  };
}
