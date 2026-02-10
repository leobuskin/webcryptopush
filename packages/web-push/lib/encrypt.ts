import { concatUint8Arrays } from 'uint8array-extras';
import { deriveClientKeys } from './client-keys.js';
import { hkdf } from './hkdf.js';
import { createAuthInfo, createInfo } from './info.js';
import { crypto } from './isomorphic-crypto.js';
import { ecJwkToBytes } from './jwk-to-bytes.js';
import { generateLocalKeys } from './local-keys.js';
import { getSalt } from './salt.js';
import type { PushSubscription } from './types.js';
import { arrayChunk, generateNonce, invariant } from './utils.js';

export interface EncryptedNotification {
  ciphertext: Uint8Array;
  salt: Uint8Array;
  localPublicKeyBytes: Uint8Array;
}

// 4096 (push service minimum) - 2 (padding prefix) - 16 (AES-GCM tag)
const MAX_PLAINTEXT_SIZE = 4078;

// See https://developer.chrome.com/blog/web-push-encryption/
export async function encryptNotification(
  subscription: PushSubscription,
  plaintext: Uint8Array,
): Promise<EncryptedNotification> {
  invariant(
    plaintext.byteLength <= MAX_PLAINTEXT_SIZE,
    `Payload too large: ${plaintext.byteLength} bytes exceeds the ${MAX_PLAINTEXT_SIZE} byte limit`,
  );

  const clientKeys = await deriveClientKeys(subscription);
  const salt = getSalt();

  // Local ephemeral keys
  const localKeys = await generateLocalKeys();
  const localPublicKeyBytes = ecJwkToBytes(localKeys.publicJwk);

  const sharedSecret = await crypto.subtle.deriveBits(
    {
      name: 'ECDH',
      public: clientKeys.publicKey,
    },
    localKeys.privateKey,
    256,
  );

  // Infos
  const cekInfo = createInfo(
    clientKeys.publicKeyBytes,
    localPublicKeyBytes,
    'aesgcm',
  );
  const nonceInfo = createInfo(
    clientKeys.publicKeyBytes,
    localPublicKeyBytes,
    'nonce',
  );
  const authInfo = createAuthInfo();

  // Encrypt
  const ikmHkdf = await hkdf(clientKeys.authSecretBytes, sharedSecret);
  const ikm = await ikmHkdf.expand(authInfo, 32);

  const messageHkdf = await hkdf(salt, ikm);
  const [cekBytes, nonceBytes] = await Promise.all([
    messageHkdf.expand(cekInfo, 16),
    messageHkdf.expand(nonceInfo, 12),
  ]);

  const cekCryptoKey = await crypto.subtle.importKey(
    'raw',
    cekBytes,
    {
      name: 'AES-GCM',
      length: 128,
    },
    false,
    ['encrypt'],
  );

  const cipherChunks = await Promise.all(
    arrayChunk(plaintext, 4095).map(async (chunk, idx) => {
      // 2-byte big-endian padding length (always 0) followed by the chunk
      const padded = new Uint8Array(2 + chunk.length);
      padded.set(chunk, 2);

      const encrypted = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: generateNonce(new Uint8Array(nonceBytes), idx),
        },
        cekCryptoKey,
        padded,
      );

      return new Uint8Array(encrypted);
    }),
  );

  return {
    ciphertext: concatUint8Arrays(cipherChunks),
    salt,
    localPublicKeyBytes,
  };
}
