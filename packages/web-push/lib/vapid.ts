import { base64UrlDecode, base64UrlEncode } from './encoding.js';
import { crypto } from './isomorphic-crypto.js';
import { sign } from './jwt.js';
import type { PushSubscription } from './types.js';
import { invariant } from './utils.js';

export type VapidKeys = {
  subject: string;
  publicKey: string;
  privateKey: string;
};

export async function vapidHeaders(
  subscription: PushSubscription,
  vapid: VapidKeys,
) {
  invariant(
    vapid.subject.startsWith('mailto:') || vapid.subject.startsWith('https://'),
    'Vapid subject must be a mailto: or https:// URI',
  );
  invariant(vapid.privateKey, 'Vapid private key is empty');
  invariant(vapid.publicKey, 'Vapid public key is empty');

  const vapidPublicKeyBytes = base64UrlDecode(vapid.publicKey);

  invariant(
    vapidPublicKeyBytes.byteLength === 65,
    `Invalid VAPID public key: expected 65 bytes (uncompressed P-256 point), got ${vapidPublicKeyBytes.byteLength}`,
  );

  const signingKey = await crypto.subtle.importKey(
    'jwk',
    {
      kty: 'EC',
      crv: 'P-256',
      x: base64UrlEncode(vapidPublicKeyBytes.slice(1, 33)),
      y: base64UrlEncode(vapidPublicKeyBytes.slice(33, 65)),
      d: vapid.privateKey,
    },
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    false,
    ['sign'],
  );

  const jwt = await sign(
    {
      aud: new URL(subscription.endpoint).origin,
      exp: Math.floor(Date.now() / 1000) + 12 * 60 * 60,
      sub: vapid.subject,
    },
    signingKey,
  );

  return {
    authorization: `WebPush ${jwt}`,
    'crypto-key': `p256ecdsa=${vapid.publicKey}`,
  };
}
