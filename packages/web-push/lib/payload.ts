import { stringToUint8Array } from 'uint8array-extras';
import { toBase64UrlSafe } from './base64.js';
import { encryptNotification } from './encrypt.js';
import type { PushMessage, PushRequestInit, PushSubscription } from './types.js';
import { type VapidKeys, vapidHeaders } from './vapid.js';

export async function buildPushPayload(
  message: PushMessage,
  subscription: PushSubscription,
  vapid: VapidKeys,
): Promise<PushRequestInit> {
  const { headers } = await vapidHeaders(subscription, vapid);

  const encrypted = await encryptNotification(
    subscription,
    stringToUint8Array(message.data),
  );

  return {
    headers: {
      ...headers,

      'crypto-key': `dh=${toBase64UrlSafe(encrypted.localPublicKeyBytes)};${headers['crypto-key']}`,

      encryption: `salt=${toBase64UrlSafe(encrypted.salt)}`,

      ttl: (message.options?.ttl ?? 60).toString(),
      ...(message.options?.urgency && {
        urgency: message.options.urgency,
      }),
      ...(message.options?.topic && {
        topic: message.options.topic,
      }),

      'content-encoding': 'aesgcm',
      'content-length': encrypted.ciphertext.byteLength.toString(),
      'content-type': 'application/octet-stream',
    },
    method: 'POST',
    body: encrypted.ciphertext,
  };
}
