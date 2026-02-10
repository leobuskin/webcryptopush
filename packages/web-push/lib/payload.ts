import { base64UrlEncode, utf8Encode } from './encoding.js';
import { encryptNotification } from './encrypt.js';
import type { PushMessage, PushRequestInit, PushSubscription } from './types.js';
import { type VapidKeys, vapidHeaders } from './vapid.js';

export async function buildPushPayload(
  message: PushMessage,
  subscription: PushSubscription,
  vapid: VapidKeys,
): Promise<PushRequestInit> {
  const vapidHdrs = await vapidHeaders(subscription, vapid);

  const encrypted = await encryptNotification(
    subscription,
    utf8Encode(message.data),
  );

  return {
    headers: {
      ...vapidHdrs,

      'crypto-key': `dh=${base64UrlEncode(encrypted.localPublicKeyBytes)};${vapidHdrs['crypto-key']}`,

      encryption: `salt=${base64UrlEncode(encrypted.salt)}`,

      ttl: (message.options?.ttl ?? 86400).toString(),
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
