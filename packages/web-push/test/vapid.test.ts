import { expect, test, vi } from 'vitest';
import { vapidHeaders } from '../lib/vapid.js';
import { subscriptions } from './fixtures/fixtures.js';
import { insecureVapid } from './fixtures/vapid.js';

test('Headers', async () => {
  vi.setSystemTime(new Date(2000, 1, 1, 13));

  const headers = await vapidHeaders(subscriptions.chrome, insecureVapid);

  expect(headers.authorization).toMatch(/^WebPush /);
  expect(headers['crypto-key']).toBe(
    `p256ecdsa=${insecureVapid.publicKey}`,
  );

  // Verify JWT structure (header.payload.signature)
  const jwt = headers.authorization.replace('WebPush ', '');
  const parts = jwt.split('.');
  expect(parts).toHaveLength(3);

  // Verify JWT payload
  const payload = JSON.parse(
    Buffer.from(parts[1], 'base64url').toString(),
  );
  expect(payload.aud).toBe('https://fcm.googleapis.com');
  expect(payload.sub).toBe('mailto:test@test.test');
  expect(payload.exp).toBeTypeOf('number');
  expect(payload.iat).toBeTypeOf('number');
});
