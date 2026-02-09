import type { PushSubscription } from '../../lib/types.js';

export const subscriptions = {
  chrome: {
    endpoint:
      'https://fcm.googleapis.com/fcm/send/ekhJ4l8bTqw:APA91bGyU0XqT5uWpyGzpx9TDtGc0m-CTPpjnnOVnl_ybIOlue7LPYlHoRyWZ4JgySwceHjmvDprQMW9vehEZn5ifluMA0Bq2FA5qfYceC3vv5YivFFtA2debLNbpfiLEN73WyoVJfgG',
    expirationTime: null,
    keys: {
      p256dh:
        'BGPknDTtnF3sW5XPDzZl9DD2YqFY0WsyqZJ2Pxrzq8x1HY-5aF2aRiCz_QKDY2nj-ZFtqdBwRsV9yoPRg_015Vo',
      auth: 'ynfeyAwBSXODSCaeRNQZiw',
    },
  },
} satisfies Record<string, PushSubscription>;
