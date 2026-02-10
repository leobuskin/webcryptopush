import { crypto } from './isomorphic-crypto.js';

export function getSalt() {
  return crypto.getRandomValues(new Uint8Array(16));
}
