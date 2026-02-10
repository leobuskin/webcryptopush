export function encodeUint16BE(int: number) {
  return new Uint8Array([0, int]);
}

export function invariant<T>(
  condition: T | undefined | null | '' | 0 | false,
  message: string,
): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}
