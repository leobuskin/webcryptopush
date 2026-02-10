const textEncoder = new TextEncoder();

export function utf8Encode(input: string): Uint8Array {
  return textEncoder.encode(input);
}

export function concatBytes(arrays: Uint8Array[]): Uint8Array {
  let totalLength = 0;
  for (const arr of arrays) {
    totalLength += arr.length;
  }
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

export function base64UrlDecode(input: string): Uint8Array {
  let b64 = input.replaceAll('-', '+').replaceAll('_', '/');
  b64 += '='.repeat((4 - (b64.length % 4)) % 4);

  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '');
}

export function jsonToBase64Url(obj: Record<string, unknown>): string {
  return base64UrlEncode(utf8Encode(JSON.stringify(obj)));
}
