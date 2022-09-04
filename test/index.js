import ChaCha from '../lib/index.js';
import test from 'node:test';
import assert from 'node:assert';

test('Draft test #1', () => {
  const data = new Uint8Array(64);
  const key = new Uint8Array(32);
  const nonce = new Uint8Array(12);

  const out = ChaCha.encrypt(data, key, nonce, 0);
  const expected = new Uint8Array([
    118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106,
    229, 83, 134, 189, 40, 189, 210, 25, 184, 160, 141,
    237, 26, 168, 54, 239, 204, 139, 119, 13, 199, 218,
    65, 89, 124, 81, 87, 72, 141, 119, 36, 224, 63,
    184, 216, 74, 55, 106, 67, 184, 244, 21, 24, 161,
    28, 195, 135, 182, 105, 178, 238, 101, 134
  ]);

  assert.deepStrictEqual(out, expected);
});

test('Draft test #2', () => {
  const data = new Uint8Array(64);
  const key = new Uint8Array(32);
  const nonce = new Uint8Array(12);

  const out = ChaCha.encrypt(data, key, nonce, 1);
  const expected = new Uint8Array([
    159, 7, 231, 190, 85, 81, 56, 122, 152, 186, 151,
    124, 115, 45, 8, 13, 203, 15, 41, 160, 72, 227,
    101, 105, 18, 198, 83, 62, 50, 238, 122, 237, 41,
    183, 33, 118, 156, 230, 78, 67, 213, 113, 51, 176,
    116, 216, 57, 213, 49, 237, 31, 40, 81, 10, 251,
    69, 172, 225, 10, 31, 75, 121, 77, 111
  ]);

  assert.deepStrictEqual(out, expected);
});

test('Draft test #3', () => {
  const data = new Uint8Array(64);
  const key = new Uint8Array(32);
  const nonce = new Uint8Array(12);

  key[key.length - 1] = 1;

  const out = ChaCha.encrypt(data, key, nonce, 1);
  const expected = new Uint8Array([
    58, 235, 82, 36, 236, 248, 73, 146, 155, 157, 130,
    141, 177, 206, 212, 221, 131, 32, 37, 232, 1, 139,
    129, 96, 184, 34, 132, 243, 201, 73, 170, 90, 142,
    202, 0, 187, 180, 167, 59, 218, 209, 146, 181, 196,
    47, 115, 242, 253, 78, 39, 54, 68, 200, 179, 97,
    37, 166, 74, 221, 235, 0, 108, 19, 160
  ]);

  assert.deepStrictEqual(out, expected);
});

test('Draft test #4', () => {
  const data = new Uint8Array(64);
  const key = new Uint8Array(32);
  const nonce = new Uint8Array(12);

  key[1] = 0xFF;

  const out = ChaCha.encrypt(data, key, nonce, 2);
  const expected = new Uint8Array([
    114, 213, 77, 251, 241, 46, 196, 75, 54, 38, 146,
    223, 148, 19, 127, 50, 143, 234, 141, 167, 57, 144,
    38, 94, 193, 187, 190, 161, 174, 154, 240, 202, 19,
    178, 90, 162, 108, 180, 166, 72, 203, 155, 157, 27,
    230, 91, 44, 9, 36, 166, 108, 84, 213, 69, 236,
    27, 115, 116, 244, 135, 46, 153, 240, 150
  ]);

  assert.deepStrictEqual(out, expected);
});

test('Draft test #5', () => {
  const data = new Uint8Array(64);
  const key = new Uint8Array(32);
  const nonce = new Uint8Array(12);

  nonce[nonce.length - 1] = 2;

  const out = ChaCha.encrypt(data, key, nonce, 0);
  const expected = new Uint8Array([
    194, 198, 77, 55, 140, 213, 54, 55, 74, 226, 4,
    185, 239, 147, 63, 205, 26, 139, 34, 136, 179, 223,
    164, 150, 114, 171, 118, 91, 84, 238, 39, 199, 138,
    151, 14, 14, 149, 92, 20, 243, 168, 142, 116, 27,
    151, 194, 134, 247, 95, 143, 194, 153, 232, 20, 131,
    98, 250, 25, 138, 57, 83, 27, 237, 109
  ]);

  assert.deepStrictEqual(out, expected);
});
