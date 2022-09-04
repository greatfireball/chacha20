import ChaCha20 from './chacha20.js';

/**
 * @exports
 * @default
 * @class
 * @module ChaCha
 */
export default class ChaCha {
  /**
   * @static
   * @private
   * @description The text encoder
   * @type {TextEncoder}
   */
  static #encoder = new TextEncoder();

  /**
   * @static
   * @description Encrypt data using the ChaCha20 cipher
   * @param {Uint8Array|string} data - The data to encrypt
   * @param {Uint8Array|string} key - The key to use
   * @param {Uint8Array|string} nonce - The nonce to use
   * @param {number} [counter=0] The counter to use
   * @returns {Uint8Array} The encrypted data
   */
  static encrypt(data, key, nonce, counter = 0) {
    if (typeof data === 'string') {
      data = this.#encoder.encode(data);
    }

    if (typeof key === 'string') {
      key = this.#encoder.encode(key);
    }

    if (typeof nonce === 'string') {
      nonce = this.#encoder.encode(nonce);
    }

    const cipher = new ChaCha20(key, nonce, counter);
    const output = cipher.perform(data);

    return output;
  }

  /**
   * @static
   * @description Decrypt data using the ChaCha20 cipher
   * @param {Uint8Array|string} data - The data to decrypt
   * @param {Uint8Array|string} key - The key to use
   * @param {Uint8Array|string} nonce - The nonce to use
   * @param {number} [counter=0] The counter to use
   * @returns {Uint8Array} The decrypted data
   */
  static decrypt(data, key, nonce, counter = 0) {
    if (typeof data === 'string') {
      data = this.#encoder.encode(data);
    }

    if (typeof key === 'string') {
      key = this.#encoder.encode(key);
    }

    if (typeof nonce === 'string') {
      nonce = this.#encoder.encode(nonce);
    }

    const cipher = new ChaCha20(key, nonce, counter);
    const output = cipher.perform(data);

    return output;
  }
}
