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
   * @description Defines if we're in testing mode or not
   * @type {boolean}
   */
  static #IS_TEST = false;

  /**
   * @static
   * @description Encrypt data using the ChaCha20 cipher
   * @param {Uint8Array} data - The data to encrypt
   * @param {Uint8Array} key - The key to use
   * @param {Uint8Array} nonce - The nonce to use
   * @param {number} [counter=0] The counter to use
   * @returns {Uint8Array} The encrypted data
   */
  static encrypt(data, key, nonce, counter = 0) {
    const cipher = new ChaCha20(key, nonce, counter);
    const output = cipher.perform(data, this.#IS_TEST);

    return output;
  }

  /**
   * @static
   * @description Decrypt data using the ChaCha20 cipher
   * @param {Uint8Array} data - The data to decrypt
   * @param {Uint8Array} key - The key to use
   * @param {Uint8Array} nonce - The nonce to use
   * @param {number} [counter=0] The counter to use
   * @returns {Uint8Array} The decrypted data
   */
  static decrypt(data, key, nonce, counter = 0) {
    const cipher = new ChaCha20(key, nonce, counter);
    const output = cipher.perform(data, this.#IS_TEST);

    return output;
  }
}
