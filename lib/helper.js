/**
 * @exports
 * @default
 * @class
 * @module Helper
 */
export default class Helper {
  /**
   * @static
   * @private
   * @description The ChaCha20 constants words
   * @see https://en.wikipedia.org/wiki/Nothing-up-my-sleeve_number
   * @type {number[]}
   */
  static #CONSTANTS = [
    1634760805, 857760878,
    2036477234, 1797285236
  ];

  /**
   * @static
   * @description Creates the state
   * @param {Uint8Array} key - The key
   * @param {Uint8Array} nonce - The nonce
   * @param {number} counter - The counter
   * @returns {Uint32Array} The state
   */
  static createState(key, nonce, counter) {
    const state = new Uint32Array([
      ...this.#CONSTANTS,
      ...this.#createPragmaKey(key),
      counter,
      ...this.#createPragmaNonce(nonce)
    ]);

    return state;
  }

  /**
   * @static
   * @private
   * @description Creates the key state
   * @param {DataView} view - The dataview of the key
   * @param {ArrayBuffer} view.buffer - The arraybuffer of the key
   * @returns {number[]} The key state
   */
  static #createPragmaKey({ buffer }) {
    const view = new DataView(buffer);

    //? First key row
    const A1 = view.getUint32(0, true);
    const B1 = view.getUint32(4, true);
    const C1 = view.getUint32(8, true);
    const D1 = view.getUint32(12, true);
    //? Second key row
    const A2 = view.getUint32(16, true);
    const B2 = view.getUint32(20, true);
    const C2 = view.getUint32(24, true);
    const D2 = view.getUint32(28, true);

    return [
      A1, B1, C1, D1,
      A2, B2, C2, D2
    ];
  }

  /**
   * @static
   * @private
   * @description Creates the nonce state
   * @param {DataView} view - The dataview of the nonce
   * @param {ArrayBuffer} view.buffer - The arraybuffer of the nonce
   * @returns {number[]} The nonce state
   */
  static #createPragmaNonce({ buffer }) {
    const view = new DataView(buffer);
    const is12 = (buffer.byteLength === 12);

    const A = is12 ? view.getUint32(0, true) : 0;
    const B = view.getUint32(is12 ? 4 : 0, true);
    const C = view.getUint32(is12 ? 8 : 4, true);

    return [A, B, C];
  }

  /**
   * @static
   * @description Left rotate for 32-bit unsigned integers
   * @see https://github.com/stdlib-js/number-uint32-base-rotl#notes
   * @param {number} value - The value to left rotate
   * @param {number} shift - The shift count
   * @returns {number} The left rotated integer
   */
  static ROTL32(value, shift) {
    return (value << shift) | (value >>> (32 - shift));
  }
}
