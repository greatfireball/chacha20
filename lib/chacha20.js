/**
 * @exports
 * @default
 * @class
 * @module ChaCha20
 */
export default class ChaCha20 {
  /**
   * @private
   * @description The cipher state
   * @type {Uint32Array}
   */
  #state;
  /**
   * @private
   * @description The 64-byte keystream block
   * @type {DataView}
   */
  #keystream;

  /**
   * @constructor
   * @param {Uint8Array} key - The key
   * @param {Uint8Array} nonce - The nonce
   * @param {number} counter - The counter
   */
  constructor(key, nonce, counter) {
    /**
     * @private
     * @description The cipher state
     * @type {Uint32Array}
     */
    this.#state = this.#createState(key, nonce, counter);
    /**
     * @private
     * @description The 64-byte keystream block
     * @type {DataView}
     */
    this.#keystream = new DataView(new ArrayBuffer(64));
  }

  /**
   * @private
   * @description Creates the constants state
   * @see https://en.wikipedia.org/wiki/Nothing-up-my-sleeve_number
   * @returns {number[]} The constants state
   */
  #createConstant() {
    const { buffer } = new TextEncoder().encode('expand 32-byte k');
    const view = new DataView(buffer);

    const A = view.getUint32(0, true); //? 'expa'
    const B = view.getUint32(4, true); //? 'nd 3'
    const C = view.getUint32(8, true); //? '2-by'
    const D = view.getUint32(12, true); //? 'te k'

    return [A, B, C, D];
  }

  /**
   * @private
   * @description Creates the key state
   * @param {DataView} view - The dataview of the key
   * @param {ArrayBuffer} view.buffer - The arraybuffer of the key
   * @returns {number[]} The key state
   */
  #createKey({ buffer }) {
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
   * @private
   * @description Creates the nonce state
   * @param {DataView} view - The dataview of the nonce
   * @param {ArrayBuffer} view.buffer - The arraybuffer of the nonce
   * @returns {number[]} The nonce state
   */
  #createNonce({ buffer }) {
    const view = new DataView(buffer);
    const is12 = (buffer.byteLength === 12);

    const A = is12 ? view.getUint32(0, true) : 0;
    const B = view.getUint32(is12 ? 4 : 0, true);
    const C = view.getUint32(is12 ? 8 : 4, true);

    return [A, B, C];
  }

  /**
   * @private
   * @description Creates the state
   * @param {Uint8Array} key - The key
   * @param {Uint8Array} nonce - The nonce
   * @param {number} counter - The counter
   * @returns {Uint32Array} The state
   */
  #createState(key, nonce, counter) {
    const state = new Uint32Array([
      ...this.#createConstant(),
      ...this.#createKey(key),
      counter,
      ...this.#createNonce(nonce)
    ]);

    return state;
  }

  /**
   * @private
   * @description Left rotate for 32-bit unsigned integers
   * @see https://github.com/stdlib-js/number-uint32-base-rotl#notes
   * @param {number} value - The value to left rotate
   * @param {number} shift - The shift count
   * @returns {number} The left rotated integer
   */
  #ROTL32(value, shift) {
    //! Note: This is unsafe, but it doesn't matter in our operations
    return (value << shift) | (value >>> (32 - shift));
  }

  /**
   * @private
   * @description The core operation of the cipher, taking 4 word in and producing 4 word out while updating each word twice
   * @param {Uint8Array} output - The output data
   * @param {number} a - Word #1
   * @param {number} b - Word #2
   * @param {number} c - Word #3
   * @param {number} d - Word #4
   */
  #quarterRound(output, a, b, c, d) {
    output[a] += output[b]; output[d] = this.#ROTL32(output[d] ^ output[a], 16);
    output[c] += output[d]; output[b] = this.#ROTL32(output[b] ^ output[c], 12);
    output[a] += output[b]; output[d] = this.#ROTL32(output[d] ^ output[a], 8);
    output[c] += output[d]; output[b] = this.#ROTL32(output[b] ^ output[c], 7);
  }

  /**
   * @private
   * @description The block making operation of the cipher, creating a 4x4 matrix with rounds
   */
  #makeBlock() {
    const mix = new Uint32Array(16);

    //? Copy state array to mix
    for (let i = 0; i < 16; i++) {
      mix[i] = this.#state[i];
    }

    //? Mix rounds
    for (let i = 0; i < 20; i += 2) {
      //? Odd rounds
      this.#quarterRound(mix, 0, 4, 8, 12); this.#quarterRound(mix, 1, 5, 9, 13);
      this.#quarterRound(mix, 2, 6, 10, 14); this.#quarterRound(mix, 3, 7, 11, 15);
      //? Even rounds
      this.#quarterRound(mix, 0, 5, 10, 15); this.#quarterRound(mix, 1, 6, 11, 12);
      this.#quarterRound(mix, 2, 7, 8, 13); this.#quarterRound(mix, 3, 4, 9, 14);
    }

    for (let i = 0, p = 0; i < 16; i++) {
      //? Add
      mix[i] += this.#state[i];

      //? Store keystream
      this.#keystream.setUint32(p, mix[i], true); p += 4;
    }
  }

  /**
   * @description Performs the cipher on the given data
   * @param {Uint8Array} data - The data to encrypt or decrypt
   * @returns {Uint8Array} The encrypted or decrypted data
   */
  perform(data) {
    const output = new Uint8Array(data.length);

    //? This for loop makes blocks and xors them with input data
    for (let i = 0, p = 0; i < data.length; i++) {
      if ((p === 0) || (p === 64)) {
        //? Make a new block
        this.#makeBlock();
        //? Increment the counter
        this.#state[12]++;
        //? Reset the position
        p = 0;
      }

      //? Xor the data
      output[i] = (data[i] ^ this.#keystream.getUint8(p++));
    }

    return output;
  }
}
