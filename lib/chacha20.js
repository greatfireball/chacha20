import Helper from './helper.js';

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
    this.#state = Helper.createState(key, nonce, counter);
    /**
     * @private
     * @description The 64-byte keystream block
     * @type {DataView}
     */
    this.#keystream = new DataView(new ArrayBuffer(64));
  }

  /**
   * @description Returns the 64-byte keystream block
   * @returns {ArrayBuffer} The 64-byte keystream block
   */
  get keystream() {
    return this.#keystream.buffer;
  }

  /**
   * @description Returns the cipher state
   * @returns {ArrayBuffer} The cipher state
   */
  get state() {
    return this.#state.buffer;
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
    output[a] += output[b]; output[d] = Helper.ROTL32(output[d] ^ output[a], 16);
    output[c] += output[d]; output[b] = Helper.ROTL32(output[b] ^ output[c], 12);
    output[a] += output[b]; output[d] = Helper.ROTL32(output[d] ^ output[a], 8);
    output[c] += output[d]; output[b] = Helper.ROTL32(output[b] ^ output[c], 7);
  }

  /**
   * @private
   * @description The block making operation of the cipher, creating a 4x4 matrix with rounds
   */
  #makeBlock() {
    //? Copy state array to mix
    const mix = Uint32Array.from(this.#state);

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
