# ChaCha20

[ChaCha20](https://datatracker.ietf.org/doc/html/draft-nir-cfrg-chacha20-poly1305-05) cipher in pure Javascript.

# Reasoning

Every Javascript implementation of ChaCha20 I came across was either poorly written or outdated. I decided to bundle it up together into modern Javascript. I used some code from [thesimj](https://github.com/thesimj/js-chacha20) and [devi](https://github.com/devi/chacha20poly1305).

# Usage

```js
// Any of these can be string or Uint8Array
const data = 'Your data';
const key = 'Your key';
const nonce = 'Your nonce';

const counter = 0; // 0 by default

const encrypted = ChaCha.encrypt(data, key, nonce, counter);
const decrypted = ChaCha.decrypt(encrypted, key, nonce, counter) // > My data
```

Want tests? See [tests](https://github.com/seirdotexe/chacha20/tree/main/test).

# Copyright and licensing

You can do whatever you want with this, you don't even have to mention me!
