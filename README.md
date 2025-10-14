# x25519-wasm-vn
[![npm](https://img.shields.io/npm/v/x25519-wasm-vn)](https://www.npmjs.com/package/x25519-wasm-vn)

### 🛠️ Installing `wasm-pack`

```
cargo install wasm-pack
```

### 🛠️ Build with `wasm-pack build`

```
wasm-pack build --target web
```

### 🎁 Publish to NPM with `wasm-pack publish`

```
wasm-pack publish
```

## Usage

```js
import init, { generate_keypair, diffie_hellman } from "x25519-wasm-vn";

init().then(() => {
    const bob_key_pair = generate_keypair();

    console.log("Public key (Bob): ", bob_key_pair.public_key);
    console.log("Private key (Bob): ", bob_key_pair.private_key);

    const alice_key_pair = generate_keypair();

    console.log("Public key (Alice): ", alice_key_pair.public_key);
    console.log("Private key (Alice): ", alice_key_pair.private_key);

    let alice_shared = diffie_hellman(alice_key_pair.private_key, bob_key_pair.public_key);

    let bob_shared = diffie_hellman(bob_key_pair.private_key, alice_key_pair.public_key);

    console.log("Shared key (Bob): ", bob_shared);
    console.log("Shared key (Alice): ", alice_shared);
});
```
