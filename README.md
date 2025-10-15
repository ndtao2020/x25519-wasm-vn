# x25519-wasm-vn
[![npm](https://img.shields.io/npm/v/x25519-wasm-vn)](https://www.npmjs.com/package/x25519-wasm-vn)

## Installing `wasm-bindgen-cli`

```sh
cargo install wasm-bindgen-cli
cargo install wasm-opt --locked
```

## Building via `wasm-bindgen-cli`

```sh
chmod +x build.sh && ./build.sh
```

### Publish to NPM

```sh
cd pkg && npm publish
```

## Usage

```ts
import instantiate, { DiffieHellman, generate_keypair, X25519Keypair } from 'x25519-wasm-vn/web'

interface KeyPair {
  privateKey: Uint8Array
  publicKey: Uint8Array
}

export const generateKeyPair = async (): Promise<KeyPair> => {
  let keypair_wasm: X25519Keypair | null = null
  try {
    await instantiate()
    keypair_wasm = generate_keypair()
    return {
      privateKey: keypair_wasm.private_key,
      publicKey: keypair_wasm.public_key
    }
  } catch (err) {
    console.error(err)
  } finally {
    if (keypair_wasm) {
      keypair_wasm.free()
    }
  }
}

export const diffieHellman = async (privateKey: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array> => {
  let _wasm: DiffieHellman | null = null
  try {
    await instantiate()
    _wasm = new DiffieHellman(privateKey)
    return _wasm.get_shared_key(publicKey)
  } catch (err) {
    console.error(err)
  } finally {
    if (_wasm) {
      _wasm.free()
    }
  }
}
```
