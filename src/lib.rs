#[global_allocator]
pub static GLOBAL_ALLOCATOR: &alloc_cat::AllocCat = &alloc_cat::ALLOCATOR;

use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

const KEY_LENGTH: usize = 32;

#[wasm_bindgen]
pub struct X25519Keypair {
    public_key: [u8; KEY_LENGTH],
    private_key: [u8; KEY_LENGTH],
}

#[wasm_bindgen]
impl X25519Keypair {
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> Vec<u8> {
        self.private_key.to_vec()
    }
}

#[wasm_bindgen]
pub fn generate_keypair() -> X25519Keypair {
    let secret = StaticSecret::random();
    let public = PublicKey::from(&secret);

    X25519Keypair {
        public_key: *public.as_bytes(),
        private_key: *secret.as_bytes(),
    }
}

#[wasm_bindgen]
pub fn random_secret() -> Vec<u8> {
    StaticSecret::random().as_bytes().to_vec()
}

#[wasm_bindgen]
pub fn public_key(private_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let private_key_array: [u8; KEY_LENGTH] = private_key
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid private key length"))?;

    let private_key: StaticSecret = StaticSecret::from(private_key_array);
    let public_key: PublicKey = PublicKey::from(&private_key);

    let shared_secret: SharedSecret = private_key.diffie_hellman(&public_key);

    Ok(shared_secret.as_bytes().to_vec())
}

#[wasm_bindgen]
pub fn diffie_hellman(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let private_key_array: [u8; KEY_LENGTH] = private_key
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid private key length"))?;

    let public_key_array: [u8; KEY_LENGTH] = public_key
        .try_into()
        .map_err(|_| JsValue::from_str("Invalid public key length"))?;

    let private_key: StaticSecret = StaticSecret::from(private_key_array);
    let public_key: PublicKey = PublicKey::from(public_key_array);

    let shared_secret: SharedSecret = private_key.diffie_hellman(&public_key);

    Ok(shared_secret.as_bytes().to_vec())
}

#[wasm_bindgen]
pub struct DiffieHellman {
    private_key: StaticSecret,
}

#[wasm_bindgen]
impl DiffieHellman {
    #[wasm_bindgen(constructor)]
    pub fn new(private_key: &[u8]) -> Result<DiffieHellman, JsValue> {
        let private_key_array: [u8; KEY_LENGTH] = private_key
            .try_into()
            .map_err(|_| JsValue::from_str("Invalid private key length"))?;

        Ok(DiffieHellman {
            private_key: StaticSecret::from(private_key_array),
        })
    }

    pub fn shared_key(&self, public_key: &[u8]) -> Result<Vec<u8>, JsValue> {
        let public_key_array: [u8; KEY_LENGTH] = public_key
            .try_into()
            .map_err(|_| JsValue::from_str("Invalid public key length"))?;

        let public_key: PublicKey = PublicKey::from(public_key_array);

        let shared_secret: SharedSecret = self.private_key.diffie_hellman(&public_key);

        Ok(shared_secret.as_bytes().to_vec())
    }

    #[wasm_bindgen]
    pub fn public_key(&self) -> Vec<u8> {
        let public_key: PublicKey = PublicKey::from(&self.private_key);
        public_key.as_bytes().to_vec()
    }

    #[wasm_bindgen]
    pub fn from_random() -> DiffieHellman {
        DiffieHellman {
            private_key: StaticSecret::random(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn test_generate_keypair() {
        let result = generate_keypair();

        assert_eq!(result.public_key.len(), KEY_LENGTH);
        assert_eq!(result.private_key.len(), KEY_LENGTH);
    }

    #[test]
    fn test_diffie_hellman() {
        // Simulate Alice and Bob key exchange
        let alice_secret: StaticSecret = StaticSecret::random();
        let alice_public: PublicKey = PublicKey::from(&alice_secret);

        let bob_secret: StaticSecret = StaticSecret::random();
        let bob_public: PublicKey = PublicKey::from(&bob_secret);

        // Now test via your wasm-exposed function
        let alice_shared_secret: Vec<u8> =
            diffie_hellman(alice_secret.as_bytes(), bob_public.as_bytes()).unwrap();

        let bob_shared_secret: Vec<u8> =
            diffie_hellman(bob_secret.as_bytes(), alice_public.as_bytes()).unwrap();

        assert_eq!(alice_shared_secret, bob_shared_secret);
    }

    #[test]
    fn test_random_secret() {
        let _secret = random_secret();

        assert_eq!(_secret.len(), KEY_LENGTH);
    }

    #[test]
    fn test_get_public_key() {
        let alice_secret: StaticSecret = StaticSecret::random();

        let alice_public = public_key(alice_secret.as_bytes()).unwrap();

        assert_eq!(alice_public.len(), KEY_LENGTH);
    }

    #[test]
    fn test_diffie_hellman_struct() {
        let alice = DiffieHellman::from_random();
        let bob = DiffieHellman::from_random();

        let alice_shared = alice.shared_key(&bob.public_key()).unwrap();
        let bob_shared = bob.shared_key(&alice.public_key()).unwrap();

        assert_eq!(alice_shared, bob_shared);
    }
}
