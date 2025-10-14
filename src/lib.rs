use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

const KEY_LENGTH: usize = 32;

#[wasm_bindgen]
pub struct X25519Keypair {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

#[wasm_bindgen]
impl X25519Keypair {
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> Vec<u8> {
        self.private_key.clone()
    }
}

#[wasm_bindgen]
pub fn generate_keypair() -> Result<X25519Keypair, JsValue> {
    let secret: StaticSecret = StaticSecret::random();
    let public = PublicKey::from(&secret);

    Ok(X25519Keypair {
        public_key: public.as_bytes().to_vec(),
        private_key: secret.as_bytes().to_vec(),
    })
}

#[wasm_bindgen]
pub fn diffie_hellman(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    if private_key.len() != KEY_LENGTH {
        return Err(JsValue::from_str("Invalid private key length !"));
    }
    if public_key.len() != KEY_LENGTH {
        return Err(JsValue::from_str("Invalid public key length !"));
    }

    // Convert byte slices into X25519 keys
    let private_key = StaticSecret::from(<[u8; KEY_LENGTH]>::try_from(private_key).unwrap());
    let public_key = PublicKey::from(<[u8; KEY_LENGTH]>::try_from(public_key).unwrap());

    let shared_secret: SharedSecret = private_key.diffie_hellman(&public_key);

    Ok(shared_secret.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn test_generate_keypair() {
        let result = generate_keypair().unwrap();
        assert_eq!(result.public_key.len(), 32);
        assert_eq!(result.private_key.len(), 32);
    }

    #[test]
    fn test_diffie_hellman_success() {
        // Simulate Alice and Bob key exchange
        let alice_secret = StaticSecret::random();
        let alice_public = PublicKey::from(&alice_secret);

        let bob_secret = StaticSecret::random();
        let bob_public = PublicKey::from(&bob_secret);

        // Now test via your wasm-exposed function
        let alice_shared_secret =
            diffie_hellman(alice_secret.as_bytes(), bob_public.as_bytes()).unwrap();

        let bob_shared_secret =
            diffie_hellman(bob_secret.as_bytes(), alice_public.as_bytes()).unwrap();

        assert_eq!(alice_shared_secret, bob_shared_secret);
    }
}
