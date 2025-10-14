use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

const KEY_LENGTH: usize = 32;

#[wasm_bindgen]
pub struct X25519Keypair {
    #[wasm_bindgen(skip)]
    pub public_key: Vec<u8>,
    #[wasm_bindgen(skip)]
    pub private_key: Vec<u8>,
}

#[wasm_bindgen]
pub fn generate_keypair() -> Result<X25519Keypair, JsValue> {
    let secret: StaticSecret = StaticSecret::random();
    let public = PublicKey::from(&secret);

    Ok(X25519Keypair {
        public_key: public.as_bytes().to_vec(),
        private_key: secret.to_bytes().to_vec(),
    })
}

#[wasm_bindgen]
pub fn diffie_hellman(
    private_key_bytes: &[u8],
    public_key_bytes: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if public_key_bytes.len() != KEY_LENGTH {
        return Err(JsValue::from_str("Invalid public key length !"));
    }
    if private_key_bytes.len() != KEY_LENGTH {
        return Err(JsValue::from_str("Invalid private key length !"));
    }

    // Convert byte slices into X25519 keys
    let private_key = StaticSecret::from(<[u8; KEY_LENGTH]>::try_from(private_key_bytes).unwrap());
    let public_key = PublicKey::from(<[u8; KEY_LENGTH]>::try_from(public_key_bytes).unwrap());

    let shared_secret: SharedSecret = private_key.diffie_hellman(&public_key);

    Ok(shared_secret.as_bytes().to_vec())
}
