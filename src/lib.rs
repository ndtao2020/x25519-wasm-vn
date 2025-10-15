#[global_allocator]
pub static GLOBAL_ALLOCATOR: &alloc_cat::AllocCat = &alloc_cat::ALLOCATOR;

use hkdf::Hkdf;
use sha2::Sha256;
use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

const KEY_LENGTH: usize = 32;
const SALT_LENGTH: usize = 32;
const INFO_MAX_LENGTH: usize = 128;

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
pub fn generate_salt() -> Vec<u8> {
    let mut salt = [0u8; SALT_LENGTH];
    getrandom::getrandom(&mut salt).expect("Failed to generate random salt");
    salt.to_vec()
}

#[wasm_bindgen]
pub fn hkdf_sha_256(
    shared_secret: &[u8],
    salt: Option<Vec<u8>>,
    info: Option<Vec<u8>>,
    length: usize,
) -> Result<Vec<u8>, JsValue> {
    // Validate input lengths
    if shared_secret.len() != KEY_LENGTH {
        return Err(JsValue::from_str(&format!(
            "Invalid shared secret length: expected {}, got {}",
            KEY_LENGTH,
            shared_secret.len()
        )));
    }
    if let Some(ref salt_bytes) = salt {
        if salt_bytes.len() > SALT_LENGTH {
            return Err(JsValue::from_str(&format!(
                "Salt too long: maximum {} bytes, got {}",
                SALT_LENGTH,
                salt_bytes.len()
            )));
        }
    }
    if let Some(ref info_bytes) = info {
        if info_bytes.len() > INFO_MAX_LENGTH {
            return Err(JsValue::from_str(&format!(
                "Info too long: maximum {} bytes, got {}",
                INFO_MAX_LENGTH,
                info_bytes.len()
            )));
        }
    }
    if length == 0 || length > 256 {
        return Err(JsValue::from_str(
            "Output length must be between 1 and 256 bytes",
        ));
    }

    // Create HKDF instance with Sha256
    let hkdf = Hkdf::<Sha256>::new(salt.as_deref(), shared_secret);

    // Derive the key
    let mut output_key = vec![0u8; length];

    // Use provided info or empty
    if info.is_some() {
        hkdf.expand(&info.unwrap(), &mut output_key)
            .map_err(|e| JsValue::from_str(&format!("HKDF expansion failed: {}", e)))?;
    }

    Ok(output_key)
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

#[wasm_bindgen]
pub struct Sha256HKDF {
    shared_secret: [u8; KEY_LENGTH],
}

#[wasm_bindgen]
impl Sha256HKDF {
    #[wasm_bindgen(constructor)]
    pub fn new(shared_secret: &[u8]) -> Result<Sha256HKDF, JsValue> {
        let shared_secret_array: [u8; KEY_LENGTH] = shared_secret
            .try_into()
            .map_err(|_| JsValue::from_str("Invalid shared secret length"))?;

        Ok(Sha256HKDF {
            shared_secret: shared_secret_array,
        })
    }

    pub fn derive_key(
        &self,
        salt: Option<Vec<u8>>,
        info: Option<Vec<u8>>,
        output_length: usize,
    ) -> Result<Vec<u8>, JsValue> {
        // Validate input lengths
        if let Some(ref salt_bytes) = salt {
            if salt_bytes.len() > SALT_LENGTH {
                return Err(JsValue::from_str(&format!(
                    "Salt too long: maximum {} bytes, got {}",
                    SALT_LENGTH,
                    salt_bytes.len()
                )));
            }
        }
        if let Some(ref info_bytes) = info {
            if info_bytes.len() > INFO_MAX_LENGTH {
                return Err(JsValue::from_str(&format!(
                    "Info too long: maximum {} bytes, got {}",
                    INFO_MAX_LENGTH,
                    info_bytes.len()
                )));
            }
        }
        if output_length == 0 || output_length > 1024 {
            return Err(JsValue::from_str(
                "Output length must be between 1 and 1024 bytes",
            ));
        }

        // Create HKDF instance with Sha256
        let hkdf = Hkdf::<Sha256>::new(salt.as_deref(), &self.shared_secret);

        // Derive the key
        let mut output_key = vec![0u8; output_length];

        if info.is_some() {
            hkdf.expand(&info.unwrap(), &mut output_key)
                .map_err(|e| JsValue::from_str(&format!("HKDF expansion failed: {}", e)))?;
        }

        Ok(output_key)
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

    #[test]
    fn test_generate_salt() {
        let salt = generate_salt();
        assert_eq!(salt.len(), SALT_LENGTH);

        // Should be random
        let salt2 = generate_salt();
        assert_ne!(salt, salt2);
    }

    #[test]
    fn test_derive_key() {
        let shared_secret = [0x42u8; KEY_LENGTH];

        let salt = Some(generate_salt());
        let info = Some(b"test-test-123$".to_vec());

        let derived = hkdf_sha_256(&shared_secret, salt.clone(), info.clone(), 32).unwrap();

        assert_eq!(derived.len(), 32);

        // Should be deterministic
        let derived2 = hkdf_sha_256(&shared_secret, salt, info, 32).unwrap();

        assert_eq!(derived, derived2);
    }

    #[test]
    fn test_complete_key_exchange_workflow() {
        // Alice generates keypair
        let alice_keypair = generate_keypair();

        // Bob generates keypair
        let bob_keypair = generate_keypair();

        // Alice computes shared secret
        let alice_shared =
            diffie_hellman(&alice_keypair.private_key, &bob_keypair.public_key).unwrap();

        // Bob computes shared secret
        let bob_shared =
            diffie_hellman(&bob_keypair.private_key, &alice_keypair.public_key).unwrap();

        // Shared secrets should match
        assert_eq!(alice_shared, bob_shared);

        let salt = Some(generate_salt());
        let info = Some(b"test-test-123$".to_vec());

        // Both derive encryption keys from shared secret
        let alice_enc_key = hkdf_sha_256(&alice_shared, salt.clone(), info.clone(), 32).unwrap();

        print!("{:?}", alice_enc_key);

        let hkdf = Sha256HKDF::new(&bob_shared).unwrap();

        let bob_enc_key = hkdf.derive_key(salt, info, 32).unwrap();

        // Derived keys should match
        assert_eq!(alice_enc_key, bob_enc_key);
    }
}
