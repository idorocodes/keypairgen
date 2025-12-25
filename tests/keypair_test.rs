use keypairgen::*;

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, SignatureError, VerifyingKey, PUBLIC_KEY_LENGTH};

    use super::*;

    #[test]
    fn keygen() {
        generate_keypair_withoutseeds();
    }

    #[test]
    fn keygenseed() -> Result<(), SignatureError> {
        let phrase = "love";
        let new = phrase.repeat(16);
        let mut array = [0u8; 64];
        array.copy_from_slice(new.as_bytes());
        let result = generate_keypair_withseeds(array)?;
        Ok(result)
    }

    #[test]
    fn gen_ran_ver() {
        generate_random_verify();
    }

    #[test]
    fn verify_withkey_andsig() -> Result<(), ed25519_dalek::ed25519::Error> {
        let key = "6c6f76656c6f76656c6f76656c6f76656c6f76656c6f76656c6f76656c6f7665";
        let signature  = "89F2D65DA9E86A9F25119B59DDC67D373D4A8BF363A6B1E1D1CBA70FE816E266284EF8827B0BA16DE88A2093340EBDB10890E87A3B22448220ECFD50DA570805";
        let message =  b"Idorocodes writes rust and builds on solana";
        verify_message_withsig(key, signature, message)
    }
}
