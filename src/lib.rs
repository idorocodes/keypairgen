

use ed25519_dalek::{
    PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, Signature, SignatureError, Signer, SigningKey, Verifier,
    VerifyingKey, ed25519::Error,
};
use hex;
use rand::rngs::OsRng;

pub fn generate_keypair_withoutseeds() {
    let mut cspring = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut cspring);
    let public_key: [u8; PUBLIC_KEY_LENGTH] = *signing_key.verifying_key().as_bytes();
    let private_key: [u8; SECRET_KEY_LENGTH] = signing_key.to_bytes();

    println!("Public key: {:}", hex::encode(public_key));
    println!("Private key: {:}", hex::encode(private_key));
}

pub fn generate_keypair_withseeds(seeds: [u8; 64]) -> Result<(), SignatureError> {
    let (secret_key, verifying_key) = seeds.split_at(SECRET_KEY_LENGTH);
    let signing_key = SigningKey::try_from(secret_key)?;
    let verifing_key = SigningKey::try_from(verifying_key)?;

    println!(
        "Signing  key {:}",
        hex::encode(signing_key.verifying_key().as_bytes())
    );
    println!("Verifying key {:}", hex::encode(verifing_key.to_bytes()));
    Ok(())
}

pub fn generate_random_verify() {
    let mut cspring = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut cspring);

    let message = b"Idorocodes writes rust and builds on solana";
    let signature: Signature = signing_key.sign(message);
    println!("{}", signature);

    println!("Message signed!");
    println!(
        "Pub key {}",
        hex::encode(signing_key.verifying_key().as_bytes())
    );

    println!("Verifying the message");

    let verifying_key = signing_key.verifying_key();

    match verifying_key.verify(message, &signature) {
        Ok(_) => println!("Message verified! LFG !!!"),
        Err(_) => println!("Unable to verify the message!"),
    }
}

pub fn verify_message_withsig(pub_key: &str, sign: &str, message: &[u8]) -> Result<(), Error> {
    let key_input = hex::decode(pub_key);

    let key = match key_input {
        Ok(x) => x,
        Err(_) => vec![],
    };

    let convert_key: [u8; PUBLIC_KEY_LENGTH] = key.try_into().expect("cant convert");

    let pub_key = VerifyingKey::from_bytes(&convert_key);

    let public_key = match pub_key {
        Ok(x) => x,
        Err(_) => VerifyingKey::default(),
    };

    let mut array: [u8; 64] = [0u8; 64];
    array.copy_from_slice(sign.as_bytes());

    let signature = Signature::from_bytes(&array);

    let result = match public_key.verify(message, &signature) {
        Ok(_) => println!("Message verified !"),
        Err(_) => println!("Error  verifying "),
    };

    Ok(result)
}
