use ed25519_dalek::{
     Signature, SignatureError, Signer, SigningKey, Verifier, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH
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
    println!("{}",signature);

    println!("Message signed!");
    println!("Pub key {}",hex::encode(signing_key.verifying_key().as_bytes()));

    println!("Verifying the message");

    let verifying_key = signing_key.verifying_key();

    match verifying_key.verify(message, &signature) {
        Ok(_) => println!("Message verified! LFG !!!"),
        Err(_) => println!("Unable to verify the message!"),
    }
}

