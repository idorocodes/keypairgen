use keypairgen::*;

#[cfg(test)]
mod tests {
    use ed25519_dalek::SignatureError;

    use super::*;

    #[test]
    fn keygen() {
        generate_keypair_withoutseeds();
    }
    
    #[test]
    fn keygenseed()-> Result<(),SignatureError>{
        let phrase = "love";
        let new=   phrase.repeat(16);
        let mut array = [0u8;64];
         array.copy_from_slice(new.as_bytes());
        let result =  generate_keypair_withseeds(array)?;
        Ok(result)
    }
    
    #[test]
    fn gen_ran_ver(){
        generate_random_verify();
    }
    
    
    
  
}
