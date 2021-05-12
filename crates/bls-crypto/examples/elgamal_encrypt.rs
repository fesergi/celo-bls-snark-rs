use algebra::{bls12_377::{Fr, G1Projective}, UniformRand, ProjectiveCurve};
use bls_crypto::{HashToCurve,hash_to_curve::try_and_increment::COMPOSITE_HASH_TO_G1};
use clap::{App, Arg};

pub fn rng() -> rand::rngs::ThreadRng {
    rand::thread_rng()
}

pub fn keygen() -> (Fr, G1Projective) {
    let rng = &mut rng();
    let sk = Fr::rand(rng);
    let pk = G1Projective::prime_subgroup_generator().mul(sk.clone());
    (sk, pk)
}

pub fn encrypt(message: &[u8], pk: G1Projective) -> (G1Projective, G1Projective) {
    let hash_to_g1 = &*COMPOSITE_HASH_TO_G1;
    let msg = hash_to_g1.hash(b"sign", message, &[]).unwrap();

    let rng = &mut rng();
    let y = Fr::rand(rng);
    let shared_secret = pk.mul(y.clone());
    let c1 = G1Projective::prime_subgroup_generator().mul(y.clone());
    let c2 = msg + shared_secret;
    (c1, c2)
}

pub fn decrypt((c1, c2): (G1Projective, G1Projective), sk: Fr) -> G1Projective {
    let s = c1.mul(sk);
    c2 - s
}

fn main() {
    // let matches = App::new("ElgamalEncryption")
    //     .about("Show an example of a elgamal encryption")
    //     .arg(
    //         Arg::with_name("message")
    //             .short("m")
    //             .value_name("MESSAGE")
    //             .help("Sets the message to encrypt")
    //             .required(true),
    //     )
    //     .get_matches();
    //
    // let message = matches.value_of("message").unwrap();

    let message: &[u8] = b"hello";
    let hash_to_g1 = &*COMPOSITE_HASH_TO_G1;

    let (sk, pk) = keygen();
    println!("private key: {},\n public key: {}", sk, pk);

    let (c1, c2) = encrypt(message, pk);
    println!("\nciper text: \n\t{},\n\t{}", c1, c2);

    let plaintext = decrypt((c1, c2), sk);
    let expected = hash_to_g1.hash(b"sign", message, &[]).unwrap();
    assert!(plaintext == expected);
    println!("\nDecrypted successfully!")
}
