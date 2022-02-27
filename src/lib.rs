use aes::Aes128;
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use bitvec::prelude::*;

const SECPAR: usize = 127;
const SECPAR_BYTE: usize = (SECPAR+1)/8;

type Key = [u8; SECPAR_BYTE];
type CW = [u8; SECPAR_BYTE+1];

const KEY0: Key = [0u8; 16];
const KEY1: Key = [1u8; 16];

struct DPF {
    cipher0: Aes128,
    cipher1: Aes128,
}

fn xor(out: &mut [u8], input: &[u8]) {
    for i in 0..out.len() {
        out[i] ^= input[i]
    }
}

impl DPF {
    fn new() -> DPF {
        DPF {
            cipher0: Aes128::new(&GenericArray::from(KEY0)),
            cipher1: Aes128::new(&GenericArray::from(KEY1)),
        }
    }

    fn prg(&self, seed: &Key) -> (Vec<u8>, Vec<u8>) {
        // check the msb is 0
        assert_eq!(seed[SECPAR_BYTE - 1] >> 8, 0);

        // use fixed-key construction, i.e.,
        // G(s) = (AES_k0(s||0) xor s||0) || (AES_k1(s||0) xor s||0)
        let mut out0 = GenericArray::from(seed.clone());
        let mut out1 = GenericArray::from(seed.clone());
        self.cipher0.encrypt_block(&mut out0);
        self.cipher1.encrypt_block(&mut out1);
        xor(out0.as_mut_slice(), seed);
        xor(out1.as_mut_slice(), seed);
        (out0.to_vec(), out1.to_vec())
    }

    fn gen(&self, alpha: u32, beta: u32) -> (GOut, GOut, Vec<CW>) {
        unimplemented!()
    }
}
