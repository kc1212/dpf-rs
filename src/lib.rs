use aes::Aes128;
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
};
use aes::cipher::generic_array::{GenericArray, typenum::U16};
use bitvec::prelude::*;
use rand::{Rng, SeedableRng};

const BLOCK_LEN: usize = 16;
type SliceBlock = [u8; BLOCK_LEN];
type GenericBlock = GenericArray<u8, U16>;
type CW = u32;

const KEY0: SliceBlock = [0u8; BLOCK_LEN];
const KEY1: SliceBlock = [1u8; BLOCK_LEN];

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

    fn prg(&self, out0: &mut GenericBlock, out1: &mut GenericBlock, seed: &GenericBlock) {
        // check the msb is 0
        assert_eq!(seed[BLOCK_LEN - 1] >> 8, 0);

        // use fixed-key construction, i.e.,
        // G(s) = (AES_k0(s||0) xor s||0) || (AES_k1(s||0) xor s||0)
        out0.copy_from_slice(&seed);
        out1.copy_from_slice(&seed);
        self.cipher0.encrypt_block(out0);
        self.cipher1.encrypt_block(out1);
        xor(out0.as_mut_slice(), seed);
        xor(out1.as_mut_slice(), seed);
    }

    fn gen(&self, alpha: u32, beta: u32) -> (GenericBlock, GenericBlock, Vec<CW>) {
        let a = alpha.view_bits::<Lsb0>();
        let mut rng = rand_chacha::ChaCha8Rng::from_entropy();
        let s0 = rng.gen::<SliceBlock>();
        let s1 = rng.gen::<SliceBlock>();
        unimplemented!()
    }
}

#[test]
fn test_block_size() {
    let a: SliceBlock = [0; BLOCK_LEN];
    let b: GenericBlock = GenericArray::from(a);
    assert_eq!(a.len(), b.as_slice().len());
}