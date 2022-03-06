extern crate core;

use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, KeyInit,
};
use aes::cipher::generic_array::{GenericArray, typenum::U16};
use rand::{Rng, SeedableRng};

const BLOCK_LEN: usize = 16;
type SliceBlock = [u8; BLOCK_LEN];
type GenericBlock = GenericArray<u8, U16>;
type CW = (GenericBlock, u8, u8);

const KEY0: SliceBlock = [0u8; BLOCK_LEN];
const KEY1: SliceBlock = [1u8; BLOCK_LEN];

struct DPF {
    cipher0: Aes128,
    cipher1: Aes128,
}

fn xor_in_memory(out: &mut [u8], input: &[u8]) {
    for i in 0..out.len() {
        out[i] ^= input[i]
    }
}

fn gen_key() -> GenericBlock {
    let mut rng = rand_chacha::ChaCha8Rng::from_entropy();
    let mut out = GenericBlock::from(rng.gen::<SliceBlock>());
    mask_msb(&mut out);
    out
}

fn get_msb(b: &GenericBlock) -> u8 {
    b.as_slice()[BLOCK_LEN - 1] >> 7
}

fn mask_msb(b: &mut GenericBlock) {
    b.as_mut_slice()[BLOCK_LEN-1] &= 0b0111_1111;
}

fn parse_s_t(mut b: GenericBlock) -> (GenericBlock, u8) {
    let t = get_msb(&b);
    mask_msb(&mut b);
    (b, t)
}

fn combine_s_t(mut s: GenericBlock, t: u8) -> GenericBlock {
    assert_eq!(get_msb(&s), 0);
    assert!(t == 0 || t == 1);
    s.as_mut_slice()[BLOCK_LEN-1] ^= t<<7;
    s
}

fn bitmul(bit: u8, block: &GenericBlock) -> GenericBlock {
    assert!(bit == 0 || bit == 1);
    if bit == 0 {
        GenericBlock::from([0u8; BLOCK_LEN])
    } else {
        *block
    }
}

impl DPF {
    pub fn new() -> DPF {
        DPF {
            cipher0: Aes128::new(&GenericArray::from(KEY0)),
            cipher1: Aes128::new(&GenericArray::from(KEY1)),
        }
    }

    fn prg(&self, seed: &GenericBlock) -> (GenericBlock, GenericBlock) {
        // check the msb is 0
        assert_eq!(seed[BLOCK_LEN - 1] >> 7, 0);

        // use fixed-key construction, i.e.,
        // G(s) = (AES_k0(s||0) xor s||0) || (AES_k1(s||0) xor s||0)
        let mut out0 = GenericArray::from(seed.clone());
        let mut out1 = GenericArray::from(seed.clone());
        self.cipher0.encrypt_block(&mut out0);
        self.cipher1.encrypt_block(&mut out1);
        xor_in_memory(out0.as_mut_slice(), seed);
        xor_in_memory(out1.as_mut_slice(), seed);

        (out0, out1)
    }

    pub fn gen(&self, a: &Vec<bool>) -> (GenericBlock, GenericBlock, Vec<CW>) {
        let n = a.len();
        let mut t0 = vec![0u8; n];
        let mut t1 = vec![1u8; n];
        let mut s0 = vec![gen_key()];
        let mut s1 = vec![gen_key()];
        let mut cw = vec![];

        for i in 0..n {
            let (l_0, r_0) = self.prg(s0.last().unwrap());
            let (mut s_l_0, t_l_0) = parse_s_t(l_0);
            let (mut s_r_0, t_r_0) = parse_s_t(r_0);

            let (l_1, r_1) = self.prg(s1.last().unwrap());
            let (mut s_l_1, t_l_1) = parse_s_t(l_1);
            let (mut s_r_1, t_r_1) = parse_s_t(r_1);

            if a[i] == false {
                // Keep <- L, Lose <- R
                xor_in_memory(&mut s_r_0, &s_r_1);
                let s_cw = s_r_0;
                let t_l_cw = t_l_0 ^ t_l_1 ^ (a[i] as u8) ^ 1;
                let t_r_cw = t_r_0 ^ t_r_1 ^ (a[i] as u8);
                cw.push((s_cw, t_l_cw, t_r_cw));

                xor_in_memory(&mut s_l_0, &bitmul(*t0.last().unwrap(), &s_cw));
                xor_in_memory(&mut s_l_1, &bitmul(*t1.last().unwrap(), &s_cw));
                s0.push(s_l_0);
                s1.push(s_l_1);
                t0.push(t_l_0 ^ (t0.last().unwrap() * t_l_cw));
                t1.push(t_l_1 ^ (t1.last().unwrap() * t_l_cw));
            } else {
                // Keep <- R, Lose <- L
                xor_in_memory(&mut s_l_0, &s_l_1);
                let s_cw = s_l_0;
                let t_l_cw = t_l_0 ^ t_l_1 ^ (a[i] as u8) ^ 1;
                let t_r_cw = t_r_0 ^ t_r_1 ^ (a[i] as u8);
                cw.push((s_cw, t_l_cw, t_r_cw));

                xor_in_memory(&mut s_r_0, &bitmul(*t0.last().unwrap(), &s_cw));
                xor_in_memory(&mut s_r_1, &bitmul(*t1.last().unwrap(), &s_cw));
                s0.push(s_r_0);
                s1.push(s_r_1);
                t0.push(t_r_0 ^ t0.last().unwrap() * t_r_cw);
                t1.push(t_r_1 ^ t1.last().unwrap() * t_r_cw);
            }
            // println!("[gen] s0={:?}, s1={:?}, t0={:?}, t1={:?}", s0.last().unwrap(), s1.last().unwrap(), t0.last().unwrap(), t1.last().unwrap());
        }
        (s0[0], s1[0], cw)
    }

    pub fn eval(&self, b: u8, k: &GenericBlock, cw: &Vec<CW>, x: &Vec<bool>) -> u8 {
        let mut t = vec![b];
        let mut s = vec![*k];
        let n = cw.len();
        for i in 0..n {
            let (s_cw, t_l_cw,  t_r_cw) = cw[i]; // TODO avoid copy
            let (mut tau_l, mut tau_r) = self.prg(s.last().unwrap());
            xor_in_memory(&mut tau_l, &bitmul(*t.last().unwrap(), &combine_s_t(s_cw, t_l_cw)));
            xor_in_memory(&mut tau_r, &bitmul(*t.last().unwrap(), &combine_s_t(s_cw, t_r_cw)));

            let (s_l, t_l) = parse_s_t(tau_l);
            let (s_r, t_r) = parse_s_t(tau_r);
            if x[i] == false {
                s.push(s_l);
                t.push(t_l);
            } else {
                s.push(s_r);
                t.push(t_r);
            }
            // println!("[eva] b={:?}, s={:?}, t={:?}", b, s.last().unwrap(), t.last().unwrap());
        }
        *t.last().unwrap()
    }
}

#[test]
fn test_block_size() {
    assert_eq!(BLOCK_LEN, 16);
    let a: SliceBlock = [0; BLOCK_LEN];
    let b: GenericBlock = GenericArray::from(a);
    assert_eq!(a.len(), b.as_slice().len());
}

#[test]
fn test_gen_key() {
    let k0 = gen_key();
    let k1 = gen_key();
    assert_ne!(k0, k1);
    assert_eq!(k0.as_slice()[BLOCK_LEN - 1] >> 7, 0);
    assert_eq!(k1.as_slice()[BLOCK_LEN - 1] >> 7, 0);
}

#[test]
fn test_parse_s_t() {
    let b = gen_key();
    let (b_out, t_out) = parse_s_t(b.clone());
    assert!(t_out == 0 || t_out == 1);
    assert_eq!(combine_s_t(b_out, t_out), b);
}

#[test]
fn test_bitmul() {
    let b = gen_key();
    assert_eq!(bitmul(0, &b), GenericArray::from([0u8; BLOCK_LEN]));
    assert_eq!(bitmul(1, &b), b);
}

#[test]
fn test_dpf_gen_3() {
    let dpf = DPF::new();
    let true_alpha = vec![false, false, false];
    let (k0, k1, cw) = dpf.gen(&true_alpha);
    assert_eq!(cw.len(), true_alpha.len());
    {
        let out0 = dpf.eval(0, &k0, &cw, &true_alpha);
        let out1 = dpf.eval(1, &k1, &cw, &true_alpha);
        assert_eq!(1, out0 ^ out1);
    }
    {
        let alpha = vec![true, false, false];
        let out0 = dpf.eval(0, &k0, &cw, &alpha);
        let out1 = dpf.eval(1, &k1, &cw, &alpha);
        assert_eq!(0, out0 ^ out1);
    }
    {
        let alpha = vec![true, true, false];
        let out0 = dpf.eval(0, &k0, &cw, &alpha);
        let out1 = dpf.eval(1, &k1, &cw, &alpha);
        assert_eq!(0, out0 ^ out1);
    }
    {
        let alpha = vec![true, true, true];
        let out0 = dpf.eval(0, &k0, &cw, &alpha);
        let out1 = dpf.eval(1, &k1, &cw, &alpha);
        assert_eq!(0, out0 ^ out1);
    }
}