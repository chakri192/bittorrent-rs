//! A small, deterministic mutation fuzzer for the tests.
//!
//! `cargo fuzz` needs a nightly toolchain and finds more, but it does not
//! run with `cargo test`. This does: it takes valid inputs, damages them in
//! the ways wire data gets damaged or forged (flipped bits, truncation,
//! lengths replaced by extreme values, duplicated and deleted stretches),
//! and hands every variant to a parser, which must survive all of them. A
//! fixed seed makes a failure reproducible; the failing input is printed.

use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};

/// xorshift64*: small, fast, and good enough to pick mutations.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Rng(seed | 1) // the state must not be zero
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A number in `0..n` (0 if `n` is 0).
    pub(crate) fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
}

/// Values that sit on the edges of length and offset arithmetic.
const EDGE_U32: [u32; 10] = [0, 1, 2, 0x7f, 0xff, 0xffff, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, 0xffff_ffff];

/// One to four stacked mutations of `seed`.
pub(crate) fn mutate(seed: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut v = seed.to_vec();
    for _ in 0..1 + rng.below(4) {
        match rng.below(9) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] = rng.next_u64() as u8;
            }
            2 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] = [0x00, 0x01, 0x7f, 0x80, 0xff, b'e', b'i', b'l', b'd', b':', b'-', b'0'][rng.below(12)];
            }
            3 => v.truncate(rng.below(v.len() + 1)),
            4 => {
                let at = rng.below(v.len() + 1);
                let extra: Vec<u8> = (0..1 + rng.below(16)).map(|_| rng.next_u64() as u8).collect();
                v.splice(at..at, extra);
            }
            5 if !v.is_empty() => {
                let a = rng.below(v.len());
                let b = a + rng.below(v.len() - a + 1);
                v.drain(a..b);
            }
            6 if !v.is_empty() => {
                let a = rng.below(v.len());
                let b = a + rng.below((v.len() - a).min(32) + 1);
                let chunk = v[a..b].to_vec();
                v.splice(a..a, chunk);
            }
            7 if v.len() >= 4 => {
                let at = rng.below(v.len() - 3);
                v[at..at + 4].copy_from_slice(&EDGE_U32[rng.below(EDGE_U32.len())].to_be_bytes());
            }
            8 if v.len() >= 2 => {
                let at = rng.below(v.len() - 1);
                v[at..at + 2].copy_from_slice(&(EDGE_U32[rng.below(EDGE_U32.len())] as u16).to_be_bytes());
            }
            _ => {}
        }
    }
    v
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Feeds `check` a large, reproducible set of hostile inputs derived from
/// `seeds` (which should be valid examples): each seed itself, each of its
/// prefixes, `iterations` mutations of it, and some plain noise. If `check`
/// panics, the input that did it is printed and the panic re-raised.
pub(crate) fn hammer(seeds: &[Vec<u8>], iterations: usize, mut check: impl FnMut(&[u8])) {
    let mut rng = Rng::new(0x00B1_77E4_4E27);
    let mut run = |input: &[u8]| {
        if let Err(panic) = catch_unwind(AssertUnwindSafe(|| check(input))) {
            eprintln!("robustness failure: {} bytes: {}", input.len(), hex(input));
            resume_unwind(panic);
        }
    };

    for seed in seeds {
        run(seed);
        for len in 0..seed.len() {
            run(&seed[..len]);
        }
        for _ in 0..iterations {
            run(&mutate(seed, &mut rng));
        }
    }
    // No structure at all, and the shapes that break naive length handling.
    run(&[]);
    for len in [1, 2, 3, 4, 5, 8, 9, 13, 20, 21, 26, 68, 100, 1000, 5000] {
        run(&vec![0x00; len]);
        run(&vec![0xff; len]);
        for _ in 0..50 {
            run(&(0..len).map(|_| rng.next_u64() as u8).collect::<Vec<u8>>());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_generator_is_deterministic_and_spreads_out() {
        let (mut a, mut b) = (Rng::new(7), Rng::new(7));
        let xs: Vec<u64> = (0..8).map(|_| a.next_u64()).collect();
        assert_eq!(xs, (0..8).map(|_| b.next_u64()).collect::<Vec<_>>(), "same seed, same sequence");
        assert!(xs.windows(2).all(|w| w[0] != w[1]));
        assert!((0..1000).all(|_| a.below(10) < 10));
        assert_eq!(a.below(0), 0);
    }

    #[test]
    fn mutations_change_the_input_and_cover_growth_and_shrinkage() {
        let seed = vec![7u8; 40];
        let mut rng = Rng::new(1);
        let outputs: Vec<Vec<u8>> = (0..500).map(|_| mutate(&seed, &mut rng)).collect();
        assert!(outputs.iter().any(|o| *o != seed), "it does mutate");
        assert!(outputs.iter().any(|o| o.len() > seed.len()), "some grow");
        assert!(outputs.iter().any(|o| o.len() < seed.len()), "some shrink");
        assert!(mutate(&[], &mut rng).len() <= 16, "an empty seed only ever grows a little");
    }

    #[test]
    fn hammer_tries_every_prefix_and_the_edge_shapes() {
        let mut seen = std::collections::HashSet::new();
        hammer(&[b"abcdef".to_vec()], 10, |input| {
            seen.insert(input.to_vec());
        });
        for len in 0..=6 {
            assert!(seen.contains(&b"abcdef"[..len]), "prefix of length {}", len);
        }
        assert!(seen.contains(&vec![0xff; 68]) && seen.contains(&Vec::new()));
    }

    #[test]
    fn a_panicking_check_fails_the_test_and_reports_its_input() {
        let outcome = catch_unwind(|| {
            hammer(&[b"boom".to_vec()], 0, |input| {
                assert!(input != b"boo", "the parser panics on this one");
            });
        });
        assert!(outcome.is_err(), "the panic must propagate");
    }
}
