### Title
Broken Inner-Loop `continue` in `miller_rabin_u32` Causes False-Negative Primality Results, Risking Prover Panic — (`callable_oracles/src/hash_to_prime/common.rs`)

---

### Summary

`miller_rabin_u32` in `callable_oracles/src/hash_to_prime/common.rs` contains a broken loop-control statement in its inner squaring loop. When the Miller-Rabin witness condition `a^(d·2^r) ≡ −1 (mod n)` is satisfied for `r ≥ 1`, the code issues a bare `continue` that advances the **inner** `for _r` loop rather than breaking out and continuing the **outer** `for a in MILLER_RABIN_BASES` loop. Execution therefore falls through to `return false`, incorrectly classifying the prime as composite. This is the direct analog of the HybridPool "approximation loop exits early with an inaccurate value" class: an iterative convergence loop terminates without reaching the correct conclusion, and the wrong result is silently accepted.

---

### Finding Description

The standard Miller-Rabin test for a candidate `n`, with `n−1 = 2^s · d`, requires:

> For each witness base `a`: if `a^d ≡ 1` or `a^d ≡ −1 (mod n)` → base passes. Otherwise, repeatedly square up to `s−1` times; if any intermediate value equals `−1 (mod n)` → base passes. If none of these conditions hold → `n` is composite.

The code at lines 188–193 implements the "repeatedly square" sub-loop:

```rust
for _r in 1..s {
    result = mont_square_u32(result, candidate, inv);
    if result == minus_one {
        continue;          // ← continues the inner `for _r` loop, NOT the outer `for a` loop
    }
}

// no luck
return false;
```

In Rust, an unlabeled `continue` advances the **innermost** enclosing loop. Here that is `for _r in 1..s`. When `result == minus_one` is detected, the inner loop simply proceeds to the next `_r` iteration (continuing to square), and after the inner loop exhausts all `s−1` iterations, execution unconditionally falls through to `return false`. The base that should have passed is instead treated as a failure witness.

The correct fix is a labeled `continue 'outer` (or an equivalent `break` + flag):

```rust
'outer: for a in MILLER_RABIN_BASES.iter().copied() {
    ...
    for _r in 1..s {
        result = mont_square_u32(result, candidate, inv);
        if result == minus_one {
            continue 'outer;   // pass this base, try next
        }
    }
    return false;
}
``` [1](#0-0) 

---

### Impact Explanation

**Path 1 — Prover panic via `unreachable!()`.**
`compute_from_entropy` iterates over a bounded window of candidates (`for _i in 0..(1 << low_bits)`) and calls `miller_rabin_u32` on each. If the buggy test returns `false` for every prime in that window, the loop exhausts without finding a prime and hits `unreachable!()`, causing a hard panic in the prover. [2](#0-1) 

**Path 2 — Verification divergence.**
`verify_hash_to_prime` calls `miller_rabin_u32` on the reconstructed step-0 prime. If the buggy test returns `false` for a legitimately prime candidate, the function returns `false` even for a correctly-generated certificate, causing the prover to reject a valid proof. [3](#0-2) 

Both outcomes constitute **valid-execution unprovability**: a transaction that executes correctly in the forward system cannot be proven because the oracle crashes or rejects its own output.

---

### Likelihood Explanation

The bug fires for any prime `p` where, for a given base `a ∈ {2, 7, 61}`:

- `a^d ≢ 1 (mod p)` (first check passes correctly), and
- `a^d ≢ −1 (mod p)` (second check passes correctly), and
- `a^(d·2^r) ≡ −1 (mod p)` for some `r ∈ [1, s)` (inner loop check is broken).

This is the common case for primes with `s ≥ 2` (i.e., `p ≡ 1 mod 4`). Roughly half of all odd primes satisfy `p ≡ 1 mod 4`. Among those, a significant fraction will have all three bases trigger the broken path simultaneously, causing `miller_rabin_u32` to return `false` for a genuine prime. Because the entropy window is small (bounded by `1 << low_bits`), it is feasible that for specific entropy inputs the only prime(s) in the window are all misclassified, triggering `unreachable!()`.

The entropy is derived deterministically from a caller-supplied byte slice via `create_entropy` (Blake2s hash), so an attacker who can influence the input to the oracle (e.g., through transaction calldata that feeds into the hash-to-prime oracle) can search for an input that maps to a window where all primes are misclassified. [4](#0-3) [5](#0-4) 

---

### Recommendation

Replace the unlabeled `continue` with a labeled `continue` targeting the outer loop:

```rust
'bases: for a in MILLER_RABIN_BASES.iter().copied() {
    let a = mont_mul_u32(a, mont_r2, candidate, inv);
    let mut result = a;
    let bits = 32 - d.leading_zeros() - 1;
    for i in (0..bits).rev() {
        result = mont_square_u32(result, candidate, inv);
        if d & (1 << i) > 0 {
            result = mont_mul_u32(result, a, candidate, inv);
        }
    }
    if result == mont_r { continue 'bases; }
    if result == minus_one { continue 'bases; }
    for _r in 1..s {
        result = mont_square_u32(result, candidate, inv);
        if result == minus_one {
            continue 'bases;   // ← fix: exit inner loop AND advance outer loop
        }
    }
    return false;
}
```

---

### Proof of Concept

Consider `candidate = 5`. Then `n−1 = 4 = 2^2 · 1`, so `s = 2`, `d = 1`.

For base `a = 2` (in Montgomery form):
- `a^d = 2^1 = 2 mod 5`. Neither `1` nor `4` (≡ −1 mod 5).
- Inner loop `r = 1`: `result = 2^2 = 4 ≡ −1 mod 5`. The buggy `continue` advances `_r` to 2, but `1..2` only has one iteration, so the loop ends.
- Execution falls through to `return false`.

`miller_rabin_u32(5)` returns `false` even though 5 is prime. In `compute_from_entropy`, if the entropy window starting point is such that 5 is the only prime candidate in the window, `unreachable!()` is reached and the prover panics. [6](#0-5)

### Citations

**File:** callable_oracles/src/hash_to_prime/common.rs (L141-200)
```rust
pub fn miller_rabin_u32(candidate: u32) -> bool {
    if candidate & 1 == 0 {
        return false;
    }
    // prime is considered N = 2^s * d + 1;
    let tmp = candidate - 1;
    let s = tmp.trailing_zeros();
    debug_assert!(s > 0);
    let d = tmp >> s;

    // since N is odd, we can compute the Montgomery representation constant
    let mont_r = (1u64 << 32) % (candidate as u64);
    let mont_r2 = (mont_r * mont_r) % (candidate as u64);
    let mont_r = mont_r as u32;
    let mont_r2 = mont_r2 as u32;
    let minus_one = candidate - mont_r;

    let mut inv = 1u32;
    for _ in 0..31 {
        inv = inv.wrapping_mul(inv);
        inv = inv.wrapping_mul(candidate);
    }
    inv = inv.wrapping_neg();

    for a in MILLER_RABIN_BASES.iter().copied() {
        let a = mont_mul_u32(a, mont_r2, candidate, inv);
        // first check that a^d == 1 mod N

        // top bit is set
        let mut result = a;
        let bits = 32 - d.leading_zeros() - 1;
        for i in (0..bits).rev() {
            result = mont_square_u32(result, candidate, inv);
            if d & (1 << i) > 0 {
                result = mont_mul_u32(result, a, candidate, inv);
            }
        }

        if result == mont_r {
            continue;
        }

        // then {a^d)^{2^r} == -1 mod N for 0 < r < s
        if result == minus_one {
            continue;
        }

        for _r in 1..s {
            result = mont_square_u32(result, candidate, inv);
            if result == minus_one {
                continue;
            }
        }

        // no luck
        return false;
    }

    true
}
```

**File:** callable_oracles/src/hash_to_prime/compute.rs (L7-31)
```rust
pub fn compute_from_entropy(entropy: &[u8; 64]) -> HashToPrimeData {
    let mut entropy_it = entropy.iter().copied();
    let (step_0_prime, initial_n) = 'outer: {
        let (entropy_bits, low_bits) = GENERATION_STEPS[0];
        let take_bytes = entropy_bits.div_ceil(8);
        let mut repr = [0u8; 4];
        write_entropy_le(
            &mut repr[..take_bytes as usize],
            &mut entropy_it,
            entropy_bits,
        );
        let high_part = u32::from_le_bytes(repr);
        let mut candidate = high_part << low_bits;
        let mut n = 0u32;
        for _i in 0..(1 << low_bits) {
            n += 1;
            candidate += 1;
            if miller_rabin_u32(candidate) == true {
                // println!("0x{:08x} is prime", candidate);
                break 'outer (candidate, n);
            }
        }

        unreachable!()
    };
```

**File:** callable_oracles/src/hash_to_prime/verify.rs (L24-26)
```rust
        if miller_rabin_u32(candidate) != true {
            return false;
        }
```
