### Title
Miller-Rabin Inner Loop `continue` Targets Wrong Scope, Producing Incorrect Primality Results - (File: `callable_oracles/src/hash_to_prime/common.rs`)

---

### Summary

The `miller_rabin_u32` function in `callable_oracles/src/hash_to_prime/common.rs` contains a loop-scope bug directly analogous to the Divergence Protocol report: a `continue` statement inside the inner squaring loop targets the **inner** loop rather than the outer witness loop. This means the "witness passes" condition (`result == minus_one`) never actually causes the algorithm to advance to the next witness — instead the inner loop keeps running and then unconditionally falls through to `return false`. The result is that many valid primes are incorrectly classified as composite, and the primality oracle produces wrong outputs.

---

### Finding Description

The Miller-Rabin test requires that for each witness `a`, if `a^(d·2^r) ≡ −1 (mod N)` for any `r` in `1..s`, the witness passes and the algorithm must move on to the next witness. In the implementation:

```rust
// callable_oracles/src/hash_to_prime/common.rs  lines 188-196
for _r in 1..s {
    result = mont_square_u32(result, candidate, inv);
    if result == minus_one {
        continue;          // ← BUG: continues inner loop, NOT outer witness loop
    }
}

// no luck
return false;
```

In Rust, `continue` inside `for _r in 1..s` advances only that inner loop. After the inner loop finishes — regardless of whether `minus_one` was ever seen — execution falls through to `return false`. The correct behaviour requires `continue 'outer` (or a boolean flag + `break`) so that finding `minus_one` skips the `return false` and moves to the next witness.

The outer loop and the two early-exit checks are correct:

```rust
// lines 165-186
for a in MILLER_RABIN_BASES.iter().copied() {   // outer witness loop
    // ...compute a^d mod N into `result`...
    if result == mont_r    { continue; }   // a^d ≡  1 mod N → witness passes ✓
    if result == minus_one { continue; }   // a^d ≡ -1 mod N → witness passes ✓

    for _r in 1..s {                       // inner squaring loop
        result = mont_square_u32(result, candidate, inv);
        if result == minus_one {
            continue;                      // ← only continues inner loop
        }
    }
    return false;                          // always reached after inner loop
}
``` [1](#0-0) 

---

### Impact Explanation

**False negatives (primes rejected as composite):** Any prime `N` for which some witness `a` satisfies `a^(d·2^r) ≡ −1 (mod N)` only for `r ≥ 1` (not `r = 0`) will be incorrectly rejected. This is the common case for primes; the `r = 0` shortcut (`a^d ≡ ±1`) is the exception.

**Panic / denial-of-service via `unreachable!()`:** `compute_from_entropy` iterates over a bounded search window and calls `miller_rabin_u32` on each candidate:

```rust
// callable_oracles/src/hash_to_prime/compute.rs  lines 21-30
for _i in 0..(1 << low_bits) {
    n += 1;
    candidate += 1;
    if miller_rabin_u32(candidate) == true {
        break 'outer (candidate, n);
    }
}
unreachable!()
``` [2](#0-1) 

If the broken test rejects every prime in the window, `unreachable!()` panics, crashing the oracle execution path.

**Verification divergence:** `verify_hash_to_prime` also calls `miller_rabin_u32`:

```rust
// callable_oracles/src/hash_to_prime/verify.rs  line 24
if miller_rabin_u32(candidate) != true {
    return false;
}
``` [3](#0-2) 

A valid prime certificate produced by an honest prover will fail verification because the broken test rejects the prime, causing a forward/proving divergence: the prover's `compute` path may accept a prime that the verifier's `verify` path rejects (or vice versa depending on which path hits the bug first).

---

### Likelihood Explanation

The bug is triggered on every call to `miller_rabin_u32` for any prime `N` where the witness condition is satisfied only at `r ≥ 1`. This is the majority of 32-bit primes. The `hash_to_prime` callable oracle is invoked during normal ZKsync OS operation; no special attacker input is required — the entropy is derived deterministically from block/transaction data. Any transaction that exercises the `hash_to_prime` oracle path will encounter this bug.

---

### Recommendation

Replace the bare `continue` with a labeled `continue` targeting the outer witness loop, or use a boolean flag:

```rust
'witness: for a in MILLER_RABIN_BASES.iter().copied() {
    // ...
    for _r in 1..s {
        result = mont_square_u32(result, candidate, inv);
        if result == minus_one {
            continue 'witness;   // ← advance to next witness, skip `return false`
        }
    }
    // no luck for this witness
    return false;
}
true
```

---

### Proof of Concept

Take the prime `N = 7`. Then `N − 1 = 6 = 2^1 · 3`, so `s = 1`, `d = 3`.

For witness `a = 2`:
- `a^d mod N = 2^3 mod 7 = 8 mod 7 = 1` → `result == mont_r` → `continue` (outer) ✓

Take the prime `N = 11`. Then `N − 1 = 10 = 2^1 · 5`, so `s = 1`, `d = 5`.

For witness `a = 2`:
- `2^5 mod 11 = 32 mod 11 = 10 = N − 1` → `result == minus_one` → `continue` (outer) ✓

Take the prime `N = 13`. Then `N − 1 = 12 = 2^2 · 3`, so `s = 2`, `d = 3`.

For witness `a = 2`:
- `2^3 mod 13 = 8` → neither `1` nor `12`
- Inner loop `r = 1`: `8^2 mod 13 = 64 mod 13 = 12 = N − 1` → `result == minus_one`
  - **Bug**: `continue` advances inner loop (but `r` is already at `s-1 = 1`, loop ends)
  - Falls through to `return false` → **13 incorrectly classified as composite**

This demonstrates that `miller_rabin_u32(13)` returns `false` despite 13 being prime, directly causing `compute_from_entropy` to skip it and potentially exhaust the search window. [4](#0-3)

### Citations

**File:** callable_oracles/src/hash_to_prime/common.rs (L141-199)
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
```

**File:** callable_oracles/src/hash_to_prime/compute.rs (L21-30)
```rust
        for _i in 0..(1 << low_bits) {
            n += 1;
            candidate += 1;
            if miller_rabin_u32(candidate) == true {
                // println!("0x{:08x} is prime", candidate);
                break 'outer (candidate, n);
            }
        }

        unreachable!()
```

**File:** callable_oracles/src/hash_to_prime/verify.rs (L24-26)
```rust
        if miller_rabin_u32(candidate) != true {
            return false;
        }
```
