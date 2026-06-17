### Title
Incorrect `continue` in Miller-Rabin Inner Loop Causes False Negatives in Primality Testing — (`callable_oracles/src/hash_to_prime/common.rs`)

---

### Summary

The `miller_rabin_u32` function in `callable_oracles/src/hash_to_prime/common.rs` contains a misplaced `continue` statement inside the inner squaring loop. The `continue` advances the inner loop rather than breaking out and continuing the outer witness loop. This is the direct Rust analog of the Venus Protocol bug: a `continue` that operates on the wrong loop scope, causing the algorithm to always fall through to `return false` even when a valid witness is found. The result is systematic false negatives in primality testing, which can cause `compute_from_entropy` to exhaust its search range and hit `unreachable!()`, panicking the prover.

---

### Finding Description

The Miller-Rabin test in `miller_rabin_u32` is structured as an outer loop over bases `{2, 7, 61}` and an inner loop over squarings `1..s`:

```rust
for a in MILLER_RABIN_BASES.iter().copied() {
    // ... compute result = a^d mod N ...

    if result == mont_r   { continue; }  // a^d ≡ 1  → base passes
    if result == minus_one { continue; }  // a^d ≡ -1 → base passes

    for _r in 1..s {
        result = mont_square_u32(result, candidate, inv);
        if result == minus_one {
            continue;          // ← BUG: continues inner loop, not outer loop
        }
    }

    // no luck
    return false;
}
true
```

When `result == minus_one` is found inside the inner loop, the correct action is to **break** out of the inner loop and **continue** the outer loop (this base has witnessed probable primality). Instead, the unlabeled `continue` merely advances `_r` to the next iteration — which would happen anyway since there is no code after the `if`. The inner loop always runs to completion, and `return false` is unconditionally reached for any prime whose witness satisfies `a^(d·2^r) ≡ −1 (mod N)` for some `r ∈ 1..s` but not `r = 0`.

The correct fix requires a labeled break/continue:

```rust
'outer: for a in MILLER_RABIN_BASES.iter().copied() {
    // ...
    for _r in 1..s {
        result = mont_square_u32(result, candidate, inv);
        if result == minus_one {
            continue 'outer;   // correct: this base passes
        }
    }
    return false;
}
``` [1](#0-0) 

---

### Impact Explanation

`compute_from_entropy` calls `miller_rabin_u32` in a bounded search loop and terminates with `unreachable!()` if no prime is found:

```rust
for _i in 0..(1 << low_bits) {
    n += 1;
    candidate += 1;
    if miller_rabin_u32(candidate) == true {
        break 'outer (candidate, n);
    }
}
unreachable!()
``` [2](#0-1) 

Because the buggy `miller_rabin_u32` rejects primes whose witnesses require the inner-loop path, a crafted entropy input can place the search window entirely over primes that the buggy test rejects, causing `unreachable!()` to be hit and the prover to panic. This is a forward-execution DoS: the block cannot be proven, halting chain progress.

Additionally, `verify_hash_to_prime` calls `miller_rabin_u32` to re-check the step-0 prime:

```rust
if miller_rabin_u32(candidate) != true {
    return false;
}
``` [3](#0-2) 

If a legitimately generated prime is one that the buggy function rejects, verification silently returns `false`, causing proof rejection for a valid block.

---

### Likelihood Explanation

The `hash_to_prime` oracle accepts entropy sourced from caller-controlled memory:

```rust
let entropy_source = read_memory_as_u8(
    memory,
    memory_region_for_request.offset,
    memory_region_for_request.len,
)
.expect("must read memory");
``` [4](#0-3) 

An oracle-data-influencing caller or prover input can supply arbitrary entropy. Because the Miller-Rabin bases `{2, 7, 61}` are fixed and the search window is small (`1 << low_bits` candidates), an attacker can offline-search for entropy values that place the window over a run of primes all requiring the inner-loop witness path, causing every candidate to be rejected and `unreachable!()` to fire. The deterministic nature of the three fixed bases makes this search tractable offline.

---

### Recommendation

Replace the unlabeled `continue` with a labeled `continue 'outer` so that finding `result == minus_one` in the inner loop correctly advances to the next Miller-Rabin base:

```rust
'outer: for a in MILLER_RABIN_BASES.iter().copied() {
    // ... compute result ...
    if result == mont_r    { continue 'outer; }
    if result == minus_one { continue 'outer; }

    for _r in 1..s {
        result = mont_square_u32(result, candidate, inv);
        if result == minus_one {
            continue 'outer;   // ← fix
        }
    }

    return false;
}
true
``` [5](#0-4) 

---

### Proof of Concept

Consider any prime `p` where, for base `a = 2`, `2^d ≢ ±1 (mod p)` but `2^(d·2) ≡ −1 (mod p)` (i.e., `s ≥ 2` and the witness is found at `r = 1`).

With the correct algorithm: inner loop finds `result == minus_one` at `_r = 1`, breaks, outer loop continues → base 2 passes → `p` is accepted as prime.

With the buggy algorithm: inner loop finds `result == minus_one` at `_r = 1`, `continue` advances to `_r = 2`, squaring `minus_one` yields `1`, loop completes, `return false` is reached → `p` is incorrectly rejected.

An attacker crafts entropy such that the search window `[high_part << low_bits, high_part << low_bits + (1 << low_bits))` contains only primes of this form. `compute_from_entropy` exhausts the window without finding an accepted prime and hits `unreachable!()`, panicking the prover process. [6](#0-5) [7](#0-6)

### Citations

**File:** callable_oracles/src/hash_to_prime/common.rs (L165-199)
```rust
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

**File:** callable_oracles/src/hash_to_prime/compute.rs (L21-31)
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
    };
```

**File:** callable_oracles/src/hash_to_prime/verify.rs (L24-26)
```rust
        if miller_rabin_u32(candidate) != true {
            return false;
        }
```

**File:** callable_oracles/src/hash_to_prime/evaluate.rs (L29-34)
```rust
        let entropy_source = read_memory_as_u8(
            memory,
            memory_region_for_request.offset,
            memory_region_for_request.len,
        )
        .expect("must read memory");
```
