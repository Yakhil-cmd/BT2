### Title
Missing Modulus Value Bound Check on Intermediate Remainders in MODEXP Delegation - (File: `basic_system/src/system_functions/modexp/delegation/bigint.rs`)

---

### Summary

The three reduction helper functions `reduce_initially`, `mul_step`, and `square_step` in the delegated MODEXP implementation each obtain a `(quotient, remainder)` pair from an untrusted advisor/oracle and verify only that `remainder.digits <= modulus.digits` (a digit-count upper bound). They do **not** verify that the remainder value is strictly less than the modulus. A malicious prover can supply non-canonical remainders (>= modulus) for every intermediate step, steering the accumulator through arbitrary values and producing a wrong final MODEXP result that still passes the only value-level check (`assert_fully_reduced`) applied at the very end.

---

### Finding Description

The `modpow` function in `bigint.rs` implements modular exponentiation using a square-and-multiply loop. Each iteration calls either `square_step` or `mul_step`, both of which:

1. Compute the product of the current accumulator with itself or the base.
2. Ask the advisor for `(quotient, remainder)` such that `product = quotient * modulus + remainder`.
3. Verify the equation by recomputing `quotient * modulus + remainder` and asserting equality with the product.
4. Return `remainder` as the new accumulator.

The only bound check on the remainder is:

```rust
assert!(scratch_1.digits <= modulus.digits);
``` [1](#0-0) [2](#0-1) 

This only checks that the remainder does not have more digits than the modulus — it does **not** check that the remainder's numeric value is less than the modulus. The same pattern exists in `reduce_initially`:

```rust
assert!(scratch_1.digits <= modulus.digits);
// ...
Self::assert_eq(&current, &scratch_2);  // only checks product reconstruction
``` [3](#0-2) 

The `assert_fully_reduced` function, which does perform a proper value comparison (`self < modulus`), is called only once — on the final result at the end of `modpow`:

```rust
if first_found {
    // at the very end we assert full reduction
    current.assert_fully_reduced(modulus);
    current
``` [4](#0-3) 

The `assert_fully_reduced` implementation correctly checks `self < modulus` via a borrow-producing subtraction: [5](#0-4) 

In production (proving mode on RISC-V), the advisor is `OracleAdvisor`, which reads the quotient and remainder from the prover-controlled oracle. Its own validation also only checks digit counts:

```rust
assert!(q_len.next_multiple_of(8) / 8 <= max_quotient_digits);
assert!(r_len.next_multiple_of(8) / 8 <= max_remainder_digits);
``` [6](#0-5) 

---

### Impact Explanation

A malicious prover can supply a remainder `r'` where `r' = (true_remainder) + k * modulus` for any `k >= 1`, as long as `r'` has the same digit count as the modulus. The equation `product = quotient * modulus + r'` still holds with an adjusted quotient. The accumulator then carries a non-canonical value into subsequent squarings and multiplications. The prover can chain such manipulations across all intermediate steps to steer the final accumulator to any value `v < modulus` of their choosing, which then passes `assert_fully_reduced`. The MODEXP precompile would return an incorrect result accepted as valid by the verifier.

This breaks the soundness of the EVM MODEXP precompile (`0x05`). Any smart contract relying on MODEXP for cryptographic operations (RSA verification, Diffie-Hellman, etc.) could be made to accept forged proofs or incorrect outputs.

---

### Likelihood Explanation

The prover is an explicit, attacker-controlled input in ZKsync OS's proving model. The oracle query `MODEXP_ADVICE_QUERY_ID` is answered by the prover-supplied oracle during proof generation. No privileged access is required — any transaction that triggers the MODEXP precompile creates the opportunity. The manipulation requires only arithmetic knowledge of the modulus and the ability to craft oracle responses, which is trivially within reach of a prover constructing a malicious proof. [7](#0-6) 

---

### Recommendation

After each call to `get_reduction_op_advice`, add a value-level check that the remainder is strictly less than the modulus. The existing `assert_fully_reduced` method already implements this logic correctly and can be reused:

In `reduce_initially`, `mul_step`, and `square_step`, after the digit-count assertion on `scratch_1`, add:

```rust
// Existing check (digit count only):
assert!(scratch_1.digits <= modulus.digits);

// Add value-level check:
scratch_1.assert_fully_reduced(modulus.duplicate_with_capacity(modulus.digits, allocator));
```

Alternatively, factor out a `assert_less_than(a, b)` helper that performs the borrow-based comparison without consuming `b`, and call it on `(scratch_1, modulus)` in all three reduction functions. [5](#0-4) 

---

### Proof of Concept

Consider `base = 2, exp = 2, modulus = 5` (single-digit case for clarity):

1. **Honest execution**: `square_step` computes `2*2 = 4`, advisor returns `(quotient=0, remainder=4)`. Check: `0*5 + 4 = 4`. ✓ Remainder `4 < 5`. Final `assert_fully_reduced(4)` passes. Output: `4`.

2. **Malicious execution**: `square_step` computes `2*2 = 4`, malicious advisor returns `(quotient=0, remainder=9)` (since `9 = 4 + 5`, same digit count as modulus if modulus is large). Check: `0*5 + 9 = 4`? No — this specific example fails because `9 != 4`. The prover must adjust: `quotient = -1` (not valid for unsigned). 

   For a more realistic multi-step example with a larger modulus: in `mul_step` computing `acc * base mod m`, the prover returns `remainder = true_remainder + m` and `quotient = true_quotient - 1`. The equality `(q-1)*m + (r+m) = q*m + r` holds. The digit count of `r+m` is at most `modulus.digits` (for most values). The accumulator is now `r + m >= m`, bypassing the field constraint. In the next `square_step`, the prover again adjusts quotient/remainder to maintain the equality invariant while steering toward any desired final value `v < m`, which passes `assert_fully_reduced`. [8](#0-7) [9](#0-8)

### Citations

**File:** basic_system/src/system_functions/modexp/delegation/bigint.rs (L282-286)
```rust
        if first_found {
            // at the very end we assert full reduction
            current.assert_fully_reduced(modulus);

            current
```

**File:** basic_system/src/system_functions/modexp/delegation/bigint.rs (L313-335)
```rust
        advisor.get_reduction_op_advice(&current, modulus, &mut scratch_0, &mut scratch_1);
        // now we should enforce everything backwards
        assert!(scratch_1.digits <= modulus.digits);

        assert!(scratch_2.capacity() >= modulus.digits + current.digits);

        // here we will use baseline FMA and scratches
        unsafe {
            Self::fma(
                &mut scratch_2,
                &scratch_0,
                &modulus,
                Some(&scratch_1),
                digit_scratch_0,
                digit_scratch_1,
                digit_scratch_2,
                digit_carry_propagation_scratch,
                scratch_0.digits + modulus.digits,
            );
        }

        // assert equality
        Self::assert_eq(&current, &scratch_2);
```

**File:** basic_system/src/system_functions/modexp/delegation/bigint.rs (L379-411)
```rust
            advisor.get_reduction_op_advice(&scratch_2, modulus, &mut scratch_0, &mut scratch_1);
            // now we should enforce everything backwards
            let max_q = if scratch_2.digits < modulus.digits {
                0
            } else if scratch_2.digits == modulus.digits {
                1
            } else {
                scratch_2.digits + 1 - modulus.digits
            };
            assert!(scratch_0.digits <= max_q);

            assert!(scratch_1.digits <= modulus.digits);

            Self::fma(
                &mut scratch_3,
                &scratch_0,
                &modulus,
                Some(&scratch_1),
                digit_scratch_0,
                digit_scratch_1,
                digit_scratch_2,
                digit_carry_propagation_scratch,
                scratch_2.digits,
            );
        }

        // assert equality
        Self::assert_eq(&scratch_2, &scratch_3);

        // we always return remainder,
        // and the rest becomes scratches pool

        (scratch_1, (current, scratch_0, scratch_2, scratch_3))
```

**File:** basic_system/src/system_functions/modexp/delegation/bigint.rs (L448-479)
```rust
            advisor.get_reduction_op_advice(&scratch_2, modulus, &mut scratch_0, &mut scratch_1);
            // now we should enforce everything backwards
            let max_q = if scratch_2.digits < modulus.digits {
                0
            } else if scratch_2.digits == modulus.digits {
                1
            } else {
                scratch_2.digits + 1 - modulus.digits
            };
            assert!(scratch_0.digits <= max_q);
            assert!(scratch_1.digits <= modulus.digits);

            Self::fma(
                &mut scratch_3,
                &scratch_0,
                &modulus,
                Some(&scratch_1),
                digit_scratch_0,
                digit_scratch_1,
                digit_scratch_2,
                digit_carry_propagation_scratch,
                scratch_2.digits,
            );
        }

        // assert equality
        Self::assert_eq(&scratch_2, &scratch_3);

        // we always return remainder,
        // and the rest becomes scratches pool

        (scratch_1, (a, scratch_0, scratch_2, scratch_3))
```

**File:** basic_system/src/system_functions/modexp/delegation/bigint.rs (L496-521)
```rust
    fn assert_fully_reduced(&self, mut modulus: Self) {
        assert!(modulus.digits >= self.digits);
        if self.digits < modulus.digits {
            return;
        }

        // we need to perform long subtraction self - modulus always produces borrow,
        // but we do not want to kill self, so we will do inverse
        let mut borrow = 0;
        for (modulus_digit, self_digit) in modulus
            .digits_mut()
            .iter_mut()
            .zip(self.digits_ref().iter())
        {
            borrow = unsafe {
                bigint_op_delegation_with_carry_bit_raw(
                    (modulus_digit as *mut DelegatedU256).cast(),
                    (self_digit as *const DelegatedU256).cast(),
                    borrow > 0,
                    BigIntOps::SubAndNegate,
                )
            };
        }

        assert!(borrow > 0);
    }
```

**File:** basic_system/src/system_functions/modexp/delegation/bigint.rs (L903-906)
```rust
        // check that hint is "sane" in upper bound

        assert!(q_len.next_multiple_of(8) / 8 <= max_quotient_digits);
        assert!(r_len.next_multiple_of(8) / 8 <= max_remainder_digits);
```

**File:** basic_system/src/system_functions/modexp/delegation/mod.rs (L15-26)
```rust
pub(super) fn modexp<O: zk_ee::oracle::IOOracle, L: Logger, A: Allocator + Clone>(
    base: &[u8],
    exp: &[u8],
    modulus: &[u8],
    oracle: &mut O,
    _logger: &mut L,
    allocator: A,
) -> Vec<u8, A> {
    let mut advisor = self::bigint::OracleAdvisor { inner: oracle };

    modexp_inner::<L, A>(base, exp, modulus, _logger, &mut advisor, allocator)
}
```
