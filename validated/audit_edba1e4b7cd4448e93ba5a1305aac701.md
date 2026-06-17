### Title
Insufficient Validation of Modexp Oracle Advice Remainder Allows Malicious Prover to Forge Modular Exponentiation Results - (File: `basic_system/src/system_functions/modexp/delegation/bigint.rs`)

### Summary
In the ZKsync OS proving environment, the `OracleAdvisor` for modular exponentiation validates oracle-provided division advice using only digit-count bounds and the Euclidean identity `a = q * m + r`. It does not verify the critical constraint `r < m`. A malicious prover can supply a remainder `r ≥ m` that still satisfies `a = q * m + r` (with a correspondingly smaller quotient), causing the modexp algorithm to propagate an incorrectly reduced intermediate value and ultimately produce a wrong result that is accepted by the ZK proof verifier.

### Finding Description

In `basic_system/src/system_functions/modexp/delegation/bigint.rs`, the `OracleAdvisor::get_reduction_op_advice` function is the proving-environment implementation of the `ModexpAdvisor` trait. It is gated behind `#[cfg(any(all(target_arch = "riscv32", feature = "proving"), test))]` and is the only advisor used when generating ZK proofs. [1](#0-0) 

After receiving the oracle's `(q_len, r_len, quotient_data, remainder_data)` response, the code performs two bounds checks:

```rust
assert!(q_len.next_multiple_of(8) / 8 <= max_quotient_digits);
assert!(r_len.next_multiple_of(8) / 8 <= max_remainder_digits);
``` [2](#0-1) 

These only bound the **number of 256-bit digits**, not the **value** of the remainder. `max_remainder_digits = m.digits`, so a remainder with the same digit count as `m` but a value `≥ m` passes unchallenged.

The oracle-provided `(q, r)` are then written into `scratch_0` and `scratch_1`, and `mul_step` / `square_step` verify them with:

```rust
Self::fma(&mut scratch_3, &scratch_0, &modulus, Some(&scratch_1), ...);
// scratch_3 = q * m + r
Self::assert_eq(&scratch_2, &scratch_3);
// checks: a == q * m + r
``` [3](#0-2) 

This is the **Euclidean identity** check only. It does **not** check `

### Citations

**File:** basic_system/src/system_functions/modexp/delegation/bigint.rs (L392-411)
```rust
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

**File:** basic_system/src/system_functions/modexp/delegation/bigint.rs (L848-912)
```rust
#[cfg(any(all(target_arch = "riscv32", feature = "proving"), test))]
impl<'a, O: IOOracle> ModexpAdvisor for OracleAdvisor<'a, O> {
    fn get_reduction_op_advice<A: Allocator + Clone>(
        &mut self,
        a: &BigintRepr<A>,
        m: &BigintRepr<A>,
        quotient_dst: &mut BigintRepr<A>,
        remainder_dst: &mut BigintRepr<A>,
    ) {
        let arg: ModExpAdviceParams = {
            let a_len = a.digits;
            let a_ptr = a.backing.as_ptr();

            let modulus_len = m.digits;
            let modulus_ptr = m.backing.as_ptr();

            assert!(modulus_len > 0);

            ModExpAdviceParams {
                op: 0,
                a_ptr: a_ptr.addr() as u32,
                a_len: a_len as u32,
                b_ptr: 0,
                b_len: 0,
                modulus_ptr: modulus_ptr.addr() as u32,
                modulus_len: modulus_len as u32,
            }
        };

        // We assume that oracle's response is well-formed lengths-wise, and we will check value-wise separately
        let mut it = self
            .inner
            .raw_query(
                MODEXP_ADVICE_QUERY_ID,
                &((&arg as *const ModExpAdviceParams).addr() as u32),
            )
            .unwrap();

        let q_len = it.next().expect("quotient length");
        let r_len = it.next().expect("remainder length");

        let max_quotient_digits = if a.digits < m.digits {
            0
        } else if a.digits == m.digits {
            1
        } else {
            a.digits + 1 - m.digits
        };

        let max_remainder_digits = m.digits;

        const {
            assert!(core::mem::size_of::<usize>() == core::mem::size_of::<u32>());
        }

        // check that hint is "sane" in upper bound

        assert!(q_len.next_multiple_of(8) / 8 <= max_quotient_digits);
        assert!(r_len.next_multiple_of(8) / 8 <= max_remainder_digits);

        write_bigint(&mut it, q_len, quotient_dst);
        write_bigint(&mut it, r_len, remainder_dst);

        assert!(it.next().is_none());
    }
```
