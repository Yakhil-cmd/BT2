No vulnerability found for this question.

The reported bug class concerns elliptic-curve point addition in zk-circuits (`circom`'s `EllipticCurveAddUnequal`) collapsing to `0=0` when doubling equal points, allowing an attacker to forge an aggregated BLS public key. Searching nearcore's actual point-addition/aggregation code shows this exact bug class does not apply:

- The `bls12381_p1_sum` / `bls12381_p2_sum` host functions (and the multiexp variants) use `blst::blst_p1_add_or_double` / `blst::blst_p2_add_or_double`, which is precisely the "handles equal-input doubling correctly" function that the external report recommends switching to instead of the unsafe unequal-only addition formula. [1](#0-0) [2](#0-1) 

- These functions are tested for exactly the doubling case (`P + P`, `P + (-P)`, etc.), and results are validated against the `ark_bls12_381` reference library and subgroup membership checks, confirming correct handling of equal-point/doubling inputs. [3](#0-2) 

There is no circom-style or custom "unequal-point-only" addition formula reachable from a transaction/contract call in nearcore's BLS12-381 host functions, ECRecover, or any other elliptic-curve-based validation path. The specific data-validation flaw described (constraints degenerating to `0=0` on point doubling, enabling arbitrary aggregate-key selection) has no analog in the nearcore codebase examined.

### Citations

**File:** runtime/near-vm-runner/src/logic/bls12381.rs (L137-168)
```rust
        pub(crate) fn $p_sum(data: &[u8], version: u32) -> Result<Option<Vec<u8>>> {
            const ITEM_SIZE: usize = BLS_BOOL_SIZE + $BLS_P_SIZE;
            check_input_size(data, ITEM_SIZE, &format!("{}_sum", $bls12381_p))?;

            let mut res_pk = blst::$blst_p::default();

            for item_data in data.chunks_exact(ITEM_SIZE) {
                let (sign_data, point_data) = item_data.split_at(BLS_BOOL_SIZE);
                debug_assert_eq!(point_data.len(), $BLS_P_SIZE);

                let mut pk = match $parse_p(point_data, version) {
                    Some(pk) => pk,
                    None => return Ok(None),
                };

                let sign = sign_data[0];

                if sign == 1 {
                    unsafe {
                        blst::$blst_p_cneg(&mut pk, true);
                    }
                } else if sign != 0 {
                    return Ok(None);
                }

                unsafe {
                    blst::$blst_p_add_or_double(&mut res_pk, &res_pk, &pk);
                }
            }

            Ok(Some($serialize_p(&res_pk)))
        }
```

**File:** runtime/near-vm-runner/src/logic/bls12381.rs (L170-200)
```rust
        pub(crate) fn $g_multiexp(data: &[u8], version: u32) -> Result<Option<Vec<u8>>> {
            const ITEM_SIZE: usize = $BLS_P_SIZE + BLS_SCALAR_SIZE;
            check_input_size(data, ITEM_SIZE, &format!("{}_multiexp", $bls12381_p))?;

            let mut res_pk = blst::$blst_p::default();

            for item_data in data.chunks_exact(ITEM_SIZE) {
                let (point_data, scalar_data) = item_data.split_at($BLS_P_SIZE);
                debug_assert_eq!(scalar_data.len(), BLS_SCALAR_SIZE);

                let pk = match $parse_p(point_data, version) {
                    Some(pk) => pk,
                    None => return Ok(None),
                };

                if unsafe { blst::$blst_p_in_g(&pk) } != true {
                    return Ok(None);
                }

                let mut pk_mul = blst::$blst_p::default();
                unsafe {
                    blst::$blst_p_mult(&mut pk_mul, &pk, scalar_data.as_ptr(), BLS_SCALAR_SIZE * 8);
                }

                unsafe {
                    blst::$blst_p_add_or_double(&mut res_pk, &res_pk, &pk_mul);
                }
            }

            Ok(Some($serialize_p(&res_pk)))
        }
```

**File:** runtime/near-vm-runner/src/logic/tests/bls12381.rs (L494-513)
```rust
                // P + P
                // P + (-P) = (-P) + P =  0
                // P + (-(P + P))
                bolero::check!().with_type().for_each(|p: &$EPoint| {
                    let p_ser = $GOp::serialize_uncompressed_g(&p.p);

                    let pmul2 = p.p.mul(Fr::from(2));
                    let pmul2_ser = $GOp::serialize_uncompressed_g(&pmul2.into_affine());
                    assert_eq!(pmul2_ser.to_vec(), $GOp::get_sum(0, &p_ser, 0, &p_ser));

                    let pneg = p.p.neg();
                    let p_neg_ser = $GOp::serialize_uncompressed_g(&pneg);

                    assert_eq!(zero.to_vec(), $GOp::get_sum(0, &p_neg_ser, 0, &p_ser));
                    assert_eq!(zero.to_vec(), $GOp::get_sum(0, &p_ser, 0, &p_neg_ser));

                    let pmul2neg = pmul2.neg();
                    let pmul2_neg = $GOp::serialize_uncompressed_g(&pmul2neg.into_affine());
                    assert_eq!(p_neg_ser.to_vec(), $GOp::get_sum(0, &p_ser, 0, &pmul2_neg));
                });
```
