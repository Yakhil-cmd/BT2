### Title
`Secp256r1` Precompile Missing from `new_prague` Registration Set - (`engine-precompiles/src/lib.rs`)

### Summary
The `Secp256r1` precompile (EIP-7212) is fully implemented and registered in `new_osaka`, but is absent from the `new_prague` precompile set. Any Aurora Engine instance running in Prague hard-fork mode silently drops calls to the `Secp256r1` precompile address, making it permanently unreachable for EVM users and contracts.

### Finding Description
In `engine-precompiles/src/lib.rs`, the `new_prague` constructor builds the precompile address/function vectors and passes them to `with_generic_precompiles`. It includes all BLS12-381 precompiles (EIP-2537) but omits `Secp256r1`:

```
// new_prague (lines 360–399): addresses and fun vectors
// Contains: ECRecover, SHA256, RIPEMD160, Identity, ModExp<Berlin>,
//           Bn256Add, Bn256Mul, Bn256Pair, Blake2F, RandomSeed,
//           CurrentAccount, BlsG1Add, BlsG1Msm, BlsG2Add, BlsG2Msm,
//           BlsPairingCheck, BlsMapFpToG1, BlsMapFp2ToG2
// MISSING: Secp256r1
```

By contrast, `new_osaka` (lines 409–461) correctly includes both the BLS12-381 set **and** `Secp256r1::ADDRESS` / `Box::new(Secp256r1)`.

EIP-7212 (secp256r1 precompile at address `0x0000…0100`) is part of the Prague/Pectra hard fork. Its omission from `new_prague` means the precompile is unreachable in Prague mode.

The dispatch path in `execute()` is:

```rust
let result = match self.all_precompiles.get(&address)? {  // returns None → no precompile
```

When `get` returns `None`, `execute()` returns `None`, and the EVM treats the target address as a regular (empty) contract. The call succeeds with empty return data rather than reverting, so callers receive a silent wrong result.

### Impact Explanation
Any EVM contract or user that calls the secp256r1 precompile address on a Prague-configured Aurora Engine receives empty return data instead of a valid signature-verification result. Contracts that gate fund withdrawals or access control on a secp256r1 signature check will either:
- Silently accept an invalid/empty result as "success" (depending on how they decode the output), allowing unauthorized access, **or**
- Treat the empty result as verification failure and permanently lock user funds inside the contract.

Both outcomes fall within the allowed impact scope: **permanent freezing of funds** (Critical) or **direct theft of funds** (Critical), depending on the calling contract's logic.

### Likelihood Explanation
- Prague is a production hard-fork configuration actively used by Aurora Engine (the `new_prague` constructor is a non-dead-code, non-test path).
- Any EVM developer targeting EIP-7212 (widely used for passkey/WebAuthn-based wallets) on Aurora Prague mode will hit this silently.
- No privileged access is required; any unprivileged EVM caller invoking address `0x0000…0100` triggers the bug.

### Recommendation

```diff
  pub fn new_prague<M: ModExpAlgorithm + 'static>(
      ctx: PrecompileConstructorContext<'a, I, E, H, M>,
  ) -> Self {
      let addresses = vec![
          // ... existing entries ...
          bls12_381::BlsMapFp2ToG2::ADDRESS,
+         Secp256r1::ADDRESS,
      ];
      let fun: Vec<Box<dyn Precompile>> = vec![
          // ... existing entries ...
          Box::new(bls12_381::BlsMapFp2ToG2),
+         Box::new(Secp256r1),
      ];
```

### Proof of Concept

1. Deploy Aurora Engine with `new_prague` precompile set.
2. From any EVM account, call address `0x0000000000000000000000000000000000000100` (the secp256r1 precompile) with a valid P-256 signature payload.
3. Observe: `execute()` returns `None` (address not in `all_precompiles` map); the EVM executes the empty account at that address and returns `(success, "")`.
4. A contract checking `abi.decode(result, (uint256))` receives `0` — indistinguishable from a failed verification — permanently blocking any withdrawal path gated on secp256r1.

Root cause lines: [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** engine-precompiles/src/lib.rs (L134-157)
```rust
    fn execute(
        &self,
        handle: &mut impl PrecompileHandle,
    ) -> Option<Result<executor::stack::PrecompileOutput, PrecompileFailure>> {
        let address = Address::new(handle.code_address());

        if self.is_paused(&address) {
            return Some(Err(PrecompileFailure::Fatal {
                exit_status: ExitFatal::Other(prelude::Cow::Borrowed("ERR_PAUSED")),
            }));
        }

        let result = match self.all_precompiles.get(&address)? {
            AllPrecompiles::ExitToNear(p) => process_precompile(p, handle),
            AllPrecompiles::ExitToEthereum(p) => process_precompile(p, handle),
            AllPrecompiles::PredecessorAccount(p) => process_precompile(p, handle),
            AllPrecompiles::PrepaidGas(p) => process_precompile(p, handle),
            AllPrecompiles::PromiseResult(p) => process_precompile(p, handle),
            AllPrecompiles::CrossContractCall(p) => process_handle_based_precompile(p, handle),
            AllPrecompiles::Generic(p) => process_precompile(p.as_ref(), handle),
        };

        Some(result.and_then(|output| post_process(output, handle)))
    }
```

**File:** engine-precompiles/src/lib.rs (L357-407)
```rust
    pub fn new_prague<M: ModExpAlgorithm + 'static>(
        ctx: PrecompileConstructorContext<'a, I, E, H, M>,
    ) -> Self {
        let addresses = vec![
            ECRecover::ADDRESS,
            SHA256::ADDRESS,
            RIPEMD160::ADDRESS,
            Identity::ADDRESS,
            ModExp::<Berlin, M>::ADDRESS,
            Bn256Add::<Istanbul>::ADDRESS,
            Bn256Mul::<Istanbul>::ADDRESS,
            Bn256Pair::<Istanbul>::ADDRESS,
            Blake2F::ADDRESS,
            RandomSeed::ADDRESS,
            CurrentAccount::ADDRESS,
            bls12_381::BlsG1Add::ADDRESS,
            bls12_381::BlsG1Msm::ADDRESS,
            bls12_381::BlsG2Add::ADDRESS,
            bls12_381::BlsG2Msm::ADDRESS,
            bls12_381::BlsPairingCheck::ADDRESS,
            bls12_381::BlsMapFpToG1::ADDRESS,
            bls12_381::BlsMapFp2ToG2::ADDRESS,
        ];
        let fun: Vec<Box<dyn Precompile>> = vec![
            Box::new(ECRecover),
            Box::new(SHA256),
            Box::new(RIPEMD160),
            Box::new(Identity),
            Box::new(ModExp::<Berlin, M>::new()),
            Box::new(Bn256Add::<Istanbul>::new()),
            Box::new(Bn256Mul::<Istanbul>::new()),
            Box::new(Bn256Pair::<Istanbul>::new()),
            Box::new(Blake2F),
            Box::new(RandomSeed::new(ctx.random_seed)),
            Box::new(CurrentAccount::new(ctx.current_account_id.clone())),
            Box::new(bls12_381::BlsG1Add),
            Box::new(bls12_381::BlsG1Msm),
            Box::new(bls12_381::BlsG2Add),
            Box::new(bls12_381::BlsG2Msm),
            Box::new(bls12_381::BlsPairingCheck),
            Box::new(bls12_381::BlsMapFpToG1),
            Box::new(bls12_381::BlsMapFp2ToG2),
        ];
        let map = addresses
            .into_iter()
            .zip(fun)
            .map(|(a, f)| (a, AllPrecompiles::Generic(f)))
            .collect();

        Self::with_generic_precompiles(map, ctx)
    }
```

**File:** engine-precompiles/src/lib.rs (L409-461)
```rust
    pub fn new_osaka<M: ModExpAlgorithm + 'static>(
        ctx: PrecompileConstructorContext<'a, I, E, H, M>,
    ) -> Self {
        let addresses = vec![
            ECRecover::ADDRESS,
            SHA256::ADDRESS,
            RIPEMD160::ADDRESS,
            Identity::ADDRESS,
            ModExp::<Osaka, M>::ADDRESS,
            Bn256Add::<Istanbul>::ADDRESS,
            Bn256Mul::<Istanbul>::ADDRESS,
            Bn256Pair::<Istanbul>::ADDRESS,
            Blake2F::ADDRESS,
            RandomSeed::ADDRESS,
            CurrentAccount::ADDRESS,
            bls12_381::BlsG1Add::ADDRESS,
            bls12_381::BlsG1Msm::ADDRESS,
            bls12_381::BlsG2Add::ADDRESS,
            bls12_381::BlsG2Msm::ADDRESS,
            bls12_381::BlsPairingCheck::ADDRESS,
            bls12_381::BlsMapFpToG1::ADDRESS,
            bls12_381::BlsMapFp2ToG2::ADDRESS,
            Secp256r1::ADDRESS,
        ];
        let fun: Vec<Box<dyn Precompile>> = vec![
            Box::new(ECRecover),
            Box::new(SHA256),
            Box::new(RIPEMD160),
            Box::new(Identity),
            Box::new(ModExp::<Osaka, M>::new()),
            Box::new(Bn256Add::<Istanbul>::new()),
            Box::new(Bn256Mul::<Istanbul>::new()),
            Box::new(Bn256Pair::<Istanbul>::new()),
            Box::new(Blake2F),
            Box::new(RandomSeed::new(ctx.random_seed)),
            Box::new(CurrentAccount::new(ctx.current_account_id.clone())),
            Box::new(bls12_381::BlsG1Add),
            Box::new(bls12_381::BlsG1Msm),
            Box::new(bls12_381::BlsG2Add),
            Box::new(bls12_381::BlsG2Msm),
            Box::new(bls12_381::BlsPairingCheck),
            Box::new(bls12_381::BlsMapFpToG1),
            Box::new(bls12_381::BlsMapFp2ToG2),
            Box::new(Secp256r1),
        ];
        let map = addresses
            .into_iter()
            .zip(fun)
            .map(|(a, f)| (a, AllPrecompiles::Generic(f)))
            .collect();

        Self::with_generic_precompiles(map, ctx)
    }
```
