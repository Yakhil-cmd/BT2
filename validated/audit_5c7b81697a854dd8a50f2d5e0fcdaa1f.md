### Title
Secp256k1/Ed25519 precompiles report success for degenerate zero-signature instruction with no signer verified - (File: precompiles/src/secp256k1.rs, precompiles/src/ed25519.rs)

### Summary
The `secp256k1` and `ed25519` precompile `verify()` functions accept a specially-crafted "zero-signature" instruction (a minimal, degenerate instruction consisting only of the `num_signatures` header byte(s) set to `0`) and return `Ok(())`, i.e. "verified", without ever executing the signature-verification loop. This is directly analogous to the wolfSSL bug: a degenerate, signer-less object is reported as successfully verified because the check for "no signer present" is bypassed by a specific data-length condition.

### Finding Description
In `precompiles/src/secp256k1.rs::verify()`: [1](#0-0) 

the zero-signature rejection is conditioned on `data.len() > 1`:
```
let count = data[0] as usize;
if count == 0 && data.len() > 1 {
    return Err(PrecompileError::InvalidInstructionDataSize);
}
```
If the instruction data is exactly one byte (`[0]`), `count == 0` and `data.len() == 1`, so the guard does not fire. `expected_data_size` becomes `1`, which is satisfied, and the `for i in 0..count` loop (with `count == 0`) never executes any cryptographic check. The function falls through to `Ok(())` [2](#0-1) , reporting the instruction as "verified" despite zero signatures ever being parsed or checked — exactly the wolfSSL "certs-only, no signer, verify succeeds" failure mode.

The same class of bug exists in `precompiles/src/ed25519.rs::verify()`: [3](#0-2) 

```
let num_signatures = data[0] as usize;
if num_signatures == 0 && data.len() > SIGNATURE_OFFSETS_START {
    return Err(PrecompileError::InvalidInstructionDataSize);
}
```
When `data.len() == SIGNATURE_OFFSETS_START` (the minimal header size) and `num_signatures == 0`, the guard again does not fire, `expected_data_size == data.len()`, the loop `for i in 0..num_signatures` runs zero times, and the function returns `Ok(())`.

By contrast, `precompiles/src/secp256r1.rs::verify()` closes this loophole correctly — it unconditionally rejects `num_signatures == 0` regardless of `data.len()`: [4](#0-3) 

showing the secp256k1/ed25519 checks are inconsistent and under-guarded relative to the intended invariant ("a precompile instruction that claims to verify signatures must verify at least one").

These precompile `verify()` functions are the authoritative runtime signature-check routines invoked by the SVM/bank when processing a transaction containing a `secp256k1_program`/`ed25519_program` instruction (see the `PRECOMPILES` registration in `precompiles/src/lib.rs`) [5](#0-4) . A single unprivileged transaction sender can trivially construct a degenerate one-instruction transaction that includes such a minimal secp256k1/ed25519 instruction; the runtime will treat it as successfully "verified" (no `InstructionError`/`PrecompileError` is raised), even though no cryptographic signature was ever checked.

### Impact Explanation
Any on-chain program that relies on the standard Solana pattern of instruction introspection via the `sysvar::instructions` account (exercised in-repo by `programs/sbf/rust/instruction_introspection/src/lib.rs` [6](#0-5)  and by `PrecompileSignatureDetails`/`get_precompile_signature_details` in `runtime-transaction/src/signature_details.rs` [7](#0-6) ) to confirm that "a secp256k1/ed25519 verify instruction was present and succeeded" — without separately re-checking that its `num_signatures` field is non-zero — can be tricked into believing an off-chain message/signature was authenticated when it was not. This is the exact analog of the wolfSSL issue: verification reports success while zero signers were actually checked. Depending on what the relying program authorizes on that basis (e.g., releasing funds, minting, or approving a withdrawal keyed off an externally-signed message), this enables unsigned fund movement / authorization bypass triggered by a single crafted transaction.

### Likelihood Explanation
Constructing the degenerate instruction requires only building a single-byte (or minimal-header) instruction with `num_signatures = 0` and submitting it — trivially reachable by any transaction sender, no special privileges required. Exploitation impact depends on a downstream consumer trusting "instruction present + `Ok`" without checking `count > 0`, which is a widely-used and previously-flagged footgun in the Solana precompile design (the `secp256r1` verify implementation already defends against it, showing the omission in `secp256k1`/`ed25519` is inconsistent with the intended security contract).

### Recommendation
Make the zero-signature rejection in `precompiles/src/secp256k1.rs::verify()` and `precompiles/src/ed25519.rs::verify()` unconditional (matching `secp256r1.rs`), i.e. always return `PrecompileError::InvalidInstructionDataSize` when `count`/`num_signatures == 0`, regardless of `data.len()`, so that a degenerate signer-less precompile instruction can never be reported as `Ok(())`.

### Proof of Concept
1. Build a transaction whose instruction list includes a `secp256k1_program` instruction with `data = [0u8]` (a single zero byte, no offsets, no signature payload).
2. Submit the transaction. `precompiles/src/secp256k1.rs::verify()` computes `count = 0`, the guard `count == 0 && data.len() > 1` evaluates `false` (since `data.len() == 1`), `expected_data_size = 1` is satisfied, the `for i in 0..0` loop performs no verification, and the function returns `Ok(())`.
3. The transaction is accepted as having a "successfully verified" secp256k1 instruction despite zero signatures ever being cryptographically checked. Any downstream instruction-introspection consumer that only checks for the presence/success of this instruction (without checking `data[0] > 0`) is bypassed.
4. The equivalent PoC applies to the `ed25519_program` using `data` truncated to exactly `SIGNATURE_OFFSETS_START` bytes with the count byte set to `0`.

### Citations

**File:** precompiles/src/secp256k1.rs (L27-43)
```rust
) -> Result<(), PrecompileError> {
    if data.is_empty() {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    let count = data[0] as usize;
    if count == 0 && data.len() > 1 {
        // count is zero but the instruction data indicates that is probably not
        // correct, fail the instruction to catch probable invalid secp256k1
        // instruction construction.
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    let expected_data_size = count
        .saturating_mul(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
        .saturating_add(1);
    if data.len() < expected_data_size {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
```

**File:** precompiles/src/secp256k1.rs (L100-103)
```rust
        }
    }
    Ok(())
}
```

**File:** precompiles/src/ed25519.rs (L16-29)
```rust
    if data.len() < SIGNATURE_OFFSETS_START {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    let num_signatures = data[0] as usize;
    if num_signatures == 0 && data.len() > SIGNATURE_OFFSETS_START {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    let expected_data_size = num_signatures
        .saturating_mul(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
        .saturating_add(SIGNATURE_OFFSETS_START);
    // We do not check or use the byte at data[1]
    if data.len() < expected_data_size {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
```

**File:** precompiles/src/secp256r1.rs (L26-29)
```rust
    let num_signatures = data[0] as usize;
    if num_signatures == 0 {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
```

**File:** precompiles/src/lib.rs (L53-72)
```rust
/// The list of all precompiled programs
static PRECOMPILES: LazyLock<Vec<Precompile>> = LazyLock::new(|| {
    vec![
        Precompile::new(
            solana_sdk_ids::secp256k1_program::id(),
            None, // always enabled
            secp256k1::verify,
        ),
        Precompile::new(
            solana_sdk_ids::ed25519_program::id(),
            None, // always enabled
            ed25519::verify,
        ),
        Precompile::new(
            solana_sdk_ids::secp256r1_program::id(),
            None, // always enabled
            secp256r1::verify,
        ),
    ]
});
```

**File:** programs/sbf/rust/instruction_introspection/src/lib.rs (L23-42)
```rust
    let secp_instruction_index = instruction_data[0];
    let instructions_account = accounts.last().ok_or(ProgramError::NotEnoughAccountKeys)?;
    assert_eq!(*instructions_account.key, instructions::id());
    let data_len = instructions_account.try_borrow_data()?.len();
    if data_len < 2 {
        return Err(ProgramError::InvalidAccountData);
    }

    let instruction = instructions::load_instruction_at_checked(
        secp_instruction_index as usize,
        instructions_account,
    )?;

    let current_instruction = instructions::load_current_index_checked(instructions_account)?;
    let my_index = instruction_data[1] as u16;
    assert_eq!(current_instruction, my_index);

    msg!(&format!("id: {}", instruction.program_id));

    msg!(&format!("data[0]: {}", instruction.data[0]));
```

**File:** runtime-transaction/src/signature_details.rs (L60-69)
```rust
/// Get transaction signature details.
pub fn get_precompile_signature_details<'a>(
    instructions: impl Iterator<Item = (&'a Pubkey, SVMInstruction<'a>)>,
) -> PrecompileSignatureDetails {
    let mut builder = PrecompileSignatureDetailsBuilder::default();
    for (program_id, instruction) in instructions {
        builder.process_instruction(program_id, &instruction);
    }
    builder.build()
}
```
