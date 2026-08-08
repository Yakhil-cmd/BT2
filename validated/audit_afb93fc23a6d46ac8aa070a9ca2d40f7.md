### Title
Unprivileged lamport-dusting front-run permanently blocks `CreateAccount`/PDA initialization at a deterministic address - (File: `programs/system/src/system_processor.rs`)

### Summary
The System Program's `create_account` handler treats *any* pre-existing lamport balance on the target address as proof the account is "already in use" and unconditionally rejects the instruction with `SystemError::AccountAlreadyInUse`. Because any unprivileged account can send lamports to an arbitrary, not-yet-created address via a plain `Transfer`, and because most program-derived addresses (PDAs) and other deterministic addresses are computable off-chain in advance, an attacker can pre-fund a target address with a trivial amount of lamports before the legitimate owner/program attempts to `CreateAccount` at that address. This permanently blocks initialization of that specific account, an on-chain analog of the Nibiru "vesting account preemption" bug where an attacker preemptively claims a deterministic address to permanently block a legitimate deployment/initialization to it.

### Finding Description
`create_account` in `programs/system/src/system_processor.rs` bails out as soon as the `to` account already holds any lamports, before performing the allocate/assign/transfer sequence: [1](#0-0) 

Specifically:
```
if to.get_lamports() > 0 {
    ic_msg!(... "Create Account: account {:?} already in use", to_address);
    return Err(SystemError::AccountAlreadyInUse.into());
}
``` [2](#0-1) 

This check is reachable by any unprivileged caller through `SystemInstruction::CreateAccount` and `SystemInstruction::CreateAccountWithSeed`, both of which route directly into `create_account`: [3](#0-2) [4](#0-3) 

The precondition an attacker needs is simply knowledge of the target address before it is created. This is trivially satisfiable for:
- Program-derived addresses (`find_program_address`) — deterministic given the program ID and seeds, both of which are frequently public/predictable (e.g., a user's own pubkey, a well-known counter, a pool ID).
- `create_account_with_seed` addresses — deterministic from `base`, `seed`, and `owner`.

Once the attacker knows the address, a single unprivileged `SystemInstruction::Transfer` of 1 lamport to that address (no signature from the target address is required for `Transfer`, only from the sender) gives the address a nonzero lamport balance while it is still owned by the System Program with zero-length data. When the legitimate program later tries to CPI into `create_account` (the standard pattern used by nearly all Anchor/native programs to initialize a PDA-backed account), the `to.get_lamports() > 0` check fires and the instruction fails with `AccountAlreadyInUse`, unconditionally and permanently, since the target address is a PDA with no private key and can never itself sign or otherwise be reset. `test_create_already_in_use` in the same file explicitly documents this behavior/expectation ("Attempt to create an account that already has lamports" → `AccountAlreadyInUse`): [5](#0-4) 

This is structurally the same bug class as the Nibiru H-01 report: an attacker preemptively "claims" (funds/marks) a deterministic address that a victim contract/program plans to initialize later, permanently preventing legitimate initialization of that specific account and orphaning any subsequent state/funds tied to it.

### Impact Explanation
Any program that derives an account address deterministically (PDA or seed-based) and relies on `CreateAccount`/`CreateAccountWithSeed` for its first-use initialization can have that specific account permanently denied initialization by an unprivileged attacker who front-runs it with a 1-lamport transfer. This causes a permanent, address-specific denial of service: the intended account can never be created at that address, and any downstream logic (escrow accounts, pool accounts, associated-token-style PDAs implemented via raw `create_account`, vesting/lock accounts, etc.) that depends on that address is blocked indefinitely, mirroring the "permanently frozen/inaccessible account" impact category. The attacker's griefing cost is minimal (a few lamports plus one transfer's fee), and the target's cost to work around it (deriving a new seed/bump) may not always be feasible if the address is externally fixed (e.g., referenced by other on-chain state, cross-program integrations, or already advertised to users).

### Likelihood Explanation
Likelihood is moderate-to-high for programs that use raw `CreateAccount`/`CreateAccountWithSeed` CPI for PDA initialization without pre-checking or defensively handling an already-funded target (a common and long-documented Solana development pitfall). It requires only a single unprivileged transaction and no special timing beyond acting before the legitimate creation transaction lands, making it broadly reachable by any unprivileged user. It is mitigated in practice by developers who additionally check account state/ownership rather than relying solely on the System Program's success/failure, or who use associated patterns that tolerate prefunding (note the newer `CreateAccountAllowPrefund` instruction path exists precisely to work around this class of issue): [6](#0-5) 

### Recommendation
- Treat this as an inherent account-model characteristic that application developers must defend against, but consider hardening the primitive itself: prefer directing new integrations toward `create_account_allow_prefund` (already gated by `create_account_allow_prefund` feature) instead of the legacy `create_account` lamports-only-in-use check, since it explicitly tolerates prefunding while still enforcing data/owner-based "already in use" checks.
- Audit built-in/native programs and widely used on-chain patterns that still call the legacy `CreateAccount`/`CreateAccountWithSeed` for PDA initialization and encourage migration to prefund-tolerant creation flows or to `Allocate`+`Assign` semantics that only checks data length and owner (not lamports) for "in use" determination: [7](#0-6) 
- Document this attack surface prominently for program developers (akin to Nibiru's mitigation of disabling the vulnerable vesting feature at the module level) so that security-critical PDA initializations are not implemented with the vulnerable `to.get_lamports() > 0` guard as their sole "already initialized" signal.

### Proof of Concept
1. Attacker computes the deterministic target address the victim program will use, e.g. `find_program_address(seeds, program_id)` for a PDA the victim intends to `CreateAccount` into, or `Pubkey::create_with_seed(base, seed, owner)` for a seed-derived address.
2. Attacker submits an unprivileged `SystemInstruction::Transfer` sending 1 lamport from their own funded account to the computed target address. This succeeds unconditionally regardless of the target's current owner/data because `transfer` only requires the sender to sign.
3. Victim's program later issues (directly or via CPI) `SystemInstruction::CreateAccount` (or `CreateAccountWithSeed`) targeting that same address as part of normal initialization logic.
4. In `create_account` (`programs/system/src/system_processor.rs:149-182`), the check `to.get_lamports() > 0` evaluates true (lamports == 1 from step 2), and the instruction fails with `SystemError::AccountAlreadyInUse`, exactly as asserted by the existing unit test `test_create_already_in_use`'s "already has lamports" case: [5](#0-4) 
5. Because the target address is a PDA (no corresponding private key) or otherwise not controlled by the victim, the victim cannot reclaim/reset it, and the intended account initialization is permanently blocked at that address.

### Citations

**File:** programs/system/src/system_processor.rs (L91-100)
```rust
    // if it looks like the `to` account is already in use, bail
    //   (note that the id check is also enforced by message_processor)
    if !account.get_data().is_empty() || !system_program::check_id(account.get_owner()) {
        ic_msg!(
            invoke_context,
            "Allocate: account {:?} already in use",
            address
        );
        return Err(SystemError::AccountAlreadyInUse.into());
    }
```

**File:** programs/system/src/system_processor.rs (L149-182)
```rust
#[allow(clippy::too_many_arguments)]
fn create_account(
    from_account_index: IndexOfAccount,
    to_account_index: IndexOfAccount,
    to_address: &Address,
    lamports: u64,
    space: u64,
    owner: &Pubkey,
    signers: &HashSet<Pubkey>,
    invoke_context: &InvokeContext,
    instruction_context: &InstructionContext,
) -> Result<(), InstructionError> {
    // if it looks like the `to` account is already in use, bail
    {
        let mut to = instruction_context.try_borrow_instruction_account(to_account_index)?;
        if to.get_lamports() > 0 {
            ic_msg!(
                invoke_context,
                "Create Account: account {:?} already in use",
                to_address
            );
            return Err(SystemError::AccountAlreadyInUse.into());
        }

        allocate_and_assign(&mut to, to_address, space, owner, signers, invoke_context)?;
    }
    transfer(
        from_account_index,
        to_account_index,
        lamports,
        invoke_context,
        instruction_context,
    )
}
```

**File:** programs/system/src/system_processor.rs (L184-214)
```rust
/// Create a new account without checking for 0 lamports. All other checks remain.
/// Intended for use where account has already had rent paid in whole or in part
/// before creation.
#[allow(clippy::too_many_arguments)]
fn create_account_allow_prefund(
    to_account_index: IndexOfAccount,
    to_address: &Address,
    from_and_lamports: Option<(IndexOfAccount, u64)>,
    space: u64,
    owner: &Pubkey,
    signers: &HashSet<Pubkey>,
    invoke_context: &InvokeContext,
    instruction_context: &InstructionContext,
) -> Result<(), InstructionError> {
    {
        let mut to = instruction_context.try_borrow_instruction_account(to_account_index)?;
        allocate_and_assign(&mut to, to_address, space, owner, signers, invoke_context)?;
    }
    if let Some((from_account_index, lamports)) = from_and_lamports
        && lamports > 0
    {
        transfer(
            from_account_index,
            to_account_index,
            lamports,
            invoke_context,
            instruction_context,
        )?;
    }
    Ok(())
}
```

**File:** programs/system/src/system_processor.rs (L330-352)
```rust
        SystemInstruction::CreateAccount {
            lamports,
            space,
            owner,
        } => {
            instruction_context.check_number_of_instruction_accounts(2)?;
            let to_address = Address::create(
                instruction_context.get_key_of_instruction_account(1)?,
                None,
                invoke_context,
            )?;
            create_account(
                0,
                1,
                &to_address,
                lamports,
                space,
                &owner,
                &signers,
                invoke_context,
                &instruction_context,
            )
        }
```

**File:** programs/system/src/system_processor.rs (L354-378)
```rust
        SystemInstruction::CreateAccountWithSeed {
            base,
            seed,
            lamports,
            space,
            owner,
        } => {
            instruction_context.check_number_of_instruction_accounts(2)?;
            let to_address = Address::create(
                instruction_context.get_key_of_instruction_account(1)?,
                Some((&base, &seed, &owner)),
                invoke_context,
            )?;
            create_account(
                0,
                1,
                &to_address,
                lamports,
                space,
                &owner,
                &signers,
                invoke_context,
                &instruction_context,
            )
        }
```

**File:** programs/system/src/system_processor.rs (L1014-1041)
```rust
        // Attempt to create an account that already has lamports
        let owned_account = AccountSharedData::new(1, 0, &Pubkey::default());
        let unchanged_account = owned_account.clone();
        let accounts = process_instruction(
            &bincode::serialize(&SystemInstruction::CreateAccount {
                lamports: 50,
                space: 2,
                owner: new_owner,
            })
            .unwrap(),
            vec![(from, from_account), (owned_key, owned_account)],
            vec![
                AccountMeta {
                    pubkey: from,
                    is_signer: true,
                    is_writable: false,
                },
                AccountMeta {
                    pubkey: owned_key,
                    is_signer: true,
                    is_writable: false,
                },
            ],
            Err(SystemError::AccountAlreadyInUse.into()),
        );
        assert_eq!(accounts[0].lamports(), 100);
        assert_eq!(accounts[1], unchanged_account);
    }
```
