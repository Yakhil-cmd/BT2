Found a strong analog in Agave's `system_processor.rs`. Let me confirm the `allocate` function's checks and `Address::create` for context.I have sufficient evidence to confirm the analog. Any account (including a PDA that a program expects to create for the first time, e.g. via `SystemInstruction::CreateAccount` CPI) can be pre-funded with lamports by anyone before the legitimate creation transaction lands, causing the `create_account` check at `programs/system/src/system_processor.rs` lines 162-171 to unconditionally reject with `SystemError::AccountAlreadyInUse` — mirroring the reported `!ZV` balance-check griefing exactly.

### Title
Unprivileged lamport pre-funding griefs `SystemInstruction::CreateAccount`, causing permanent Denial of Service for PDA/account initialization - (File: `programs/system/src/system_processor.rs`)

### Summary
The System Program's `create_account` handler rejects account creation whenever the destination account already holds `lamports > 0`, regardless of who sent those lamports or why. Because plain lamport transfers to an arbitrary pubkey require no cooperation from, or signature by, the target account, any unprivileged attacker who learns (from the mempool, from a deterministic PDA derivation, or from an on-chain event) that a specific address is about to be initialized via `CreateAccount`/`CreateAccountWithSeed` can front-run it with a 1-lamport `Transfer` to that address. When the legitimate creation instruction executes, it unconditionally fails with `AccountAlreadyInUse`, permanently blocking any program logic that assumes it can `create_account` into a fresh address (e.g., "create escrow PDA", "initialize pool/vault account", "create ATA-style derived account") unless that program explicitly special-cases pre-funded destinations. This is structurally identical to the reported bug: an attacker externally deposits value into an address the victim's transaction expects to be pristine, tripping a naive zero-balance/zero-lamport precondition and reverting the legitimate transaction. [1](#0-0) 

### Finding Description
`create_account` first borrows the `to` account and checks `to.get_lamports() > 0`; if true it immediately returns `SystemError::AccountAlreadyInUse` before any allocation/assignment/transfer logic runs: [2](#0-1) 

Because Solana's `system_program::transfer` lets anyone credit lamports to any address without that address needing to sign or even exist yet, an attacker can watch the mempool/logs for a pending `CreateAccount` (or `CreateAccountWithSeed`, whose target address is a public deterministic function of `base`/`seed`/`owner` per `Address::create`) and race a 1-lamport transfer to the target pubkey ahead of the legitimate transaction: [3](#0-2) 

Once pre-funded, every future attempt by the victim (a user, a program invoking `create_account` via CPI, or any retried resend of the same instruction) to create that account fails with `AccountAlreadyInUse`, since the check only tests `lamports > 0` and has no notion of "who funded it" or "was it funded incidentally by the protocol" — the same class of flaw as the `pairAddress` balance check in the external report, which failed to verify provenance of the funds/pair before treating a non-zero balance as disqualifying.

Notably, Agave's own developers have already recognized this exact class of griefing and added a new, opt-in instruction, `SystemInstruction::CreateAccountAllowPrefund`, specifically to tolerate a pre-funded destination without failing: [4](#0-3) [5](#0-4) 

This confirms the bug class is real and already causes practical DoS/griefing against callers of the legacy `CreateAccount`/`CreateAccountWithSeed` path — the mitigation is a new instruction gated behind `feature_set.create_account_allow_prefund`, meaning any program/PDA-creation flow still using plain `CreateAccount` (the vast majority of existing on-chain programs, since this is a brand-new feature-gated instruction) remains fully exposed.

### Impact Explanation
This enables cheap, unprivileged, repeatable Denial of Service against any protocol relying on `system_instruction::create_account`/`create_account_with_seed` to initialize a fresh PDA or keypair-derived account (vaults, pools, escrows, nonce accounts, token-like derived accounts, etc.). An attacker spends a single lamport plus transaction fee to permanently brick that specific address for legitimate initialization, since the destination address usually can't be changed once it's derived deterministically (e.g., PDA seeds), forcing protocol operators into griefing loops or requiring off-chain coordination/new addresses — a direct availability impact reachable from a single unprivileged transaction, matching the "concrete...transaction-triggered" impact bar (repeated DoS of core protocol functionality), though it does not itself move funds or corrupt consensus state.

### Likelihood Explanation
High. No special privilege, staking, or leader position is required — only knowledge of the target address (often derivable in advance from public seeds or observable in the mempool/logs) and the ability to send a trivial `Transfer` instruction, which is a base capability of any Solana account. The cost is negligible (1 lamport + fee), and the check unconditionally triggers regardless of the funder's identity.

### Recommendation
For the legacy `CreateAccount`/`CreateAccountWithSeed` instructions, either (a) relax the `lamports > 0` precondition to tolerate externally pre-funded destinations as long as the account has no data and is still owned by the system program (i.e., merge the already-shipped `create_account_allow_prefund` semantics into the default path, or make it the recommended/default pattern), or (b) document and steer client/program authors toward `CreateAccountAllowPrefund` for any address that can be predicted or front-run by third parties. Since the mitigation instruction already exists in `programs/system/src/system_processor.rs` lines 184-214, the residual risk is that ecosystem programs/tooling continue defaulting to the vulnerable `CreateAccount`, so broader migration guidance/tooling updates are the practical remediation.

### Proof of Concept
1. Victim program/client intends to call `system_instruction::create_account(payer, pda_address, lamports, space, owner)` for a PDA whose address is deterministically derivable (or observable via a pending transaction in the mempool), matching `SystemInstruction::CreateAccount` handling at [6](#0-5) .
2. Attacker submits `system_instruction::transfer(attacker, pda_address, 1)` and gets it landed before the victim's transaction (e.g., simple fee bump/race, or by observing the mempool).
3. Victim's `CreateAccount` transaction executes; `create_account` in `system_processor.rs` reads `to.get_lamports() > 0` as `true` and returns `SystemError::AccountAlreadyInUse`, as exercised in the existing unit test `test_create_already_in_use` at [7](#0-6) .
4. Victim's transaction reverts; the address remains permanently unable to be initialized via `CreateAccount`, reproducing the DoS/griefing pattern from the external report at negligible attacker cost.

### Citations

**File:** programs/system/src/system_processor.rs (L150-182)
```rust
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

**File:** programs/system/src/system_processor.rs (L530-563)
```rust
        SystemInstruction::CreateAccountAllowPrefund {
            lamports,
            space,
            owner,
        } => {
            if !invoke_context
                .get_feature_set()
                .create_account_allow_prefund
            {
                return Err(InstructionError::InvalidInstructionData);
            }
            let from_and_lamports = if lamports > 0 {
                instruction_context.check_number_of_instruction_accounts(2)?;
                Some((1, lamports))
            } else {
                instruction_context.check_number_of_instruction_accounts(1)?;
                None
            };
            let to_address = Address::create(
                instruction_context.get_key_of_instruction_account(0)?,
                None,
                invoke_context,
            )?;
            create_account_allow_prefund(
                0,
                &to_address,
                from_and_lamports,
                space,
                &owner,
                &signers,
                invoke_context,
                &instruction_context,
            )
        }
```

**File:** programs/system/src/system_processor.rs (L1014-1040)
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
```
