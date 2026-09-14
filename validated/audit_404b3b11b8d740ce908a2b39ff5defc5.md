### Title
Missing signer check on `SystemInstruction::InitializeNonceAccount` allows front-running of nonce account authority assignment - ([File: programs/system/src/system_instruction.rs])

### Summary
The `initialize_nonce_account` function in the System program only checks that the nonce account is *writable*; it never checks that the account itself (or any privileged party tied to it) is a *signer* of the transaction. This mirrors the reported `__INIT_VAULT` bug class: an initializer that assigns security-critical state (here, the durable-nonce `authorized` pubkey) with no access control, letting any unrelated transaction "win the race" to initialize the account with attacker-chosen values.

### Finding Description
`initialize_nonce_account` transitions a system-owned account from `State::Uninitialized` to `State::Initialized(data)`, embedding whatever `nonce_authority` pubkey was supplied in the instruction: [1](#0-0) 

The dispatcher for `SystemInstruction::InitializeNonceAccount` only requires one instruction account and never validates that account 0 is a signer — it just borrows it and passes it straight to `initialize_nonce_account`: [2](#0-1) 

Compare this with `allocate`/`assign`, which explicitly enforce `address.is_signer(signers)` before mutating an account's owner/space: [3](#0-2) 

Because `InitializeNonceAccount` has no equivalent signer requirement, *anyone* can submit a transaction naming a victim's already-created-but-not-yet-initialized nonce account (writable, non-signer) and set an arbitrary `authorized` pubkey (e.g. their own key) before the legitimate owner's `InitializeNonceAccount` instruction lands — exactly the "lack of access control on initialize → malicious/wrong values assigned" pattern from the report. This is only safe when `CreateAccount` and `InitializeNonceAccount` are bundled atomically in the same transaction (as `solana_system_interface`'s helper does); if a client or program splits account creation and initialization into two separate transactions/instructions, the intermediate on-chain state (system-owned, correctly-sized, funded, but `State::Uninitialized`) is a race window exploitable by any unprivileged sender.

### Impact Explanation
If a victim's nonce account is initialized by an attacker first, the attacker becomes the recorded `authority` in `nonce::state::Data`. Later, the attacker can call `WithdrawNonceAccount` (which only checks the recorded authority signs, not who funded the account) to drain the lamports the victim deposited when creating the account — resulting in unsigned fund loss for the victim without the victim ever authorizing the attacker. This is a concrete unsigned-fund-movement outcome reachable from a single unprivileged transaction sender, matching the allowed impact category (unsigned fund movement via the System program builtin).

### Likelihood Explanation
Requires the victim (wallet, program, or SDK integration) to submit `CreateAccount` and `InitializeNonceAccount` as separate transactions rather than atomically, leaving a public, observable window where the freshly-funded, correctly-sized, system-owned nonce account sits in `State::Uninitialized`. An attacker monitoring the mempool/ledger can race an `InitializeNonceAccount` instruction naming the same address with their own authority before the legitimate initialize lands. Likelihood is contingent on this non-atomic usage pattern occurring in practice; instruction ordering in the same transaction is unaffected.

### Recommendation
Require that `InitializeNonceAccount` (and any other System-program instruction that assigns a security-critical authority field to a freshly allocated account) verify that either the account itself signs, or that its designated authority/creator signs, before transitioning from `Uninitialized` to `Initialized`. At minimum, document/enforce that `CreateAccount` and `InitializeNonceAccount` must occur atomically within the same transaction, and consider adding a runtime check tying initialization to the same-transaction creation to close the race window entirely.

### Proof of Concept
1. Victim sends `CreateAccount` (funding a new account with nonce-account size/rent, owned by System) in transaction T1.
2. Before the victim's follow-up `InitializeNonceAccount` transaction lands, attacker submits transaction T2 containing `SystemInstruction::InitializeNonceAccount(attacker_pubkey)` naming the victim's new account as the sole (writable, non-signer) instruction account — this passes `initialize_nonce_account`'s only check (`account.is_writable()`), since no signer check exists: [4](#0-3) 
3. The account transitions to `State::Initialized(Data{ authority: attacker_pubkey, ... })`.
4. Attacker later calls `WithdrawNonceAccount` signed by `attacker_pubkey` to withdraw the victim-funded lamports.

### Citations

**File:** programs/system/src/system_instruction.rs (L163-211)
```rust
pub(crate) fn initialize_nonce_account(
    account: &mut BorrowedInstructionAccount,
    nonce_authority: &Pubkey,
    rent: &Rent,
    invoke_context: &InvokeContext,
) -> Result<(), InstructionError> {
    if !account.is_writable() {
        ic_msg!(
            invoke_context,
            "Initialize nonce account: Account {} must be writeable",
            account.get_key()
        );
        return Err(InstructionError::InvalidArgument);
    }

    match account.get_state::<Versions>()?.state() {
        State::Uninitialized => {
            let min_balance = rent.minimum_balance(account.get_data().len());
            if account.get_lamports() < min_balance {
                ic_msg!(
                    invoke_context,
                    "Initialize nonce account: insufficient lamports {}, need {}",
                    account.get_lamports(),
                    min_balance
                );
                return Err(InstructionError::InsufficientFunds);
            }
            let durable_nonce =
                DurableNonce::from_blockhash(&invoke_context.environment_config.blockhash);
            let data = nonce::state::Data::new(
                *nonce_authority,
                durable_nonce,
                invoke_context
                    .environment_config
                    .blockhash_lamports_per_signature,
            );
            let state = State::Initialized(data);
            account.set_state(&Versions::new(state))
        }
        State::Initialized(_) => {
            ic_msg!(
                invoke_context,
                "Initialize nonce account: Account {} state is invalid",
                account.get_key()
            );
            Err(InstructionError::InvalidAccountData)
        }
    }
}
```

**File:** programs/system/src/system_processor.rs (L82-89)
```rust
    if !address.is_signer(signers) {
        ic_msg!(
            invoke_context,
            "Allocate: 'to' account {:?} must sign",
            address
        );
        return Err(InstructionError::MissingRequiredSignature);
    }
```

**File:** programs/system/src/system_processor.rs (L448-467)
```rust
        SystemInstruction::InitializeNonceAccount(authorized) => {
            instruction_context.check_number_of_instruction_accounts(1)?;
            let mut me = instruction_context.try_borrow_instruction_account(0)?;
            #[allow(deprecated)]
            let recent_blockhashes = get_sysvar_with_account_check::recent_blockhashes(
                invoke_context,
                &instruction_context,
                1,
            )?;
            if recent_blockhashes.is_empty() {
                ic_msg!(
                    invoke_context,
                    "Initialize nonce account: recent blockhash list is empty",
                );
                return Err(SystemError::NonceNoRecentBlockhashes.into());
            }
            let rent =
                get_sysvar_with_account_check::rent(invoke_context, &instruction_context, 2)?;
            initialize_nonce_account(&mut me, &authorized, &rent, invoke_context)
        }
```
