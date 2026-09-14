I have enough evidence to establish the analog now. The key finding is in `programs/system/src/system_instruction.rs`'s `initialize_nonce_account` function, which sets a nonce account's authority without requiring any signer check — this directly mirrors the frontrunning bug class from the report.

### Title
Nonce account `InitializeNonceAccount` accepts arbitrary authority with no signer check, enabling frontrun hijack of authority - ([File: programs/system/src/system_instruction.rs])

### Summary
The Solana `system_program`'s `InitializeNonceAccount` instruction sets the durable-nonce authority field from unauthenticated instruction data, without requiring any signature from the account being initialized, its creator, or the intended authority. When a wallet/tool splits nonce-account creation into two separate transactions (`CreateAccount` then `InitializeNonceAccount`, rather than atomically combining them as `solana_system_interface::instruction::create_nonce_account` does), an unprivileged attacker can observe the pending `CreateAccount` transaction in the mempool/gossip, then race a malicious `InitializeNonceAccount` transaction naming themselves as `nonce_authority` before the legitimate initialize transaction lands. This is a direct structural analog of the reported EVM wallet-initialize frontrun: a two-step "deploy-then-initialize" pattern where the initialize step lacks an ownership/signature binding to the deployer.

### Finding Description
`SystemInstruction::CreateAccount` (handled in `programs/system/src/system_processor.rs` lines 330-352 via the `create_account` helper) requires the "to" account itself to sign, because `allocate()` at lines 75-115 enforces `address.is_signer(signers)`. This binds account creation to the new keypair. However, once the account exists (owned by `system_program`, correctly sized, and rent-exempt-funded — all done atomically within the single `CreateAccount` instruction), a subsequent, separate `InitializeNonceAccount(authorized)` instruction is processed by: [1](#0-0) 

which calls `initialize_nonce_account`: [2](#0-1) 

This function only checks that the account `is_writable()` and that its state is `Uninitialized` plus that lamports meet the rent-exempt minimum — it performs **no signer check at all**, either on the nonce account itself or on any account related to the caller. Any transaction can list the target (already-created, uninitialized) nonce-account pubkey as a writable, non-signing account and call `InitializeNonceAccount` with an attacker-controlled `authorized` pubkey. Writability of an account in a transaction requires no permission beyond not violating account-lock scheduling; it does not require ownership or a signature.

Contrast this with `withdraw_nonce_account` and `authorize_nonce_account`, both of which properly require `check_signer(&data.authority)`/`signers.contains` once the nonce is `Initialized`: [3](#0-2) 

So the *only* unauthenticated step in the nonce lifecycle is the initial `InitializeNonceAccount` call — exactly the "initialize()" step described as vulnerable in the EVM report.

### Impact Explanation
If any deploy tooling creates a nonce account and initializes it in two separate transactions instead of using the atomic `create_nonce_account` helper (a common pattern for programmatically managed nonce accounts, PDAs-adjacent flows, or batch tooling), an attacker monitoring the network can frontrun the `InitializeNonceAccount` call and set themselves as `nonce_authority`. Once they hold `authority`, they can later call `WithdrawNonceAccount` (`programs/system/src/system_instruction.rs` lines 80-161) to drain any lamports subsequently deposited into that account, since `withdraw_nonce_account` trusts `data.authority` as the sole authorization gate. This is a concrete, unsigned/attacker-authorized fund-drain path — matching the "Impact: High" classification of the original report.

### Likelihood Explanation
Medium: exploitation requires the target application to submit `CreateAccount` and `InitializeNonceAccount` as separate transactions (rather than using the SDK's atomic bundling), and requires the attacker to win a frontrun race against the second transaction. This mirrors the original report's "Likelihood: Medium, frontrun required" rating.

### Recommendation
Enforce that `InitializeNonceAccount` requires the nonce account itself (or a designated creator authority) to be a signer, closing the unauthenticated initialization window. Alternatively/additionally, encourage/require atomic bundling of `CreateAccount` + `InitializeNonceAccount` in a single transaction (as `create_nonce_account` already does) and document the frontrun risk clearly for any manual two-step usage.

### Proof of Concept
1. Victim wallet software submits transaction T1: `SystemInstruction::CreateAccount` creating account `N` (nonce-authority TBD), owned by `system_program`, funded to rent-exemption, sized for `nonce::state::State`. `N`'s keypair signs T1.
2. Victim intends to submit T2: `SystemInstruction::InitializeNonceAccount(victim_authority)` referencing `N` as account 0 (writable, non-signer).
3. Attacker observes T1 landing (or pending) and races transaction T2': `SystemInstruction::InitializeNonceAccount(attacker_pubkey)` referencing the same `N` as account 0, writable, non-signer — no signature from `N` or from any authority is required by `initialize_nonce_account`.
4. If T2' lands first, `N`'s state transitions to `Initialized(Data { authority: attacker_pubkey, .. })`. Victim's T2 then fails with `InstructionError::InvalidAccountData` (state already `Initialized`), confirming attacker has taken over.
5. Victim, believing setup succeeded or unaware of the failure, deposits SOL into `N` for durable-nonce fee usage over time.
6. Attacker calls `WithdrawNonceAccount(lamports)` with themselves as `data.authority`, passing `check_signer(&data.authority)` in `withdraw_nonce_account`, and drains `N`'s balance to their own account.

### Citations

**File:** programs/system/src/system_processor.rs (L448-466)
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
```

**File:** programs/system/src/system_instruction.rs (L99-151)
```rust
    let check_signer = |signer: &Pubkey| {
        if !signers.contains(signer) {
            ic_msg!(
                invoke_context,
                "Withdraw nonce account: Account {} must sign",
                signer
            );
            return Err(InstructionError::MissingRequiredSignature);
        }
        Ok(())
    };

    let state: Versions = from.get_state()?;
    match state.state() {
        State::Uninitialized => {
            if lamports > from.get_lamports() {
                ic_msg!(
                    invoke_context,
                    "Withdraw nonce account: insufficient lamports {}, need {}",
                    from.get_lamports(),
                    lamports,
                );
                return Err(InstructionError::InsufficientFunds);
            }
            check_signer(from.get_key())?;
        }
        State::Initialized(data) => {
            if lamports == from.get_lamports() {
                let durable_nonce =
                    DurableNonce::from_blockhash(&invoke_context.environment_config.blockhash);
                if data.durable_nonce == durable_nonce {
                    ic_msg!(
                        invoke_context,
                        "Withdraw nonce account: nonce can only advance once per slot"
                    );
                    return Err(SystemError::NonceBlockhashNotExpired.into());
                }
                check_signer(&data.authority)?;
                from.set_state(&Versions::new(State::Uninitialized))?;
            } else {
                let min_balance = rent.minimum_balance(from.get_data().len());
                let amount = checked_add(lamports, min_balance)?;
                if amount > from.get_lamports() {
                    ic_msg!(
                        invoke_context,
                        "Withdraw nonce account: insufficient lamports {}, need {}",
                        from.get_lamports(),
                        amount,
                    );
                    return Err(InstructionError::InsufficientFunds);
                }
                check_signer(&data.authority)?;
            }
```

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
