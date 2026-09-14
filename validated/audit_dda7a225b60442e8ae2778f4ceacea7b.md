### Title
Unauthenticated draining of any loader-owned account left in the `Uninitialized` state via `bpf_loader_upgradeable`'s `Close` instruction - (File: `programs/bpf_loader/src/lib.rs`)

### Summary
The `UpgradeableLoaderInstruction::Close` handler branches on the target account's deserialized state. For `Buffer` and `ProgramData` states it correctly requires the recorded authority to be present and to have signed the transaction, but for the `Uninitialized` branch it performs **no authority or signer check at all** before sweeping the account's lamports to an attacker-chosen recipient. Any account owned by `bpf_loader_upgradeable` that is currently in the `Uninitialized` state (e.g. a freshly `CreateAccount`'d buffer/program-data account that has not yet been initialized via `InitializeBuffer`/`DeployWithMaxDataLen`, or that is sitting between creation and initialization across transactions) can have its lamports drained by anyone, without owning, signing for, or being named as an authority on that account.

### Finding Description
In `process_loader_upgradeable_instruction`, the `Close` case is: [1](#0-0) 

```
UpgradeableLoaderInstruction::Close => {
    instruction_context.check_number_of_instruction_accounts(2)?;
    if ... index(0) == index(1) { return Err(InvalidArgument); }
    let mut close_account = instruction_context.try_borrow_instruction_account(0)?;
    let close_key = *close_account.get_key();
    let close_account_state = close_account.get_state()?;
    close_account.set_data_length(UpgradeableLoaderState::size_of_uninitialized())?;
    match close_account_state {
        UpgradeableLoaderState::Uninitialized => {
            let mut recipient_account = instruction_context.try_borrow_instruction_account(1)?;
            recipient_account.checked_add_lamports(close_account.get_lamports())?;
            close_account.set_lamports(0)?;
            ...
        }
        UpgradeableLoaderState::Buffer { authority_address } => {
            ...
            common_close_account(&authority_address, &instruction_context, &log_collector)?;
        }
        UpgradeableLoaderState::ProgramData { .. } => {
            ...
            common_close_account(&authority_address, &instruction_context, &log_collector)?;
        }
        ...
    }
}
```

Compare this to `common_close_account`, used by the `Buffer`/`ProgramData` paths, which explicitly requires an authority key match and signer check: [2](#0-1) 

The `Uninitialized` arm has no equivalent of this check — it only requires that the closing account and the recipient account differ (instruction accounts 0 and 1), and that account 0 is writable (a property the transaction author controls freely by simply listing the account as writable). There is no requirement that the caller be a signer, own the account, or be named anywhere on it.

Any account owned by `bpf_loader_upgradeable` whose data deserializes to the `Uninitialized` variant (discriminant 0, i.e. any zeroed/blank account owned by this program, such as one right after `SystemInstruction::CreateAccount` sets its owner to `bpf_loader_upgradeable` but before `InitializeBuffer` writes the `Buffer` state) satisfies `close_account_state == Uninitialized`. If such an account persists on-chain (e.g. across a transaction boundary, between the `CreateAccount` transaction and a subsequent `InitializeBuffer` transaction, or if initialization simply never completes for any reason), the account holds real lamports (funded to be rent-exempt) but is fully unprotected: anyone can submit a `Close` instruction naming that account as index 0 and any address of their choosing as index 1, and unconditionally receive all of its lamports.

This mirrors the reported bug class conceptually: a state that is expected to be transient/protected-until-initialized ("uninitialized" implementation/account) is instead directly reachable and actionable by an unprivileged caller with no ownership/authority gate, leading to unconditional fund loss for whoever funded that account.

### Impact Explanation
This allows unconditioned, signature-free transfer of lamports out of any loader-owned account sitting in the `Uninitialized` state to an attacker-controlled recipient. This is a direct "concrete unsigned fund movement" from an unprivileged transaction: the attacker need not sign for, own, or be named as authority of the drained account — they only need to know its pubkey and submit a `Close` instruction. Any dApp/tooling flow that creates a buffer/program-data account and initializes it in a later, separate transaction exposes a window during which the account's rent-exempt lamports can be stolen by a third party, and the loss is permanent (lamports are moved via `checked_add_lamports`/`set_lamports(0)`, an irreversible on-chain state change).

### Likelihood Explanation
Likelihood is bounded by how often loader-owned accounts remain in the `Uninitialized` state visible to other transactions (i.e., not atomically created+initialized within one transaction). Since account creation (`SystemInstruction::CreateAccount` with owner set to `bpf_loader_upgradeable`) and buffer/program-data initialization can be, and in practice sometimes are, split across multiple transactions or multiple instructions submitted independently (e.g. tooling that funds/creates the account first and initializes later, or partial/failed deploy flows that leave a dangling uninitialized account with lamports), there is a realistic window in which any observer of the mempool/ledger can race to submit the `Close` instruction before the legitimate initialization/close occurs.

### Recommendation
Require the same authorization discipline for the `Uninitialized` branch as for `Buffer`/`ProgramData`: either require the closing account to be a signer, or require its owner (the entity that funded/created it, tracked separately) to sign, mirroring `common_close_account`'s authority check. At minimum, disallow the no-authority-check `Uninitialized` sweep for cases where the intended owner cannot be proven, or restrict the "self-close of an all-zero account" pattern to require the recipient/authority to match the original funder recorded at creation time.

### Proof of Concept
1. Attacker (or victim, unwittingly) submits `SystemInstruction::CreateAccount` creating account `A`, assigning owner = `bpf_loader_upgradeable::id()`, sized as `UpgradeableLoaderState::size_of_buffer(...)`, funded to rent-exemption. At this point `A`'s data is all zero, i.e. `UpgradeableLoaderState::Uninitialized`.
2. Before a follow-up `InitializeBuffer` instruction executes (whether delayed to a later transaction, or the initializer's transaction simply never lands), any third party submits an instruction:
   `UpgradeableLoaderInstruction::Close` with accounts `[A (writable, index 0), attacker_recipient (writable, index 1)]`.
3. Per `programs/bpf_loader/src/lib.rs:701-709`, `close_account_state` matches `Uninitialized`; the handler immediately moves `A`'s full lamport balance to `attacker_recipient` and zeroes `A`'s lamports — no signature by `A`'s creator/owner, and no signer requirement on `A` itself, is ever checked.
4. `A`'s rent-exempt funding is now unrecoverably transferred to the attacker.

### Citations

**File:** programs/bpf_loader/src/lib.rs (L686-709)
```rust
        UpgradeableLoaderInstruction::Close => {
            instruction_context.check_number_of_instruction_accounts(2)?;
            if instruction_context.get_index_of_instruction_account_in_transaction(0)?
                == instruction_context.get_index_of_instruction_account_in_transaction(1)?
            {
                ic_logger_msg!(
                    log_collector,
                    "Recipient is the same as the account being closed"
                );
                return Err(InstructionError::InvalidArgument);
            }
            let mut close_account = instruction_context.try_borrow_instruction_account(0)?;
            let close_key = *close_account.get_key();
            let close_account_state = close_account.get_state()?;
            close_account.set_data_length(UpgradeableLoaderState::size_of_uninitialized())?;
            match close_account_state {
                UpgradeableLoaderState::Uninitialized => {
                    let mut recipient_account =
                        instruction_context.try_borrow_instruction_account(1)?;
                    recipient_account.checked_add_lamports(close_account.get_lamports())?;
                    close_account.set_lamports(0)?;

                    ic_logger_msg!(log_collector, "Closed Uninitialized {}", close_key);
                }
```

**File:** programs/bpf_loader/src/lib.rs (L1002-1018)
```rust
fn common_close_account(
    authority_address: &Option<Pubkey>,
    instruction_context: &InstructionContext,
    log_collector: &Option<Rc<RefCell<LogCollector>>>,
) -> Result<(), InstructionError> {
    if authority_address.is_none() {
        ic_logger_msg!(log_collector, "Account is immutable");
        return Err(InstructionError::Immutable);
    }
    if *authority_address != Some(*instruction_context.get_key_of_instruction_account(2)?) {
        ic_logger_msg!(log_collector, "Incorrect authority provided");
        return Err(InstructionError::IncorrectAuthority);
    }
    if !instruction_context.is_instruction_account_signer(2)? {
        ic_logger_msg!(log_collector, "Authority did not sign");
        return Err(InstructionError::MissingRequiredSignature);
    }
```
