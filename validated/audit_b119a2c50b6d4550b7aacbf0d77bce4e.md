### Title
Missing Signer/Ownership Checks in `InitializeBuffer` Allow Front-Running of Buffer Authority Assignment - (File: `programs/bpf_loader/src/lib.rs`)

### Summary
The `bpf_loader_upgradeable` program's `InitializeBuffer` instruction handler sets an arbitrary account as the buffer's `authority_address` without requiring that account, the buffer account, or any related party to sign the transaction. This mirrors the reported `GSP.sol::init` issue: an initialization routine that sets critical state (an "owner"/authority field) is callable by any unprivileged party with no access control, enabling front-running of the legitimate initializer.

### Finding Description
`process_loader_upgradeable_instruction` handles `UpgradeableLoaderInstruction::InitializeBuffer` as follows: [1](#0-0) 

The only precondition checked is that the target account's current state is `Uninitialized`; there is no signer check on account index 0 (the buffer) or account index 1 (the proposed authority). Compare this to every other authority-mutating instruction in the same file — `Write`, `SetAuthority`, `SetAuthorityChecked` — which explicitly require `instruction_context.is_instruction_account_signer(...)` before accepting a new/current authority: [2](#0-1) 

A buffer account must be created (via the System Program) before it can be initialized, and its address/owner (`bpf_loader_upgradeable`) becomes publicly visible on-chain as soon as the `create_account` transaction lands. If the buffer creation and `InitializeBuffer` call are not atomic within a single transaction (which the CLI does by default, but is not enforced by the runtime), there is a window in which the account exists in `Uninitialized` state. Any unprivileged actor can submit an `InitializeBuffer` instruction referencing that account and an arbitrary pubkey they control as `authority_address`, with no signature required from either the buffer or the claimed authority.

Once the attacker's `InitializeBuffer` transaction lands first, the account moves to `AccountAlreadyInitialized`, so the legitimate initializer's follow-up transaction fails, and the attacker is now recorded as the buffer authority — despite having paid nothing towards the account's rent-exempt balance (which was funded by the victim's `create_account`).

### Impact Explanation
Because the attacker becomes the recorded `authority_address` on the buffer, they gain the ability to:
- Call `Write` to overwrite the buffer content (which the victim funded), and/or
- Call `Close` on the `Buffer`-state account via `common_close_account`, which validates against `authority_address` and directs all lamports held by the buffer account to a recipient of the closer's choosing: [3](#0-2) 

This results in concrete unsigned fund extraction: lamports paid by the victim to fund the buffer account's rent-exemption can be redirected to an attacker-controlled recipient account, purely because `InitializeBuffer` never validated that the caller/authority is authorized to claim that role. This satisfies the "concrete unsigned fund movement" bar analogous to the reported GSP.sol front-running issue.

### Likelihood Explanation
Exploitation requires only:
1. A victim submitting two separate transactions — one to create the buffer account (System Program `create_account`, owner set to `bpf_loader_upgradeable`), and a later, separate transaction to call `InitializeBuffer`. This is a realistic pattern for tooling/scripts that don't bundle both instructions atomically (the CLI's `create_buffer` helper does bundle them, but nothing in the on-chain program enforces this).
2. An attacker (or MEV searcher) observing the mempool/leader block and racing an `InitializeBuffer` instruction referencing the same buffer address before the victim's follow-up transaction is included.

This is a standard front-running scenario reachable by any unprivileged transaction sender with no special validator/leader/network privileges, matching the required threat model.

### Recommendation
Require a signer check in `InitializeBuffer`, consistent with `Write`/`SetAuthority`/`SetAuthorityChecked`:
- Require that the buffer account itself (index 0) is a signer at creation, so `InitializeBuffer` can only be invoked as part of the same transaction that creates the account (this is how `create_buffer` client helper already constructs it, but the runtime does not currently enforce it).
- Additionally/alternatively require that the specified `authority_address` (index 1) sign the instruction, to prove consent to holding the authority role, or require the payer/creator of the account to co-sign.

### Proof of Concept
1. Victim submits Transaction A: System Program `create_account` creating `buffer_pubkey`, funded with rent-exempt lamports, owner = `bpf_loader_upgradeable`, sized via `UpgradeableLoaderState::size_of_buffer(len)`. Victim's follow-up `InitializeBuffer` transaction (Transaction B, naming victim as authority) is not yet confirmed.
2. Attacker observes `buffer_pubkey` in the `Uninitialized` state on-chain (post Transaction A, pre Transaction B) and submits Transaction C containing a single `InitializeBuffer` instruction:
   - account[0] = `buffer_pubkey` (writable, not signer)
   - account[1] = `attacker_pubkey` (not signer)
   
   No signatures from `buffer_pubkey` or `attacker_pubkey` are required per the handler at `programs/bpf_loader/src/lib.rs:158-172`.
3. If Transaction C lands before Transaction B, `buffer_pubkey`'s state becomes `Buffer { authority_address: Some(attacker_pubkey) }`. Victim's Transaction B now fails with `AccountAlreadyInitialized`.
4. Attacker submits `Close` instruction on `buffer_pubkey` with account[1] = attacker-controlled recipient and account[2] = `attacker_pubkey` as signer (matching `authority_address`), draining all lamports (originally paid by the victim) to the attacker's recipient account, per `common_close_account` logic invoked from `programs/bpf_loader/src/lib.rs:710-716`.

### Citations

**File:** programs/bpf_loader/src/lib.rs (L158-172)
```rust
        UpgradeableLoaderInstruction::InitializeBuffer => {
            instruction_context.check_number_of_instruction_accounts(2)?;
            let mut buffer = instruction_context.try_borrow_instruction_account(0)?;

            if UpgradeableLoaderState::Uninitialized != buffer.get_state()? {
                ic_logger_msg!(log_collector, "Buffer account already initialized");
                return Err(InstructionError::AccountAlreadyInitialized);
            }

            let authority_key = Some(*instruction_context.get_key_of_instruction_account(1)?);

            buffer.set_state(&UpgradeableLoaderState::Buffer {
                authority_address: authority_key,
            })?;
        }
```

**File:** programs/bpf_loader/src/lib.rs (L549-572)
```rust
        UpgradeableLoaderInstruction::SetAuthority => {
            instruction_context.check_number_of_instruction_accounts(2)?;
            let mut account = instruction_context.try_borrow_instruction_account(0)?;
            let present_authority_key = instruction_context.get_key_of_instruction_account(1)?;
            let new_authority = instruction_context.get_key_of_instruction_account(2).ok();

            match account.get_state()? {
                UpgradeableLoaderState::Buffer { authority_address } => {
                    if new_authority.is_none() {
                        ic_logger_msg!(log_collector, "Buffer authority is not optional");
                        return Err(InstructionError::IncorrectAuthority);
                    }
                    if authority_address.is_none() {
                        ic_logger_msg!(log_collector, "Buffer is immutable");
                        return Err(InstructionError::Immutable);
                    }
                    if authority_address != Some(*present_authority_key) {
                        ic_logger_msg!(log_collector, "Incorrect buffer authority provided");
                        return Err(InstructionError::IncorrectAuthority);
                    }
                    if !instruction_context.is_instruction_account_signer(1)? {
                        ic_logger_msg!(log_collector, "Buffer authority did not sign");
                        return Err(InstructionError::MissingRequiredSignature);
                    }
```

**File:** programs/bpf_loader/src/lib.rs (L710-716)
```rust
                UpgradeableLoaderState::Buffer { authority_address } => {
                    instruction_context.check_number_of_instruction_accounts(3)?;
                    drop(close_account);
                    common_close_account(&authority_address, &instruction_context, &log_collector)?;

                    ic_logger_msg!(log_collector, "Closed Buffer {}", close_key);
                }
```
