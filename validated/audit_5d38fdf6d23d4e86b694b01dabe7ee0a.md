### Title
`InitializeBuffer` instruction in the upgradeable BPF loader sets buffer authority with no signer or ownership check, allowing front-running/hijack of program deploy buffers - (File: programs/bpf_loader/src/lib.rs)

### Summary
The `UpgradeableLoaderInstruction::InitializeBuffer` handler in `process_loader_upgradeable_instruction` only checks that the target buffer account is currently `Uninitialized`, then unconditionally writes the caller-supplied account at index 1 as the new `authority_address` — with no requirement that this account sign the instruction, and no check that the transaction sender has any prior claim to the buffer account. [1](#0-0) 

### Finding Description
When a legitimate user prepares to deploy or upgrade a program, they typically first create a buffer account (owned by `bpf_loader_upgradeable`, state `Uninitialized`) via `system_instruction::create_account`, then call `InitializeBuffer` to record the intended authority, before `Write`-ing bytecode and finally `DeployWithMaxDataLen`/`Upgrade`. The higher-level client helper (`create_buffer`) bundles the `create_account` and `InitializeBuffer` instructions into one transaction, as seen in test usage: [2](#0-1) 

However, nothing in the on-chain program enforces this pairing must be atomic. The `InitializeBuffer` handler itself has no signer requirement on account 0 (the buffer) or account 1 (the new authority) — it merely checks `UpgradeableLoaderState::Uninitialized != buffer.get_state()?` and then sets whatever pubkey is passed at index 1 as the authority: [3](#0-2) 

Once a buffer account exists on-chain in the `Uninitialized` state (which is visible to anyone, not just via mempool sniffing — it persists until initialized), any unrelated transaction sender can submit an `InitializeBuffer` instruction targeting that same buffer pubkey with an attacker-controlled authority key. Because the check is only "is the state currently Uninitialized," the first `InitializeBuffer` to land wins and locks in the authority; the legitimate follow-up `InitializeBuffer` from the real owner will then fail with `AccountAlreadyInitialized`: [4](#0-3) 

Subsequent instructions on this buffer — `Write` and `DeployWithMaxDataLen`/`Upgrade` — check that the caller-provided authority key matches the stored `authority_address` *and* that it signs the instruction: [5](#0-4) [6](#0-5) 

Since the attacker now owns the recorded authority, the legitimate deployer can never write to or deploy through that buffer — permanently blocking the intended program deployment/upgrade for that buffer account and stranding the rent-exempt lamports already paid to create it.

### Impact Explanation
This is a transaction-triggered griefing/hijack against any party deploying or upgrading a BPF program via a buffer account created and initialized as separate transactions (or where the buffer-creation transaction is publicly observable before the paired `InitializeBuffer` lands). An attacker with no special privileges — just the ability to observe an on-chain `Uninitialized` buffer account owned by `bpf_loader_upgradeable` — can permanently seize the `authority_address` field of that buffer, preventing the intended owner from ever writing program bytecode into it or using it to deploy/upgrade a program. This matches the reported bug class: insufficient access control on an "initialize" instruction that can be front-run to set attacker-controlled authority values, denying the intended contract deployment/upgrade.

### Likelihood Explanation
Exploitability depends on the buffer's `create_account` and `InitializeBuffer` instructions not being submitted atomically in the same transaction. Standard client tooling (as reflected in `runtime/src/loader_utils.rs` and the `program-test` builtins test) bundles both into a single signed message, which closes the window in the common case. The likelihood is therefore contingent on any deploy flow that separates these two steps into different transactions (e.g., retries, multi-step tooling, or scripts that create the buffer well ahead of initializing it) — a scenario this repository's own program logic does not prevent or even validate against, since the instruction handler performs no ownership/signer binding to the account creator.

### Recommendation
Require the buffer account itself (or the account's creator/authority-to-be) to sign the `InitializeBuffer` instruction, and validate that the buffer account has no unexpected prior owner assumptions — i.e., enforce that `InitializeBuffer` can only succeed when signed by the intended authority (mirroring the signer checks already present in `Write`), removing the ability for an arbitrary, non-authorized transaction sender to claim an uninitialized buffer's authority.

### Proof of Concept
1. Victim submits `system_instruction::create_account(payer, buffer_pubkey, ..., owner = bpf_loader_upgradeable::id())` in transaction T1, intending to follow up with `InitializeBuffer` in transaction T2.
2. After T1 lands (buffer account now exists, owned by `bpf_loader_upgradeable`, state `Uninitialized`), attacker observes this on-chain state and submits `InitializeBuffer` with accounts `[buffer_pubkey (writable, non-signer), attacker_pubkey (non-signer)]` before T2 confirms.
3. Per `programs/bpf_loader/src/lib.rs:158-172`, the check only verifies `Uninitialized != buffer.get_state()`, which is true, so the attacker's instruction succeeds and sets `authority_address = Some(attacker_pubkey)`.
4. Victim's T2 (`InitializeBuffer` with `authority_address = victim_pubkey`) now fails with `AccountAlreadyInitialized` (line 164), and all subsequent `Write`/`Upgrade`/`DeployWithMaxDataLen` calls by the victim fail `IncorrectAuthority`/`MissingRequiredSignature` checks (lines 183-190, 242-250), permanently blocking the victim's deployment through that buffer.

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

**File:** programs/bpf_loader/src/lib.rs (L177-190)
```rust
            if let UpgradeableLoaderState::Buffer { authority_address } = buffer.get_state()? {
                if authority_address.is_none() {
                    ic_logger_msg!(log_collector, "Buffer is immutable");
                    return Err(InstructionError::Immutable); // TODO better error code
                }
                let authority_key = Some(*instruction_context.get_key_of_instruction_account(1)?);
                if authority_address != authority_key {
                    ic_logger_msg!(log_collector, "Incorrect buffer authority provided");
                    return Err(InstructionError::IncorrectAuthority);
                }
                if !instruction_context.is_instruction_account_signer(1)? {
                    ic_logger_msg!(log_collector, "Buffer authority did not sign");
                    return Err(InstructionError::MissingRequiredSignature);
                }
```

**File:** programs/bpf_loader/src/lib.rs (L242-250)
```rust
            if let UpgradeableLoaderState::Buffer { authority_address } = buffer.get_state()? {
                if authority_address != authority_key {
                    ic_logger_msg!(log_collector, "Buffer and upgrade authority don't match");
                    return Err(InstructionError::IncorrectAuthority);
                }
                if !instruction_context.is_instruction_account_signer(7)? {
                    ic_logger_msg!(log_collector, "Upgrade authority did not sign");
                    return Err(InstructionError::MissingRequiredSignature);
                }
```

**File:** runtime/src/loader_utils.rs (L88-107)
```rust
    bank_client
        .send_and_confirm_message(
            &[from_keypair, buffer_keypair],
            Message::new(
                &solana_loader_v3_interface::instruction::create_buffer(
                    &from_keypair.pubkey(),
                    &buffer_pubkey,
                    &buffer_authority_pubkey,
                    1.max(
                        bank_client
                            .get_minimum_balance_for_rent_exemption(program_buffer_bytes)
                            .unwrap(),
                    ),
                    program.len(),
                )
                .unwrap(),
                Some(&from_keypair.pubkey()),
            ),
        )
        .unwrap();
```
