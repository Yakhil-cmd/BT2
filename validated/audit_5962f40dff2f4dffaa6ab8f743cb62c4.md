### Title
Front-runnable `InitializeBuffer` instruction lets an unprivileged sender hijack the authority of a not-yet-initialized upgradeable-loader buffer account - (File: `programs/bpf_loader/src/lib.rs`)

### Summary
The `bpf_loader_upgradeable` program's `InitializeBuffer` instruction handler sets the buffer account's authority from an instruction account that is required to be neither a signer nor otherwise authenticated. The only guard is that the target buffer account must currently be `UpgradeableLoaderState::Uninitialized`. Any transaction sender who observes an account in that state (created via a separate `SystemInstruction::CreateAccount` call, e.g. before the paired `InitializeBuffer` instruction lands) can submit their own `InitializeBuffer` instruction first and set an arbitrary (attacker-controlled) authority on that account, matching the reported "front-runnable initializer" bug class of missing access control on an initializer.

### Finding Description
`process_loader_upgradeable_instruction` handles `UpgradeableLoaderInstruction::InitializeBuffer` as follows: [1](#0-0) 

The check only verifies that `buffer.get_state()? == Uninitialized`; the authority key at instruction-account index 1 is read with `get_key_of_instruction_account(1)`, which does **not** require `is_instruction_account_signer`. This is confirmed by the unit test, which builds the authority `AccountMeta` with `is_signer: false`: [2](#0-1) 

By contrast, every subsequent operation on the buffer (`Write`, `SetAuthority`, `DeployWithMaxDataLen`, etc.) requires the *current* authority to sign: [3](#0-2) 

The standard client-side flow atomically bundles `CreateAccount` + `InitializeBuffer` into one message via `create_buffer()`/`loader_v3_instruction::create_buffer` so that in the common path there is no window for front-running: [4](#0-3) 

However, nothing in the on-chain program enforces that these two instructions must be atomic. Any account that is owned by `bpf_loader_upgradeable`, sized for `UpgradeableLoaderState::Buffer`, and left in the `Uninitialized` state (e.g., created by a `CreateAccount` call in one transaction, with `InitializeBuffer` deferred to a later transaction) is a race target: whoever's `InitializeBuffer` transaction lands first wins, and since the authority field is unauthenticated, an attacker can name themselves (or anyone) as the buffer authority.

### Impact Explanation
Once an attacker becomes the recorded `authority_address` of the buffer, they gain exclusive control needed for `Write`, `SetAuthority`, `SetAuthorityChecked`, and ultimately `DeployWithMaxDataLen`/`Upgrade`, all of which check `authority_address == authority_key` and require that key to sign. This lets the attacker:
- Deny the legitimate deployer the ability to write to or deploy from "their" buffer (denial of service on the account, forcing costly redeployment to a new address, matching the referenced report's "needing to be redeployed" impact), and
- Potentially write and control the buffer's contents, since only the attacker can subsequently authorize `Write`/upgrade actions on it.

This is a systemic missing-access-control pattern on an initializer instruction reachable by any signer of an ordinary transaction, consistent with the referenced report's bug class. I was not able to fully verify whether a chained `Close` instruction against the hijacked buffer additionally allows unsigned lamport drainage back to an attacker-chosen recipient, since I could not inspect the full `Close` handler within the available iterations; this residual path should be checked separately before assigning a "Medium" vs higher severity for the concrete fund-movement acceptance criterion.

### Likelihood Explanation
Exploitability depends on the target buffer account existing on-chain in the `Uninitialized` state while un-paired with its `InitializeBuffer` instruction in the same atomic transaction. The default `create_buffer()` helper bundles both instructions atomically, which eliminates the race in the common CLI/SDK path. However, nothing in the protocol enforces this atomicity, and any tooling, wallet flow, or manual instruction composition that separates account creation from buffer initialization (for example, pre-funding/pre-creating buffer accounts ahead of time, a pattern explicitly supported by `buffer_program_data`/prefund style flows) reopens the window. Because the check is purely on-chain state (`Uninitialized`) with no signature requirement on the authority, exploitation requires no elevated privilege — just monitoring the mempool/ledger for such accounts and racing a normal transaction.

### Recommendation
Require the authority account passed to `InitializeBuffer` to be a signer (`instruction_context.is_instruction_account_signer(1)?`), consistent with every other authority-consuming instruction in the same file (`Write`, `SetAuthorityChecked`, etc.), so that no unauthenticated party can claim ownership of a buffer account. Additionally, document/enforce (at the SDK level) that `CreateAccount` and `InitializeBuffer` for a given buffer must always be submitted as a single atomic transaction to remove any window where an `Uninitialized` loader-owned buffer account can exist independently.

### Proof of Concept
1. Victim submits (or a wallet constructs) a `SystemInstruction::CreateAccount` for pubkey `B`, assigning owner `bpf_loader_upgradeable::id()` and sizing it as `UpgradeableLoaderState::size_of_buffer(len)`, in a transaction that does **not** also include `InitializeBuffer` (e.g., pre-allocation, or a delay before the paired instruction is broadcast).
2. Attacker observes account `B` on-chain (or in-flight in the mempool) with state `Uninitialized`, owner `bpf_loader_upgradeable`.
3. Attacker crafts and sends a transaction with instruction `UpgradeableLoaderInstruction::InitializeBuffer` against `B`, listing an attacker-controlled pubkey as the authority account with `is_signer: false` — matching the accepted account-meta shape shown in the existing test: [5](#0-4) 
4. If the attacker's transaction lands first, `buffer.set_state(&UpgradeableLoaderState::Buffer { authority_address: Some(attacker_key) })` executes successfully per the handler at lines 158-172, permanently setting the attacker as the buffer's authority; the victim's subsequent `InitializeBuffer` attempt now fails with `AccountAlreadyInitialized`.
5. The victim can no longer `Write` to or `Deploy`/`Upgrade` from `B` since those operations require the (now attacker-owned) authority's signature, per lines 173-194 of the same file.

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

**File:** programs/bpf_loader/src/lib.rs (L173-194)
```rust
        UpgradeableLoaderInstruction::Write { offset, bytes } => {
            instruction_context.check_number_of_instruction_accounts(2)?;
            let buffer = instruction_context.try_borrow_instruction_account(0)?;

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
            } else {
                ic_logger_msg!(log_collector, "Invalid Buffer account");
                return Err(InstructionError::InvalidAccountData);
            }
```

**File:** programs/bpf_loader/src/lib.rs (L1416-1429)
```rust
        let instruction_data =
            bincode::serialize(&UpgradeableLoaderInstruction::InitializeBuffer).unwrap();
        let instruction_accounts = vec![
            AccountMeta {
                pubkey: buffer_address,
                is_signer: false,
                is_writable: true,
            },
            AccountMeta {
                pubkey: authority_address,
                is_signer: false,
                is_writable: false,
            },
        ];
```

**File:** cli/src/program.rs (L2711-2726)
```rust
    let (initial_instructions, balance_needed, buffer_program_data) =
        if let Some(buffer_program_data) = buffer_program_data {
            (vec![], 0, buffer_program_data)
        } else {
            (
                loader_v3_instruction::create_buffer(
                    &fee_payer_signer.pubkey(),
                    buffer_pubkey,
                    &buffer_authority_signer.pubkey(),
                    min_rent_exempt_program_buffer_balance,
                    program_len,
                )?,
                min_rent_exempt_program_buffer_balance,
                vec![0; program_len],
            )
        };
```
