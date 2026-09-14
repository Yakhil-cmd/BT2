## Analog Vulnerability Found

### Title
`InitializeBuffer` instruction sets buffer authority without requiring any signature, enabling front-running/hijack of upgradeable program buffer accounts - (File: `programs/bpf_loader/src/lib.rs`)

### Summary
The `bpf_loader_upgradeable` program's `InitializeBuffer` instruction handler transitions a `Buffer` account from `Uninitialized` to `Buffer { authority_address }` using the pubkey of instruction account #1, but never checks that this account is a signer, nor that the transaction sender has any relationship to the account that created/funds the buffer. This mirrors the Sherlock finding's root cause: an externally reachable "initialize" entrypoint with no access control on who may call it or claim the resulting authority, making it front-runnable.

### Finding Description
In `process_loader_upgradeable_instruction`, the `InitializeBuffer` arm only validates that the buffer account is currently `Uninitialized`, then unconditionally sets its authority to whatever pubkey is passed as account index 1 - with `is_signer` never checked: [1](#0-0) 

Compare this to every other authority-mutating instruction in the same file (`Write`, `SetAuthority`, `SetAuthorityChecked`, `DeployWithMaxDataLen`), which all explicitly call `instruction_context.is_instruction_account_signer(...)` before honoring an authority claim, e.g. in `Write`: [2](#0-1) 

The test suite for `InitializeBuffer` itself constructs the authority account meta with `is_signer: false`, confirming the instruction is intentionally designed to accept an unsigned authority claim: [3](#0-2) 

The account-creation step (`system_instruction::create_account` funding a new keypair with `owner = bpf_loader_upgradeable`) and the `InitializeBuffer` call are two logically separate instructions. The Agave CLI happens to bundle them atomically into a single message/transaction (`loader_v3_instruction::create_buffer` produces both instructions, sent together in `do_process_write_buffer`/`do_process_program_deploy` with `initial_signer` and `fee_payer_signer` both required): [4](#0-3) [5](#0-4) 

However, nothing in the on-chain program enforces this atomicity. Any transaction sender can submit a `create_account` for a brand-new keypair with `owner = bpf_loader_upgradeable` and the correct buffer size in one transaction, and defer `InitializeBuffer` to a later, separate transaction (this is explicitly the CLI's documented "resume a failed deploy" pattern for the `--buffer` flag): [6](#0-5) 

During the window between these two transactions, the buffer account is visible on-chain as `owner = bpf_loader_upgradeable`, state = `Uninitialized`. Because `InitializeBuffer` requires no signature at all and does not check that the caller controls/paid for the account, any unprivileged party can race the legitimate owner's `InitializeBuffer` transaction and claim themselves (or any pubkey) as the buffer's authority. Once initialized by the attacker, the legitimate follow-up `InitializeBuffer` call fails with `AccountAlreadyInitialized`, and the honest party's account (and the rent-exempt lamports locked into it) is effectively hijacked/griefed, since only the (attacker-controlled) authority can subsequently `Write`, `SetAuthority`, or `Close` the buffer to recover lamports.

### Impact Explanation
This allows a stranger with no relationship to the buffer account's creator to seize control of the authority over that buffer account by racing an unsigned instruction. The impact is a denial-of-service on the affected deploy/upgrade workflow and a griefing loss of the rent-exempt lamports paid into the buffer account (the legitimate depositor cannot reclaim them without the hijacked authority's cooperation, since `Close`/`SetAuthority` both require the current, now-attacker-controlled, authority to sign). This matches the "Medium" severity class of the referenced report: loss of funds/DoS stemming from an unauthenticated initialize path, though the blast radius here is scoped to the buffer account rather than the overall program (the subsequent `DeployWithMaxDataLen`/`Upgrade` instructions independently re-validate that the supplied authority signer matches the buffer's recorded authority, so the attacker cannot smuggle malicious bytecode into an unrelated victim's program).

### Likelihood Explanation
Exploitability requires only that a victim submit the `create_account` and `InitializeBuffer` instructions in separate transactions (a documented, supported usage pattern via the CLI's `--buffer <BUFFER_SIGNER>` "resume a failed deploy" flow, or any custom client that doesn't bundle them atomically). An attacker monitoring the mempool/recent blocks for buffer accounts newly owned by `bpf_loader_upgradeable` in the `Uninitialized` state can trivially front-run with a higher-fee `InitializeBuffer` transaction naming themselves as authority — no signature or special privilege is needed to do so.

### Recommendation
Require the authority account (instruction account index 1) to be a signer in the `InitializeBuffer` handler, consistent with how `Write`, `SetAuthority`, and `SetAuthorityChecked` already validate authority signatures:
```rust
UpgradeableLoaderInstruction::InitializeBuffer => {
    instruction_context.check_number_of_instruction_accounts(2)?;
    let mut buffer = instruction_context.try_borrow_instruction_account(0)?;
    if UpgradeableLoaderState::Uninitialized != buffer.get_state()? {
        return Err(InstructionError::AccountAlreadyInitialized);
    }
    if !instruction_context.is_instruction_account_signer(1)? {
        return Err(InstructionError::MissingRequiredSignature);
    }
    let authority_key = Some(*instruction_context.get_key_of_instruction_account(1)?);
    buffer.set_state(&UpgradeableLoaderState::Buffer { authority_address: authority_key })?;
}
```
This is a consensus-affecting instruction-processing change and would require a feature-gate to activate safely across the cluster.

### Proof of Concept
1. Victim submits Tx A: `system_instruction::create_account(payer, buffer_pubkey, lamports, UpgradeableLoaderState::size_of_buffer(len), owner=bpf_loader_upgradeable::id())`, signed by `payer` and the new `buffer_pubkey` keypair. Tx A lands; `buffer_pubkey` account now exists, `owner = bpf_loader_upgradeable`, state = `Uninitialized`.
2. Before the victim submits their own `InitializeBuffer` transaction, an attacker observes the new account on-chain and submits Tx B: `UpgradeableLoaderInstruction::InitializeBuffer` with `accounts = [buffer_pubkey (writable, not signer), attacker_pubkey (not signer)]`, requiring zero signatures beyond a fee payer (see the account-meta construction and lack of signer checks at `programs/bpf_loader/src/lib.rs:158-172` and the test fixture at lines 1418-1429 which explicitly uses `is_signer: false` for the authority).
3. Tx B lands first; `buffer_pubkey`'s state becomes `Buffer { authority_address: Some(attacker_pubkey) }`.
4. Victim's later `InitializeBuffer` transaction fails with `AccountAlreadyInitialized`, and the victim can no longer `Write` to, `SetAuthority` on, or `Close` (reclaim rent from) `buffer_pubkey` without the attacker's cooperation.

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

**File:** programs/bpf_loader/src/lib.rs (L182-190)
```rust
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

**File:** programs/bpf_loader/src/lib.rs (L1418-1429)
```rust
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

**File:** cli/src/program.rs (L230-233)
```rust
                                .help(
                                    "Intermediate buffer account to write data to, which can be \
                                     used to resume a failed deploy [default: random address]",
                                ),
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

**File:** cli/src/program.rs (L3178-3187)
```rust
            if message.header.num_required_signatures == 3 {
                initial_transaction.try_sign(
                    &[fee_payer_signer, initial_signer, write_signer.unwrap()],
                    blockhash,
                )?;
            } else if message.header.num_required_signatures == 2 {
                initial_transaction.try_sign(&[fee_payer_signer, initial_signer], blockhash)?;
            } else {
                initial_transaction.try_sign(&[fee_payer_signer], blockhash)?;
            }
```
