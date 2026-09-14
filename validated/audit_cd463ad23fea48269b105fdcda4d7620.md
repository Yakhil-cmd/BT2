### Title
Front-running `InitializeBuffer` allows theft of upgrade-buffer rent lamports via unauthorized `Close` - (File: `programs/bpf_loader/src/lib.rs`)

### Summary
`bpf_loader_upgradeable`'s `InitializeBuffer` instruction sets a buffer account's `authority_address` from whatever pubkey is supplied at account index 1, without requiring that key to sign, and without requiring the buffer account itself to sign. If a client submits `system_instruction::create_account` (assigning the buffer to `bpf_loader_upgradeable`) and `InitializeBuffer` as two separate transactions instead of atomically in one, an attacker can observe the freshly-created, still-`Uninitialized` buffer account on-chain and race their own `InitializeBuffer` transaction naming themselves as authority before the legitimate owner's transaction lands.

### Finding Description
`InitializeBuffer` only checks that the account state is `Uninitialized`, then unconditionally records whatever pubkey is passed as account index 1 as the new `authority_address`, with no signature check on either the buffer account or the proposed authority: [1](#0-0) 

Compare this to `Write`/`SetAuthority`, which correctly require the authority to match and sign: [2](#0-1) 

Because the buffer account must first be assigned to `bpf_loader_upgradeable` by a `system_instruction::create_account` call (which requires the new account's own keypair signature), the recommended and universally-used tooling pattern bundles `CreateAccount` + `InitializeBuffer` into a single atomic transaction, as seen in Agave's own CLI and program-test helpers: [3](#0-2) [4](#0-3) [5](#0-4) 

However, nothing in the protocol enforces this bundling. If a caller (wallet, exchange integration, or naive script) submits the two instructions as separate transactions, there is a window where the buffer account exists on-chain, owned by `bpf_loader_upgradeable`, in the `Uninitialized` state, before the legitimate `InitializeBuffer` transaction lands. Any other transaction can submit `InitializeBuffer` against that same buffer address during this window, since the instruction requires neither the buffer nor the named authority to sign.

Once an attacker's transaction sets themselves as `authority_address`, the legitimate owner's subsequent `InitializeBuffer` attempt fails with `AccountAlreadyInitialized`: [6](#0-5) 

The attacker, now controlling the buffer's `authority_address`, can call `Close` to redirect all lamports funded by the victim (rent-exempt reserve for the buffer, paid via the earlier `CreateAccount`) to an arbitrary recipient account of the attacker's choosing: [7](#0-6) 

This is directly analogous to the reported `PublicLock.initialize()` front-run: an implementation/account is deployed (created) separately from the step that assigns its controlling authority, and the assignment step lacks access control, letting anyone claim control and force the legitimate depositor to lose funds/redeploy.

### Impact Explanation
An attacker can steal the rent lamports the victim funded into the buffer account by front-running `InitializeBuffer` and then calling `Close`, redirecting funds to an address they control. This is a concrete unsigned fund movement reachable from a single, unprivileged submitted transaction, requiring no special leader/validator privilege — only correctly timed transaction submission (front-running via higher priority fee or faster propagation).

### Likelihood Explanation
Likelihood is moderate-to-low in practice: virtually all first-party tooling (Agave CLI, `program-test`, SDK helpers) bundles `CreateAccount` and `InitializeBuffer` atomically in one transaction, which fully eliminates the race window. The vulnerability is only exploitable against clients/integrations that (incorrectly) split these two steps across separate transactions and expose the intermediate `Uninitialized` buffer state to the network before their own `InitializeBuffer` lands. I was not able to verify from the indexed code whether any first-party path (CLI, RPC helpers, `solana_loader_v3_interface`) ever legitimately performs this split; all examples found combine them atomically.

### Recommendation
Require the account being initialized in `InitializeBuffer` (account index 0) to be a signer, matching the pattern already used for `Write` and `SetAuthority` (which require the current authority to sign). This would make it impossible for a third party to claim authority over a buffer account they did not create, closing the front-running window regardless of how client tooling splits the transactions.

### Proof of Concept
1. Victim submits Tx1: `system_instruction::create_account(payer, buffer_pubkey, lamports, size, bpf_loader_upgradeable::id())`, signed by `payer` and `buffer_keypair`, funding the buffer with rent-exempt lamports.
2. Attacker observes Tx1 land (buffer now owned by `bpf_loader_upgradeable`, state `Uninitialized`).
3. Attacker submits `InitializeBuffer` against `buffer_pubkey` with account index 1 = attacker's own pubkey, before the victim's intended `InitializeBuffer` transaction (Tx2) lands. This succeeds because `InitializeBuffer` requires no signature from the buffer or the named authority — see [1](#0-0) .
4. Victim's Tx2 (`InitializeBuffer` naming themselves as authority) now fails with `AccountAlreadyInitialized`.
5. Attacker submits `Close` on the buffer with themselves as authority (account index 1 = attacker recipient), draining all lamports the victim funded into the buffer — see [7](#0-6) .

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

**File:** programs/bpf_loader/src/lib.rs (L173-190)
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
```

**File:** programs/bpf_loader/src/lib.rs (L686-716)
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
                UpgradeableLoaderState::Buffer { authority_address } => {
                    instruction_context.check_number_of_instruction_accounts(3)?;
                    drop(close_account);
                    common_close_account(&authority_address, &instruction_context, &log_collector)?;

                    ic_logger_msg!(log_collector, "Closed Buffer {}", close_key);
                }
```

**File:** cli/src/program.rs (L2716-2722)
```rust
                loader_v3_instruction::create_buffer(
                    &fee_payer_signer.pubkey(),
                    buffer_pubkey,
                    &buffer_authority_signer.pubkey(),
                    min_rent_exempt_program_buffer_balance,
                    program_len,
                )?,
```

**File:** program-test/tests/builtins.rs (L24-38)
```rust
    let create_buffer_instructions = solana_loader_v3_interface::instruction::create_buffer(
        &payer.pubkey(),
        &buffer_keypair.pubkey(),
        &upgrade_authority_keypair.pubkey(),
        buffer_rent,
        1,
    )
    .unwrap();

    let mut transaction =
        Transaction::new_with_payer(&create_buffer_instructions[..], Some(&payer.pubkey()));
    transaction.sign(&[&payer, &buffer_keypair], recent_blockhash);

    // Act
    banks_client.process_transaction(transaction).await.unwrap();
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
