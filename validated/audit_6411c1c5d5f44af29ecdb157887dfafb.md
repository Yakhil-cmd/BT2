### Title
Front-runnable `InitializeNonceAccount` allows attacker to seize nonce authority and drain funded nonce accounts - (File: `programs/system/src/system_instruction.rs`)

### Summary
`initialize_nonce_account` in `programs/system/src/system_instruction.rs` transitions a System-Program-owned account from `State::Uninitialized` to `State::Initialized` and sets the `nonce_authority` supplied in the instruction, but it performs **no signer/ownership check at all** on who is allowed to do this — it only checks that the account is writable and currently `Uninitialized`. [1](#0-0) 

This is structurally identical to the VibeXYZ bug class: a privileged state-setting function (`setVibeFees` / here, "assign nonce authority") is guarded only by a state check ("does a master exist" / "is the account Uninitialized"), not by an authorization check tied to the entity that is supposed to own the resource. Anyone who observes the pending account-creation transaction (which funds and assigns ownership of the future nonce account to the System Program, e.g. via `CreateAccount`) can race ahead of the legitimate owner's `InitializeNonceAccount` instruction and claim the `nonce_authority` role for themselves.

### Finding Description
A durable nonce account's lifecycle typically has two logical steps: (1) create/fund an account owned by the System Program (`SystemInstruction::CreateAccount`, which does enforce the new address signs), and (2) `SystemInstruction::InitializeNonceAccount`, dispatched to `initialize_nonce_account`, which stores the caller-supplied `nonce_authority` into the account with no additional authorization requirement. [2](#0-1) 

Unlike `withdraw_nonce_account`, which explicitly calls `check_signer` against the recorded authority once the account is `Initialized` [3](#0-2) , the initialization path has no equivalent check against the account's creator, the account itself, or any pre-established owner — the sole precondition is `State::Uninitialized`. If the create and initialize steps are ever submitted as separate transactions (which is a legitimate, supported usage pattern, and the exact scenario the CLI's `check_nonce_account`/`parse_upgrade_nonce_account` helpers are built to detect after the fact) [4](#0-3) , any third party can observe the pending `CreateAccount` transaction in the mempool, and submit their own `InitializeNonceAccount` transaction against that same (now-created, funded, System-Program-owned, Uninitialized) account before the legitimate owner's initialize transaction lands — setting `nonce_authority` to an address the attacker controls.

### Impact Explanation
Once the attacker has set themselves as `nonce_authority`, `withdraw_nonce_account` will validate them via `check_signer(&data.authority)` and permit draining the account's entire lamport balance to any destination the attacker chooses. [5](#0-4) 
Because the victim funded the account (paying for its rent-exempt minimum, and often more) with the intention of using it as their own durable-nonce account, this results in concrete, unsigned-by-the-victim fund movement — the attacker steals the lamports the victim deposited, exactly mirroring the VibeXYZ report's outcome where the exploiter seizes control of privileged fields (`vibeTreasury`) before the legitimate deployer's transaction lands.

### Likelihood Explanation
The attack requires only observing a pending, unconfirmed `InitializeNonceAccount` transaction (or a create+fund transaction followed by a separate initialize transaction) and racing a competing transaction ahead of it — a standard MEV/front-running capability available to any unprivileged network participant, requiring no special leader or validator privilege. The likelihood is limited to workflows where account creation and initialization are not atomically bundled in a single transaction/instruction batch, which is a documented but not universally enforced usage pattern.

### Recommendation
Mirror the fix recommended for `MintSaleBase`: require that initialization only succeed when authorized by the entity that is supposed to control the resource. Concretely, require the account itself (or a designated "create" authority derived at account-creation time) to be a signer of the `InitializeNonceAccount` instruction, or otherwise bind the allowed `nonce_authority`-setting operation to the same transaction/signer set that created and funded the account, rejecting a `State::Uninitialized → State::Initialized` transition that isn't signed by the funding/creating party.

### Proof of Concept
1. Victim submits `SystemInstruction::CreateAccount` to create a new account `N` owned by the System Program, funded above the rent-exempt minimum, intending to follow up with `InitializeNonceAccount` in a later transaction naming themselves as `nonce_authority`.
2. Attacker observes the pending `CreateAccount` transaction (or the already-landed but not-yet-initialized account) and submits their own `SystemInstruction::InitializeNonceAccount { nonce_authority: attacker_pubkey }` against `N` before the victim's initialize transaction lands. `initialize_nonce_account` succeeds because `N` is `State::Uninitialized` and writable — no other check is performed. [2](#0-1) 
3. Victim's own `InitializeNonceAccount` transaction now fails with `InstructionError::InvalidAccountData` since the state is already `Initialized`. [6](#0-5) 
4. Attacker submits `SystemInstruction::WithdrawNonceAccount` signed by `attacker_pubkey` (the recorded authority) to sweep `N`'s lamports to an address they control, which succeeds via the authority signer check. [5](#0-4)

### Citations

**File:** programs/system/src/system_instruction.rs (L99-123)
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
```

**File:** programs/system/src/system_instruction.rs (L125-161)
```rust
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
        }
    };

    from.checked_sub_lamports(lamports)?;
    drop(from);
    let mut to = instruction_context.try_borrow_instruction_account(to_account_index)?;
    to.checked_add_lamports(lamports)?;

    Ok(())
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

**File:** cli/src/nonce.rs (L378-404)
```rust
/// Check if a nonce account is initialized with the given authority and hash
pub fn check_nonce_account(
    nonce_account: &Account,
    nonce_authority: &Pubkey,
    nonce_hash: &Hash,
) -> Result<(), CliError> {
    match state_from_account(nonce_account)? {
        State::Initialized(ref data) => {
            if &data.blockhash() != nonce_hash {
                Err(Error::InvalidHash {
                    provided: *nonce_hash,
                    expected: data.blockhash(),
                }
                .into())
            } else if nonce_authority != &data.authority {
                Err(Error::InvalidAuthority {
                    provided: *nonce_authority,
                    expected: data.authority,
                }
                .into())
            } else {
                Ok(())
            }
        }
        State::Uninitialized => Err(Error::InvalidStateForOperation.into()),
    }
}
```
