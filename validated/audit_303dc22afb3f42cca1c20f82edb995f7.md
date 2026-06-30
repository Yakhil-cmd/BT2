### Title
`pause_precompiles` Is Permanently Non-Functional Due to Unpopulatable `EngineAuthorizer` ACL — (`engine/src/contract_methods/admin.rs`)

### Summary

The Aurora Engine implements a granular precompile pause mechanism via `pause_precompiles`, which guards the `ExitToNear` and `ExitToEthereum` bridge precompiles. However, the authorization check inside `pause_precompiles` relies on an `EngineAuthorizer` whose ACL (`BTreeSet<AccountId>`) can never be populated — no setter function exists anywhere in the contract interface. As a result, `pause_precompiles` always returns `ERR_UNAUTHORIZED` for every caller, including the contract owner, making the precompile pause mechanism permanently non-functional. This is a direct analog of the reported pattern: a security mechanism is declared and its check is enforced, but the mechanism to actually trigger the protected state is absent.

### Finding Description

`pause_precompiles` in `engine/src/contract_methods/admin.rs` reads the `EngineAuthorizer` from storage and checks whether the caller is authorized:

```rust
pub fn pause_precompiles<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |io| {
        require_running(&state::get_state(&io)?)?;
        let authorizer: EngineAuthorizer = engine::get_authorizer(&io);

        if !authorizer.is_authorized(&env.predecessor_account_id()) {
            return Err(b"ERR_UNAUTHORIZED".into());
        }
        ...
    })
}
``` [1](#0-0) 

`EngineAuthorizer` is defined in `pausables.rs` with an `acl: BTreeSet<AccountId>` field. Its `is_authorized` method simply checks membership in that set:

```rust
impl Authorizer for EngineAuthorizer {
    fn is_authorized(&self, account: &AccountId) -> bool {
        self.acl.contains(account)
    }
}
``` [2](#0-1) 

The default `EngineAuthorizer` has an empty ACL: [3](#0-2) 

A complete audit of all exported contract entrypoints in `engine/src/lib.rs` (lines 46–934) and all functions in `engine/src/contract_methods/admin.rs` reveals **no `set_authorizer`, `add_to_authorizer`, or equivalent function**. The `new()` initialization path also does not set any authorizer: [4](#0-3) 

`NewCallArgs` variants (`V1`–`V4`) carry no authorizer field: [5](#0-4) 

The asymmetry is stark: `resume_precompiles` uses `require_owner_only` (the owner can always resume), while `pause_precompiles` uses the authorizer check (no one can ever pause): [6](#0-5) 

The precompile flags themselves are properly stored and checked during EVM execution — the infrastructure works — but the gate to set those flags is permanently locked. [7](#0-6) 

### Impact Explanation

The `ExitToNear` and `ExitToEthereum` precompiles are the primary bridge exit paths for user funds. The precompile pause mechanism exists precisely to allow operators to halt these precompiles in an emergency (e.g., a discovered exploit in bridge accounting). Because `pause_precompiles` always fails, operators have only one recourse: call `pause_contract`, which halts **all** EVM execution. This forces a binary choice between:

1. Accepting ongoing fund theft via a precompile exploit (no pause), or
2. Temporarily freezing **all** user funds across the entire engine (full contract pause).

The inability to selectively pause bridge precompiles directly causes either **temporary freezing of all user funds** (High) or, if the operator hesitates to pause everything, enables **direct theft of user funds** via an unmitigated precompile exploit (Critical).

### Likelihood Explanation

The `EngineAuthorizer` ACL is empty at deployment and remains empty for the lifetime of the contract. Every call to `pause_precompiles` unconditionally returns `ERR_UNAUTHORIZED`. This is not a theoretical edge case — it is the guaranteed behavior on every invocation, by every caller, including the contract owner. Likelihood is **certain** given the missing setter.

### Recommendation

Add an admin-only function to populate the `EngineAuthorizer` ACL, analogous to how `set_key_manager` manages the relayer key manager:

```rust
#[named]
pub fn set_pauser<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        require_owner_only(&state, &env.predecessor_account_id())?;
        let args: PauserArgs = io.read_input_borsh()?;
        engine::set_authorizer(&mut io, args.accounts);
        Ok(())
    })
}
```

Alternatively, grant the contract owner implicit authorization in `pause_precompiles` as a fallback, consistent with how `resume_precompiles` is gated.

### Proof of Concept

1. Deploy Aurora Engine with any `NewCallArgs` variant.
2. Call `pause_precompiles` from the contract owner account with a valid `PausePrecompilesCallArgs` bitmask targeting `EXIT_TO_NEAR`.
3. Observe the call panics with `ERR_UNAUTHORIZED` — `engine::get_authorizer` returns an `EngineAuthorizer` with an empty ACL, so `is_authorized` returns `false` for every account.
4. Confirm no exported function exists to add accounts to the authorizer ACL.
5. Confirm `resume_precompiles` succeeds for the owner (it uses `require_owner_only`, not the authorizer), demonstrating the asymmetry. [8](#0-7) [1](#0-0)

### Citations

**File:** engine/src/contract_methods/admin.rs (L55-88)
```rust
#[named]
pub fn new<I: IO + Copy, E: Env>(mut io: I, env: &E) -> Result<(), ContractError> {
    if state::get_state(&io).is_ok() {
        return Err(b"ERR_ALREADY_INITIALIZED".into());
    }

    let input = io.read_input().to_vec();
    let args = NewCallArgs::deserialize(&input).map_err(|_| errors::ERR_BORSH_DESERIALIZE)?;

    let initial_hashchain = args.initial_hashchain();
    let state: EngineState = args.into();

    if let Some(block_hashchain) = initial_hashchain {
        let block_height = env.block_height();
        let mut hashchain = Hashchain::new(
            state.chain_id,
            env.current_account_id(),
            block_height,
            block_hashchain,
        );

        hashchain.add_block_tx(
            block_height,
            function_name!(),
            &input,
            &[],
            &Bloom::default(),
        )?;
        crate::hashchain::save_hashchain(&mut io, &hashchain)?;
    }

    state::set_state(&mut io, &state)?;
    Ok(())
}
```

**File:** engine/src/contract_methods/admin.rs (L208-223)
```rust
#[named]
pub fn resume_precompiles<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        let predecessor_account_id = env.predecessor_account_id();

        require_owner_only(&state, &predecessor_account_id)?;

        let args: PausePrecompilesCallArgs = io.read_input_borsh()?;
        let flags = PrecompileFlags::from_bits_truncate(args.paused_mask);
        let mut pauser = EnginePrecompilesPauser::from_io(io);
        pauser.resume_precompiles(flags);
        Ok(())
    })
}
```

**File:** engine/src/contract_methods/admin.rs (L225-241)
```rust
#[named]
pub fn pause_precompiles<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |io| {
        require_running(&state::get_state(&io)?)?;
        let authorizer: EngineAuthorizer = engine::get_authorizer(&io);

        if !authorizer.is_authorized(&env.predecessor_account_id()) {
            return Err(b"ERR_UNAUTHORIZED".into());
        }

        let args: PausePrecompilesCallArgs = io.read_input_borsh()?;
        let flags = PrecompileFlags::from_bits_truncate(args.paused_mask);
        let mut pauser = EnginePrecompilesPauser::from_io(io);
        pauser.pause_precompiles(flags);
        Ok(())
    })
}
```

**File:** engine/src/pausables.rs (L19-36)
```rust
impl PrecompileFlags {
    #[must_use]
    pub fn from_address(address: &Address) -> Option<Self> {
        Some(if address == &exit_to_ethereum::ADDRESS {
            Self::EXIT_TO_ETHEREUM
        } else if address == &exit_to_near::ADDRESS {
            Self::EXIT_TO_NEAR
        } else {
            return None;
        })
    }

    /// Checks if the precompile belonging to the `address` is marked as paused.
    #[must_use]
    pub fn is_paused_by_address(&self, address: &Address) -> bool {
        Self::from_address(address).is_some_and(|precompile_flag| self.contains(precompile_flag))
    }
}
```

**File:** engine/src/pausables.rs (L86-100)
```rust
#[derive(BorshSerialize, BorshDeserialize, Debug, Default, Clone)]
#[borsh(crate = "aurora_engine_types::borsh")]
pub struct EngineAuthorizer {
    /// List of [`AccountId`]s with the permission to pause precompiles.
    pub acl: BTreeSet<AccountId>,
}

impl EngineAuthorizer {
    /// Creates new [`EngineAuthorizer`] and grants permission to pause precompiles for all given `accounts`.
    pub fn from_accounts(accounts: impl Iterator<Item = AccountId>) -> Self {
        Self {
            acl: accounts.collect(),
        }
    }
}
```

**File:** engine/src/pausables.rs (L140-143)
```rust
impl Authorizer for EngineAuthorizer {
    fn is_authorized(&self, account: &AccountId) -> bool {
        self.acl.contains(account)
    }
```

**File:** engine/src/pausables.rs (L156-168)
```rust
impl<I: IO> PausedPrecompilesManager for EnginePrecompilesPauser<I> {
    fn resume_precompiles(&mut self, precompiles_to_resume: PrecompileFlags) {
        let mut pause_flags = self.read_flags_from_storage();
        pause_flags.remove(precompiles_to_resume);
        self.write_flags_into_storage(pause_flags);
    }

    fn pause_precompiles(&mut self, precompiles_to_pause: PrecompileFlags) {
        let mut pause_flags = self.read_flags_from_storage();
        pause_flags.insert(precompiles_to_pause);
        self.write_flags_into_storage(pause_flags);
    }
}
```

**File:** engine/src/state.rs (L63-88)
```rust
#[derive(BorshSerialize, BorshDeserialize, Default, Clone, PartialEq, Eq, Debug)]
#[borsh(crate = "aurora_engine_types::borsh")]
pub struct BorshableEngineStateV1<'a> {
    pub chain_id: [u8; 32],
    pub owner_id: Cow<'a, AccountId>,
    pub bridge_prover_id: Cow<'a, AccountId>,
    pub upgrade_delay_blocks: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Default, Clone, PartialEq, Eq, Debug)]
#[borsh(crate = "aurora_engine_types::borsh")]
pub struct BorshableEngineStateV2<'a> {
    pub chain_id: [u8; 32],
    pub owner_id: Cow<'a, AccountId>,
    pub upgrade_delay_blocks: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Default, Clone, PartialEq, Eq, Debug)]
#[borsh(crate = "aurora_engine_types::borsh")]
pub struct BorshableEngineStateV3<'a> {
    pub chain_id: [u8; 32],
    pub owner_id: Cow<'a, AccountId>,
    pub upgrade_delay_blocks: u64,
    pub is_paused: bool,
    pub key_manager: Option<Cow<'a, AccountId>>,
}
```
