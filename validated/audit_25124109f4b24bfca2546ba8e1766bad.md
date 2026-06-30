### Title
`pause_precompiles` Permanently Inaccessible Due to Missing `EngineAuthorizer` ACL Management Function - (`engine/src/contract_methods/admin.rs`)

### Summary

`pause_precompiles` gates access through an `EngineAuthorizer` ACL stored in contract state, but no public entrypoint exists anywhere in `lib.rs` to write accounts into that ACL. If the ACL is empty (the Borsh-default for `BTreeSet`), every call to `pause_precompiles` unconditionally returns `ERR_UNAUTHORIZED`, permanently disabling the only mechanism that can halt the `exit_to_near` and `exit_to_ethereum` bridge precompiles.

### Finding Description

`pause_precompiles` reads the authorizer from storage and rejects any caller not in its ACL: [1](#0-0) 

The authorizer type is: [2](#0-1) 

Authorization check: [3](#0-2) 

A complete audit of every `#[unsafe(no_mangle)]` entrypoint in `lib.rs` reveals no function that writes to the `EngineAuthorizer` storage key — no `set_authorizer`, `add_pauser`, or equivalent. [4](#0-3) 

By contrast, `resume_precompiles` uses the entirely different `require_owner_only` guard: [5](#0-4) 

This asymmetry confirms the ACL management path was never wired up. The `EngineAuthorizer` defaults to an empty `BTreeSet`, so `is_authorized` always returns `false`: [3](#0-2) 

### Impact Explanation

The two pausable precompiles are `exit_to_near` and `exit_to_ethereum`: [6](#0-5) 

These are the bridge exit paths that move user ETH/ERC-20 balances out of Aurora. If either contains an exploitable bug, the intended emergency response — pausing the precompile — is permanently unavailable. Any user funds flowing through the bridge exit precompiles are exposed for the full duration of any incident, with no on-chain mechanism to stop the drain. This maps to **High: Temporary (potentially permanent) freezing of funds** and, depending on the precompile bug, **Critical: Direct theft of user funds**.

### Likelihood Explanation

The broken state is unconditional and present from genesis: the ACL is empty by default, no deployment step can populate it through a public call, and the asymmetry with `resume_precompiles` (which correctly uses `require_owner_only`) shows the management path was simply never implemented. Any operator who attempts to invoke `pause_precompiles` in an emergency will receive `ERR_UNAUTHORIZED` with no recourse.

### Recommendation

Add an owner-gated entrypoint (e.g., `set_pauser_accounts`) that serializes a new `EngineAuthorizer` into the same storage key read by `engine::get_authorizer`. Alternatively, align `pause_precompiles` with `resume_precompiles` by replacing the ACL check with `require_owner_only` until a proper ACL management lifecycle is implemented.

### Proof of Concept

1. Deploy Aurora Engine. `EngineAuthorizer` storage key is absent → `get_authorizer` returns `EngineAuthorizer { acl: BTreeSet::new() }`.
2. Any account calls `pause_precompiles` with a valid `PausePrecompilesCallArgs`.
3. `authorizer.is_authorized(&predecessor)` returns `false` (empty set).
4. Function returns `Err(b"ERR_UNAUTHORIZED")` — call fails.
5. Scan all `#[unsafe(no_mangle)]` symbols in `lib.rs`: no symbol writes to the `EngineAuthorizer` storage key.
6. Conclusion: `pause_precompiles` is permanently unreachable by any account, including the contract owner.

### Citations

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

**File:** engine/src/pausables.rs (L9-17)
```rust
bitflags! {
    /// Wraps unsigned integer where each bit identifies a different precompile.
    #[derive(BorshSerialize, BorshDeserialize, Default)]
    #[borsh(crate = "aurora_engine_types::borsh")]
    pub struct PrecompileFlags: u32 {
        const EXIT_TO_NEAR        = 0b01;
        const EXIT_TO_ETHEREUM    = 0b10;
    }
}
```

**File:** engine/src/pausables.rs (L88-99)
```rust
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
```

**File:** engine/src/pausables.rs (L140-144)
```rust
impl Authorizer for EngineAuthorizer {
    fn is_authorized(&self, account: &AccountId) -> bool {
        self.acl.contains(account)
    }
}
```

**File:** engine/src/lib.rs (L46-933)
```rust
#[cfg(feature = "contract")]
mod contract {
    use aurora_engine_sdk::env::Env;
    use aurora_engine_sdk::io::{IO, StorageIntermediate};
    use aurora_engine_sdk::near_runtime::{Runtime, ViewEnv};
    use aurora_engine_types::account_id::AccountId;
    use aurora_engine_types::borsh;
    use aurora_engine_types::parameters::silo::{
        Erc20FallbackAddressArgs, FixedGasArgs, SiloParamsArgs, WhitelistArgs, WhitelistKindArgs,
        WhitelistStatusArgs,
    };

    use crate::contract_methods::{require_owner_and_running, require_running};
    use crate::engine::{self, Engine};
    use crate::errors;
    use crate::parameters::{GetStorageAtArgs, ViewCallArgs};
    use crate::prelude::sdk::types::{SdkExpect, SdkUnwrap};
    use crate::prelude::storage::{KeyPrefix, bytes_to_key};
    use crate::prelude::{Address, H256, ToString, Vec, sdk, u256_to_arr};
    use crate::{
        contract_methods::{self, ContractError, silo},
        state,
    };

    const CODE_KEY: &[u8; 4] = b"CODE";
    const CODE_STAGE_KEY: &[u8; 10] = b"CODE_STAGE";

    /// ADMINISTRATIVE METHODS
    /// Sets the configuration for the Engine.
    /// Should be called on deployment.
    #[unsafe(no_mangle)]
    pub extern "C" fn new() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::admin::new(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Get a version of the contract.
    #[unsafe(no_mangle)]
    pub extern "C" fn get_version() {
        let io = Runtime;
        contract_methods::admin::get_version(io)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Get owner account id for this contract.
    #[unsafe(no_mangle)]
    pub extern "C" fn get_owner() {
        let io = Runtime;
        contract_methods::admin::get_owner(io)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Set owner account id for this contract.
    #[unsafe(no_mangle)]
    pub extern "C" fn set_owner() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::admin::set_owner(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Get chain id for this contract.
    #[unsafe(no_mangle)]
    pub extern "C" fn get_chain_id() {
        let io = Runtime;
        contract_methods::admin::get_chain_id(io)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn get_upgrade_delay_blocks() {
        let io = Runtime;
        contract_methods::admin::get_upgrade_delay_blocks(io)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn set_upgrade_delay_blocks() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::admin::set_upgrade_delay_blocks(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn get_upgrade_index() {
        let io = Runtime;
        contract_methods::admin::get_upgrade_index(io)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Upgrade the contract with the provided code bytes.
    #[unsafe(no_mangle)]
    pub extern "C" fn upgrade() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;

        contract_methods::admin::upgrade(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Stage new code for deployment.
    #[unsafe(no_mangle)]
    pub extern "C" fn stage_upgrade() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::admin::stage_upgrade(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Deploy staged upgrade.
    #[unsafe(no_mangle)]
    pub extern "C" fn deploy_upgrade() {
        // This function is intentionally not implemented in `contract_methods`
        // because it only makes sense in the context of the NEAR runtime.
        let mut io = Runtime;
        let state = state::get_state(&io).sdk_unwrap();
        require_running(&state)
            .map_err(ContractError::msg)
            .sdk_unwrap();
        let index = internal_get_upgrade_index();
        if io.block_height() <= index {
            sdk::panic_utf8(errors::ERR_NOT_ALLOWED_TOO_EARLY);
        }
        Runtime::self_deploy(&bytes_to_key(KeyPrefix::Config, CODE_KEY));
        io.remove_storage(&bytes_to_key(KeyPrefix::Config, CODE_STAGE_KEY));
    }

    /// Called as part of the upgrade process (see `engine-sdk::self_deploy`). This function is meant
    /// to make any necessary changes to the state such that it aligns with the newly deployed
    /// code.
    #[unsafe(no_mangle)]
    #[allow(clippy::missing_const_for_fn)]
    pub extern "C" fn state_migration() {
        // TODO: currently we don't have migrations
    }

    /// Resumes previously [`paused`] precompiles.
    ///
    /// [`paused`]: pause_precompiles
    #[unsafe(no_mangle)]
    pub extern "C" fn resume_precompiles() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::admin::resume_precompiles(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Pauses a precompile.
    #[unsafe(no_mangle)]
    pub extern "C" fn pause_precompiles() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::admin::pause_precompiles(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Returns an unsigned integer where each bit set to 1 means that corresponding precompile
    /// to that bit is paused and 0-bit means not paused.
    #[unsafe(no_mangle)]
    pub extern "C" fn get_paused_precompiles() {
        let io = Runtime;
        contract_methods::admin::paused_precompiles(io)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Sets the flag to pause the contract.
    #[unsafe(no_mangle)]
    pub extern "C" fn pause_contract() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::admin::pause_contract(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Sets the flag to resume the contract.
    #[unsafe(no_mangle)]
    pub extern "C" fn resume_contract() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::admin::resume_contract(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    // TODO: rust-2023-08-24  #[allow(clippy::empty_line_after_doc_comments)]
    /// MUTATIVE METHODS
    /// Deploy code into the EVM.
    #[unsafe(no_mangle)]
    pub extern "C" fn deploy_code() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::evm_transactions::deploy_code(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Call method on the EVM contract.
    #[unsafe(no_mangle)]
    pub extern "C" fn call() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::evm_transactions::call(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Process signed Ethereum transaction.
    /// Must match `CHAIN_ID` to make sure it's signed for given chain vs replayed from another chain.
    #[unsafe(no_mangle)]
    pub extern "C" fn submit() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::evm_transactions::submit(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Analog of the `submit` function, but waits for the `SubmitArgs` structure rather than
    /// the array of bytes representing the transaction.
    #[unsafe(no_mangle)]
    pub extern "C" fn submit_with_args() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::evm_transactions::submit_with_args(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn register_relayer() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::admin::register_relayer(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Updates the bytecode for user's router contracts created by the engine.
    /// These contracts are where cross-contract calls initiated by the EVM precompile
    /// will be sent from.
    #[unsafe(no_mangle)]
    pub extern "C" fn factory_update() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::xcc::factory_update(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Updates the bytecode version for the given account. This is only called as a callback
    /// when a new version of the router contract is deployed to an account.
    #[unsafe(no_mangle)]
    pub extern "C" fn factory_update_address_version() {
        let io = Runtime;
        let env = Runtime;
        let handler = Runtime;
        contract_methods::xcc::factory_update_address_version(io, &env, &handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Sets the address for the `wNEAR` ERC-20 contract. This contract will be used by the
    /// cross-contract calls feature to have users pay for their NEAR transactions.
    #[unsafe(no_mangle)]
    pub extern "C" fn factory_set_wnear_address() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::xcc::factory_set_wnear_address(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Returns the address for the `wNEAR` ERC-20 contract in borsh format.
    #[unsafe(no_mangle)]
    pub extern "C" fn factory_get_wnear_address() {
        let io = Runtime;
        contract_methods::xcc::factory_get_wnear_address(io)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Create and/or fund an XCC sub-account directly (as opposed to having one be automatically
    /// created via the XCC precompile in the EVM). The purpose of this method is to enable
    /// XCC on engine instances where wrapped NEAR (`wNEAR`) is not bridged.
    #[unsafe(no_mangle)]
    pub extern "C" fn fund_xcc_sub_account() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::xcc::fund_xcc_sub_account(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// A private function (only callable by the contract itself) used as part of the XCC flow.
    /// This function uses the exit to Near precompile to move wNear from Aurora to a user's
    /// XCC account.
    #[unsafe(no_mangle)]
    pub extern "C" fn withdraw_wnear_to_router() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::xcc::withdraw_wnear_to_router(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Mirror existing ERC-20 token on the main Aurora contract.
    /// Notice: It works if the SILO mode is on.
    #[unsafe(no_mangle)]
    pub extern "C" fn mirror_erc20_token() {
        let io = Runtime;
        let mut handler = Runtime;
        contract_methods::connector::mirror_erc20_token(io, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Callback used by the `mirror_erc20_token` function.
    #[unsafe(no_mangle)]
    pub extern "C" fn mirror_erc20_token_callback() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::connector::mirror_erc20_token_callback(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Sets relayer key manager.
    #[unsafe(no_mangle)]
    pub extern "C" fn set_key_manager() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::admin::set_key_manager(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Adds a relayer function call key.
    #[unsafe(no_mangle)]
    pub extern "C" fn add_relayer_key() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::admin::add_relayer_key(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Callback which is called by `add_relayer_key` and stores the relayer function
    /// call key into the storage.
    #[unsafe(no_mangle)]
    pub extern "C" fn store_relayer_key_callback() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::admin::store_relayer_key_callback(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Removes a relayer function call key.
    #[unsafe(no_mangle)]
    pub extern "C" fn remove_relayer_key() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::admin::remove_relayer_key(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Initialize the hashchain.
    #[unsafe(no_mangle)]
    pub extern "C" fn start_hashchain() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::admin::start_hashchain(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Attach a full access key.
    #[unsafe(no_mangle)]
    pub extern "C" fn attach_full_access_key() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::admin::attach_full_access_key(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    ///
    /// READ-ONLY METHODS
    ///
    #[unsafe(no_mangle)]
    pub extern "C" fn view() {
        let mut io = Runtime;
        let env = ViewEnv;
        let args: ViewCallArgs = io.read_input_borsh().sdk_unwrap();
        let current_account_id = io.current_account_id();
        let engine: Engine<_, _> =
            Engine::new(args.sender, current_account_id, io, &env).sdk_unwrap();
        let result = Engine::view_with_args(&engine, args).sdk_unwrap();
        io.return_output(&borsh::to_vec(&result).sdk_expect(errors::ERR_SERIALIZE));
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn get_block_hash() {
        let mut io = Runtime;
        let block_height = io.read_input_borsh().sdk_unwrap();
        let account_id = io.current_account_id();
        let chain_id = state::get_state(&io)
            .map(|state| state.chain_id)
            .sdk_unwrap();
        let block_hash = engine::compute_block_hash(chain_id, block_height, account_id.as_bytes());
        io.return_output(block_hash.as_bytes());
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn get_code() {
        let mut io = Runtime;
        let address = io.read_input_arr20().sdk_unwrap();
        let code = engine::get_code(&io, &Address::from_array(address));
        io.return_output(&code);
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn get_balance() {
        let mut io = Runtime;
        let address = io.read_input_arr20().sdk_unwrap();
        let balance = engine::get_balance(&io, &Address::from_array(address));
        io.return_output(&balance.to_bytes());
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn get_nonce() {
        let mut io = Runtime;
        let address = io.read_input_arr20().sdk_unwrap();
        let nonce = engine::get_nonce(&io, &Address::from_array(address));
        io.return_output(&u256_to_arr(&nonce));
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn get_storage_at() {
        let mut io = Runtime;
        let args: GetStorageAtArgs = io.read_input_borsh().sdk_unwrap();
        let address = args.address;
        let generation = engine::get_generation(&io, &address);
        let value = engine::get_storage(&io, &args.address, &H256(args.key), generation);
        io.return_output(&value.0);
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn get_latest_hashchain() {
        let mut io = Runtime;
        contract_methods::admin::get_latest_hashchain(&mut io)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Return metadata of the ERC-20 contract.
    #[unsafe(no_mangle)]
    pub extern "C" fn get_erc20_metadata() {
        let io = Runtime;
        let env = ViewEnv;
        contract_methods::connector::get_erc20_metadata(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    ///
    /// ETH-CONNECTOR
    ///
    #[unsafe(no_mangle)]
    pub extern "C" fn withdraw() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::connector::withdraw(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn ft_total_supply() {
        let io = Runtime;
        contract_methods::connector::ft_total_eth_supply_on_near(io)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn ft_balance_of() {
        let io = Runtime;
        contract_methods::connector::ft_balance_of(io)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn ft_balance_of_eth() {
        let io = Runtime;
        contract_methods::connector::ft_balance_of_eth(io)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn ft_transfer() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::connector::ft_transfer(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn ft_transfer_call() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::connector::ft_transfer_call(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Allows receiving NEP141 tokens in the EVM contract.
    ///
    /// This function is called when NEP141 tokens are transferred to the contract.
    /// It returns the amount of tokens that should be returned to the sender.
    ///
    /// There are two possible outcomes:
    /// 1. If an error occurs during the token transfer, all the transferred tokens are returned to the sender.
    /// 2. If the token transfer is successful, no tokens are returned, and the contract keeps the transferred tokens.
    #[unsafe(no_mangle)]
    pub extern "C" fn ft_on_transfer() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::connector::ft_on_transfer(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Deploy ERC20 token mapped to a NEP141
    #[unsafe(no_mangle)]
    pub extern "C" fn deploy_erc20_token() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::connector::deploy_erc20_token(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Callback used by the `deploy_erc20_token` function.
    #[unsafe(no_mangle)]
    pub extern "C" fn deploy_erc20_token_callback() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::connector::deploy_erc20_token_callback(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Set metadata of ERC-20 contract.
    #[unsafe(no_mangle)]
    pub extern "C" fn set_erc20_metadata() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::connector::set_erc20_metadata(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Callback invoked by exit to NEAR precompile to handle potential
    /// errors in the exit call or to perform the near tokens transfer.
    #[unsafe(no_mangle)]
    pub extern "C" fn exit_to_near_precompile_callback() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::connector::exit_to_near_precompile_callback(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn storage_deposit() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::connector::storage_deposit(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn storage_unregister() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::connector::storage_unregister(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn storage_withdraw() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::connector::storage_withdraw(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn storage_balance_of() {
        let io = Runtime;
        contract_methods::connector::storage_balance_of(io)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn get_eth_connector_contract_account() {
        let io = Runtime;
        contract_methods::connector::get_eth_connector_contract_account(io)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn set_eth_connector_contract_account() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::connector::set_eth_connector_contract_account(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn get_erc20_from_nep141() {
        let mut io = Runtime;
        let nep141: AccountId = io.read_input_borsh().sdk_unwrap();

        io.return_output(
            engine::get_erc20_from_nep141(&io, &nep141)
                .sdk_unwrap()
                .as_bytes(),
        );
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn get_nep141_from_erc20() {
        let mut io = Runtime;
        let erc20_address: engine::ERC20Address = io.read_input().to_vec().try_into().sdk_unwrap();
        io.return_output(
            engine::nep141_erc20_map(io)
                .lookup_right(&erc20_address)
                .sdk_expect("ERC20_NOT_FOUND")
                .as_ref(),
        );
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn ft_metadata() {
        let io = Runtime;
        let env = Runtime;
        contract_methods::connector::ft_metadata(io, &env)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }

    /// Function used to create accounts for tests
    #[cfg(feature = "integration-test")]
    #[unsafe(no_mangle)]
    pub extern "C" fn mint_account() {
        use crate::prelude::{NEP141Wei, U256};
        use aurora_evm::backend::ApplyBackend;

        let io = Runtime;
        let args: ([u8; 20], u64, u64) = io.read_input_borsh().sdk_expect(errors::ERR_ARGS);
        let address = Address::from_array(args.0);
        let nonce = U256::from(args.1);
        let balance = NEP141Wei::new(u128::from(args.2));
        let current_account_id = io.current_account_id();
        let mut engine: Engine<_, _> =
            Engine::new(address, current_account_id, io, &io).sdk_unwrap();
        let state_change = aurora_evm::backend::Apply::Modify {
            address: address.raw(),
            basic: aurora_evm::backend::Basic {
                balance: U256::from(balance.as_u128()),
                nonce,
            },
            code: None,
            storage: core::iter::empty(),
            reset_storage: false,
        };
        engine.apply(core::iter::once(state_change), core::iter::empty(), false);
    }

    ///
    /// Silo
    ///
    #[unsafe(no_mangle)]
    pub extern "C" fn get_fixed_gas() {
        let mut io = Runtime;
        let args = FixedGasArgs {
            fixed_gas: silo::get_fixed_gas(&io),
        };

        io.return_output(&borsh::to_vec(&args).map_err(|e| e.to_string()).sdk_unwrap());
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn set_fixed_gas() {
        let mut io = Runtime;
        let state = state::get_state(&io).sdk_unwrap();
        require_owner_and_running(&state, &io.predecessor_account_id())
            .map_err(ContractError::msg)
            .sdk_unwrap();

        let args: FixedGasArgs = io.read_input_borsh().sdk_unwrap();
        silo::set_fixed_gas(&mut io, args.fixed_gas);
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn get_erc20_fallback_address() {
        let mut io = Runtime;
        let args = Erc20FallbackAddressArgs {
            address: silo::get_erc20_fallback_address(&io),
        };

        io.return_output(&borsh::to_vec(&args).map_err(|e| e.to_string()).sdk_unwrap());
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn set_erc20_fallback_address() {
        let mut io = Runtime;
        let state = state::get_state(&io).sdk_unwrap();
        require_owner_and_running(&state, &io.predecessor_account_id())
            .map_err(ContractError::msg)
            .sdk_unwrap();

        let args: Erc20FallbackAddressArgs = io.read_input_borsh().sdk_unwrap();
        silo::set_erc20_fallback_address(&mut io, args.address);
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn get_silo_params() {
        let mut io = Runtime;
        let params = silo::get_silo_params(&io);

        io.return_output(
            &borsh::to_vec(&params)
                .map_err(|e| e.to_string())
                .sdk_unwrap(),
        );
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn set_silo_params() {
        let mut io = Runtime;
        let state = state::get_state(&io).sdk_unwrap();
        require_owner_and_running(&state, &io.predecessor_account_id())
            .map_err(ContractError::msg)
            .sdk_unwrap();

        let args: Option<SiloParamsArgs> = io.read_input_borsh().sdk_unwrap();
        silo::set_silo_params(&mut io, args);
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn set_whitelist_status() {
        let io = Runtime;
        let state = state::get_state(&io).sdk_unwrap();
        require_owner_and_running(&state, &io.predecessor_account_id())
            .map_err(ContractError::msg)
            .sdk_unwrap();

        let args: WhitelistStatusArgs = io.read_input_borsh().sdk_unwrap();
        silo::set_whitelist_status(&io, &args);
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn set_whitelists_statuses() {
        let io = Runtime;
        let state = state::get_state(&io).sdk_unwrap();
        require_owner_and_running(&state, &io.predecessor_account_id())
            .map_err(ContractError::msg)
            .sdk_unwrap();

        let args: Vec<WhitelistStatusArgs> = io.read_input_borsh().sdk_unwrap();
        silo::set_whitelists_statuses(&io, args);
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn get_whitelist_status() {
        let mut io = Runtime;
        let args: WhitelistKindArgs = io.read_input_borsh().sdk_unwrap();
        let status = borsh::to_vec(&silo::get_whitelist_status(&io, &args))
            .map_err(|e| e.to_string())
            .sdk_unwrap();

        io.return_output(&status);
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn get_whitelists_statuses() {
        let mut io = Runtime;
        let statuses = borsh::to_vec(&silo::get_whitelists_statuses(&io))
            .map_err(|e| e.to_string())
            .sdk_unwrap();

        io.return_output(&statuses);
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn add_entry_to_whitelist() {
        let io = Runtime;
        let state = state::get_state(&io).sdk_unwrap();
        require_owner_and_running(&state, &io.predecessor_account_id())
            .map_err(ContractError::msg)
            .sdk_unwrap();

        let args: WhitelistArgs = io.read_input_borsh().sdk_unwrap();
        silo::add_entry_to_whitelist(&io, &args);
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn add_entry_to_whitelist_batch() {
        let io = Runtime;
        let state = state::get_state(&io).sdk_unwrap();
        require_owner_and_running(&state, &io.predecessor_account_id())
            .map_err(ContractError::msg)
            .sdk_unwrap();

        let args: Vec<WhitelistArgs> = io.read_input_borsh().sdk_unwrap();
        silo::add_entry_to_whitelist_batch(&io, args);
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn remove_entry_from_whitelist() {
        let io = Runtime;
        let state = state::get_state(&io).sdk_unwrap();
        require_owner_and_running(&state, &io.predecessor_account_id())
            .map_err(ContractError::msg)
            .sdk_unwrap();

        let args: WhitelistArgs = io.read_input_borsh().sdk_unwrap();
        silo::remove_entry_from_whitelist(&io, &args);
    }

    /// Utility methods.
    fn internal_get_upgrade_index() -> u64 {
        let io = Runtime;
        match io.read_u64(&bytes_to_key(KeyPrefix::Config, CODE_STAGE_KEY)) {
            Ok(index) => index,
            Err(sdk::error::ReadU64Error::InvalidU64) => {
                sdk::panic_utf8(errors::ERR_INVALID_UPGRADE)
            }
            Err(sdk::error::ReadU64Error::MissingValue) => sdk::panic_utf8(errors::ERR_NO_UPGRADE),
        }
    }
}
```
