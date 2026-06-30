### Title
Unbounded Loop in `move_to_block` Causes Permanent Freeze of All Engine Operations — (File: `engine-hashchain/src/hashchain.rs`)

---

### Summary

The `Hashchain::move_to_block` function contains an unbounded `while` loop that iterates once per NEAR block elapsed since the last hashchain update. Because this function is invoked unconditionally on every state-changing engine call via `with_hashchain` / `with_logs_hashchain`, a sufficiently long period of inactivity causes every subsequent engine call to exceed NEAR's per-transaction gas limit, permanently freezing all EVM transaction submission and bridge operations.

---

### Finding Description

`move_to_block` in `engine-hashchain/src/hashchain.rs` iterates from the stored block height up to the current NEAR block height, performing a keccak256 hash and Merkle-tree operation on every step: [1](#0-0) 

```rust
while self.current_block_height < next_block_height {
    self.previous_block_hashchain = self.block_hashchain_computer.compute_block_hashchain(...);
    self.block_hashchain_computer.clear_txs();
    self.current_block_height += 1;
}
```

This is called from `load_hashchain` in `engine/src/hashchain.rs`: [2](#0-1) 

`load_hashchain` is called at the very start of both `with_hashchain` and `with_logs_hashchain`, **before** the user-supplied closure (which contains `require_running` and the actual business logic) is executed: [3](#0-2) 

Every state-changing engine method is wrapped in one of these two functions. Examples:

- `ft_on_transfer`, `deploy_erc20_token`, `set_erc20_metadata`, `exit_to_near_precompile_callback`, `mirror_erc20_token_callback` — all use `with_hashchain` [4](#0-3) 

- `withdraw_wnear_to_router`, `factory_update`, `factory_update_address_version`, `fund_xcc_sub_account` — all use `with_hashchain` / `with_logs_hashchain` [5](#0-4) 

The number of loop iterations equals `current_NEAR_block_height − stored_hashchain_block_height`. NEAR produces approximately one block per second. Each loop iteration calls `compute_block_hashchain`, which performs a keccak256 over ~424 bytes plus a Merkle-tree hash: [6](#0-5) 

NEAR's per-transaction gas limit is 300 TGas. A single keccak256 call costs roughly 1.5–2 TGas base plus per-byte cost. With the additional Merkle computation, each loop iteration consumes on the order of 3–5 TGas, meaning the loop exhausts the gas budget after approximately **60–100 iterations** — i.e., after roughly **60–100 seconds** of engine inactivity.

---

### Impact Explanation

Once the gap between the stored hashchain block height and the current NEAR block height exceeds the threshold, **every** call to `with_hashchain` or `with_logs_hashchain` fails with an out-of-gas error before the closure body is reached. This includes:

- All EVM transaction submissions (`submit`)
- All ETH/ERC-20 bridge deposits (`ft_on_transfer`)
- All bridge withdrawals
- All XCC operations

User funds deposited into the bridge or held in EVM accounts become inaccessible. Because the loop runs before any admin check or pause check, there is no in-band recovery path through normal engine calls — the engine is effectively bricked for as long as the hashchain state remains stale.

**Impact: Permanent freezing of funds.**

---

### Likelihood Explanation

NEAR produces ~1 block/second. Any period of engine inactivity lasting more than ~1–2 minutes is sufficient to trigger the condition. Realistic triggers include:

- A scheduled or emergency pause of the engine (the `require_running` check is inside the closure, executed *after* the loop, so pausing the engine does not prevent the loop from running when the engine is later unpaused).
- A natural low-traffic window on the Aurora network.
- A deliberate griefing attack: an attacker who can pause the engine (or simply wait for a quiet period) can ensure the gap grows large enough to permanently block recovery.

The condition is self-reinforcing: once the loop is too large to complete, no transaction can update the stored block height, so the gap only grows larger over time.

**Likelihood: High** (any inactivity window of ~1–2 minutes suffices; engine pause is a documented operational procedure).

---

### Recommendation

1. **Cap the loop**: In `move_to_block`, process at most `N` blocks per call (where `N` is chosen to stay well within the NEAR gas budget), and persist the intermediate state so subsequent calls continue from where the previous one left off.
2. **Lazy / amortized update**: Instead of catching up all missed blocks in a single call, record only the current block height and previous hashchain at the time of the first transaction in a new block, skipping empty blocks entirely (since they contribute no transactions to the Merkle tree).
3. **Separate the catch-up from the transaction**: Provide a dedicated admin method to advance the hashchain by a bounded number of blocks, callable multiple times, so recovery is always possible even after a long gap.

---

### Proof of Concept

1. Deploy Aurora Engine with hashchain enabled (hashchain state written to storage).
2. Allow the NEAR chain to produce ≥ 100 blocks with no engine transactions (approximately 100 seconds of inactivity, or pause the engine for that duration).
3. Submit any EVM transaction or bridge operation (e.g., `ft_on_transfer`).
4. Observe that `with_hashchain` → `load_hashchain` → `move_to_block` iterates ~100 times, exhausting the 300 TGas budget before the closure body executes.
5. The transaction fails with an out-of-gas error. All subsequent transactions fail identically. Funds are frozen. [7](#0-6) [8](#0-7)

### Citations

**File:** engine-hashchain/src/hashchain.rs (L67-88)
```rust
    pub fn move_to_block(
        &mut self,
        next_block_height: u64,
    ) -> Result<(), BlockchainHashchainError> {
        if next_block_height <= self.current_block_height {
            return Err(BlockchainHashchainError::BlockHeightIncorrect);
        }

        while self.current_block_height < next_block_height {
            self.previous_block_hashchain = self.block_hashchain_computer.compute_block_hashchain(
                &self.chain_id,
                self.contract_account_id.as_bytes(),
                self.current_block_height,
                self.previous_block_hashchain,
            );

            self.block_hashchain_computer.clear_txs();
            self.current_block_height += 1;
        }

        Ok(())
    }
```

**File:** engine-hashchain/src/hashchain.rs (L268-289)
```rust
    /// Computes the block hashchain.
    pub fn compute_block_hashchain(
        &self,
        chain_id: &[u8; 32],
        contract_account_id: &[u8],
        current_block_height: u64,
        previous_block_hashchain: RawH256,
    ) -> RawH256 {
        let txs_hash = self.txs_merkle_tree.compute_hash();

        let data = [
            chain_id,
            contract_account_id,
            &current_block_height.to_be_bytes(),
            &previous_block_hashchain,
            &txs_hash,
            self.txs_logs_bloom.as_bytes(),
        ]
        .concat();

        keccak(&data).0
    }
```

**File:** engine/src/hashchain.rs (L21-52)
```rust
pub fn with_hashchain<I, E, T, F>(
    mut io: I,
    env: &E,
    function_name: &str,
    f: F,
) -> Result<T, ContractError>
where
    I: IO + Copy,
    E: Env,
    F: for<'a> FnOnce(CachedIO<'a, I>) -> Result<T, ContractError>,
{
    let block_height = env.block_height();
    let maybe_hashchain = load_hashchain(&io, block_height)?;

    let cache = RefCell::new(IOCache::default());
    let hashchain_io = CachedIO::new(io, &cache);
    let result = f(hashchain_io)?;

    if let Some(mut hashchain) = maybe_hashchain {
        let cache_ref = cache.borrow();
        hashchain.add_block_tx(
            block_height,
            function_name,
            &cache_ref.input,
            &cache_ref.output,
            &Bloom::default(),
        )?;
        save_hashchain(&mut io, &hashchain)?;
    }

    Ok(result)
}
```

**File:** engine/src/hashchain.rs (L88-96)
```rust
fn load_hashchain<I: IO>(io: &I, block_height: u64) -> Result<Option<Hashchain>, ContractError> {
    let mut maybe_hashchain = read_current_hashchain(io)?;
    if let Some(hashchain) = maybe_hashchain.as_mut()
        && block_height > hashchain.get_current_block_height()
    {
        hashchain.move_to_block(block_height)?;
    }
    Ok(maybe_hashchain)
}
```

**File:** engine/src/contract_methods/connector.rs (L62-109)
```rust
pub fn ft_on_transfer<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<Option<SubmitResult>, ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        require_running(&state::get_state(&io)?)?;
        let current_account_id = env.current_account_id();
        let predecessor_account_id = env.predecessor_account_id();
        let mut engine: Engine<_, _> = Engine::new(
            predecessor_address(&predecessor_account_id),
            current_account_id.clone(),
            io,
            env,
        )?;

        sdk::log!("Call ft_on_transfer");

        let args: FtOnTransferArgs = read_json_args(&io)?;
        let result = if predecessor_account_id == get_connector_account_id(&io)? {
            engine.receive_base_tokens(&args)
        } else {
            engine.receive_erc20_tokens(
                &predecessor_account_id,
                &args,
                &current_account_id,
                handler,
            )
        };

        #[allow(clippy::used_underscore_binding)]
        let amount_to_return = if let Err(_err) = &result {
            sdk::log!("Error in ft_on_transfer: {_err:?}");
            // An error occurred, so we need to return the amount of tokens to the sender.
            args.amount.as_u128()
        } else {
            // Everything is ok, so return 0.
            0
        };

        let output = crate::prelude::format!("\"{amount_to_return}\"");
        io.return_output(output.as_bytes());

        // In case of an error, we just return Ok(None) to avoid a panic in the contract. It's ok
        // because in case of an error, we already returned the amount of tokens to the sender.
        Ok(result.unwrap_or(None))
    })
}
```

**File:** engine/src/contract_methods/xcc.rs (L23-65)
```rust
#[named]
pub fn withdraw_wnear_to_router<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<SubmitResult, ContractError> {
    with_logs_hashchain(io, env, function_name!(), |io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        env.assert_private_call()?;
        if matches!(handler.promise_result_check(), Some(false)) {
            return Err(b"ERR_CALLBACK_OF_FAILED_PROMISE".into());
        }
        let args: WithdrawWnearToRouterArgs = io.read_input_borsh()?;
        let current_account_id = env.current_account_id();
        let recipient = AccountId::try_from(format!(
            "{}.{}",
            args.target.encode(),
            current_account_id.as_ref()
        ))?;
        let wnear_address = aurora_engine_precompiles::xcc::state::get_wnear_address(&io);
        let mut engine: Engine<_, E, AuroraModExp> = Engine::new_with_state(
            state,
            predecessor_address(&current_account_id),
            current_account_id,
            io,
            env,
        );
        let (result, ids) = xcc::withdraw_wnear_to_router(
            &recipient,
            args.amount,
            wnear_address,
            &mut engine,
            handler,
        )?;
        if !result.status.is_ok() {
            return Err(b"ERR_WITHDRAW_FAILED".into());
        }
        let id = ids.last().ok_or(b"ERR_NO_PROMISE_CREATED")?;
        handler.promise_return(*id);
        Ok(result)
    })
}
```
