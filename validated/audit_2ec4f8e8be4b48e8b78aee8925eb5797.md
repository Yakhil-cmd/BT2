### Title
Unbounded Loop in `move_to_block` Causes NEAR Gas Exhaustion When Hashchain Is Stale, Temporarily Freezing All Hashchain-Gated Contract Methods — (File: `engine-hashchain/src/hashchain.rs`)

---

### Summary

The `Hashchain::move_to_block` function iterates through every skipped NEAR block in a `while` loop, performing a keccak hash per iteration. When the Aurora Engine is inactive for a large number of NEAR blocks, the first transaction that calls any hashchain-enabled method triggers this loop with an unbounded iteration count, exhausting the NEAR 300 TGas per-transaction gas budget. Because the NEAR runtime reverts all state changes on gas exhaustion, the hashchain state remains at the old block height, causing every subsequent hashchain-enabled call to also fail — a self-reinforcing denial of service that freezes all hashchain-gated operations until admin intervention.

---

### Finding Description

`Hashchain::move_to_block` in `engine-hashchain/src/hashchain.rs` contains an uncapped `while` loop:

```rust
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
``` [1](#0-0) 

Each iteration calls `compute_block_hashchain`, which invokes `keccak` (a NEAR host function with non-trivial gas cost) and `StreamCompactMerkleTree::compute_hash`. [2](#0-1) 

This loop is triggered unconditionally in `load_hashchain` whenever the stored hashchain block height lags behind the current NEAR block height:

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
``` [3](#0-2) 

`load_hashchain` is called at the start of every `with_hashchain` and `with_logs_hashchain` wrapper, which gates all major contract entry points including `submit`, `ft_on_transfer`, `register_relayer`, and others. [4](#0-3) 

The analogy to the original report is direct: just as `alpha → 0` when `price_w()` is not called for a long time (allowing a single transaction to dominate the EMA), here the block-height gap grows unboundedly when the engine is idle, causing a single transaction to trigger an unbounded computation that exhausts the NEAR gas budget.

---

### Impact Explanation

NEAR enforces a hard 300 TGas limit per transaction. Each keccak host-function call consumes a fixed amount of NEAR gas. Once the block gap (`current_block_height` lag) exceeds the number of keccak iterations that fit within 300 TGas, every call to a hashchain-enabled method is aborted by the NEAR runtime. Because NEAR reverts all state changes on gas exhaustion, the hashchain state is never advanced, so every subsequent call also fails. This freezes all hashchain-gated operations — including ERC-20 bridging via `ft_on_transfer` and EVM transaction submission via `submit` — until an admin manually resets the hashchain via `start_hashchain` (which itself requires the contract to be paused first). [5](#0-4) 

**Impact class**: High — Temporary freezing of funds (all hashchain-enabled operations blocked until admin intervention).

---

### Likelihood Explanation

NEAR produces approximately one block per second. The exact gas cost of each loop iteration depends on the NEAR host-function pricing for keccak and the merkle tree computation, but it is bounded and finite. If, for example, each iteration costs ~1 TGas, then only ~300 blocks (~5 minutes) of inactivity would be sufficient to trigger the DoS. Even at a more conservative 0.1 TGas per iteration, ~3,000 blocks (~50 minutes) of inactivity suffices. Aurora Engine is a production system that can experience periods of low activity. Any unprivileged user submitting the first transaction after such a period would trigger the condition — no special privileges or coordination required.

---

### Recommendation

Cap the number of blocks processed per call in `move_to_block`. If the gap exceeds a safe maximum (e.g., 100 blocks), either:
1. Process only up to the cap per call and store the intermediate state, or
2. Skip intermediate empty blocks by computing the iterated hash mathematically (since empty blocks have a deterministic structure), or
3. Detect a large gap in `load_hashchain` and return an error that triggers a controlled admin reset path rather than attempting the unbounded loop.

Additionally, the `start_hashchain` recovery path should be hardened to accept a `block_height` equal to `current_block_height - 1` so that `move_to_block` is never called during recovery, ensuring the admin can always reset the hashchain regardless of the gap size. [6](#0-5) 

---

### Proof of Concept

1. The Aurora Engine hashchain is initialized at block height `B` via `start_hashchain`.
2. The engine receives no hashchain-enabled transactions for `N` NEAR blocks (where `N` exceeds the per-transaction gas budget divided by the per-iteration gas cost).
3. At block height `B + N`, any unprivileged user submits any hashchain-enabled transaction (e.g., a simple ETH transfer via `submit`).
4. `with_logs_hashchain` calls `load_hashchain`, which calls `hashchain.move_to_block(B + N)`.
5. The loop runs `N` iterations, each calling `compute_block_hashchain` (keccak + merkle hash).
6. The NEAR runtime aborts the transaction at the 300 TGas limit; all state changes are reverted.
7. The hashchain state remains at block height `B`.
8. Every subsequent hashchain-enabled call repeats steps 4–7 and also fails.
9. All hashchain-gated operations are frozen until an admin pauses the contract and calls `start_hashchain` with `args.block_height = current_block_height - 1`. [7](#0-6) [8](#0-7)

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

**File:** engine-hashchain/src/hashchain.rs (L269-289)
```rust
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

**File:** engine/src/hashchain.rs (L54-86)
```rust
pub fn with_logs_hashchain<I, E, F>(
    mut io: I,
    env: &E,
    function_name: &str,
    f: F,
) -> Result<SubmitResult, ContractError>
where
    I: IO + Copy,
    E: Env,
    F: for<'a> FnOnce(CachedIO<'a, I>) -> Result<SubmitResult, ContractError>,
{
    let block_height = env.block_height();
    let maybe_hashchain = load_hashchain(&io, block_height)?;

    let cache = RefCell::new(IOCache::default());
    let hashchain_io = CachedIO::new(io, &cache);
    let result = f(hashchain_io)?;

    if let Some(mut hashchain) = maybe_hashchain {
        let log_bloom = bloom::get_logs_bloom(&result.logs);
        let cache_ref = cache.borrow();
        hashchain.add_block_tx(
            block_height,
            function_name,
            &cache_ref.input,
            &cache_ref.output,
            &log_bloom,
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

**File:** engine/src/contract_methods/admin.rs (L426-463)
```rust
pub fn start_hashchain<I: IO + Copy, E: Env>(mut io: I, env: &E) -> Result<(), ContractError> {
    let mut state = state::get_state(&io)?;
    require_paused(&state)?;
    require_key_manager_only(&state, &env.predecessor_account_id())?;

    let input = io.read_input().to_vec();
    let args = StartHashchainArgs::try_from_slice(&input).map_err(|_| errors::ERR_SERIALIZE)?;
    let block_height = env.block_height();

    // Starting hashchain must be for an earlier block
    if block_height < args.block_height {
        return Err(errors::ERR_ARGS.into());
    }

    let mut hashchain = Hashchain::new(
        state.chain_id,
        env.current_account_id(),
        args.block_height + 1,
        args.block_hashchain,
    );

    if hashchain.get_current_block_height() < block_height {
        hashchain.move_to_block(block_height)?;
    }

    hashchain.add_block_tx(
        block_height,
        function_name!(),
        &input,
        &[],
        &Bloom::default(),
    )?;
    crate::hashchain::save_hashchain(&mut io, &hashchain)?;

    state.is_paused = false;
    state::set_state(&mut io, &state)?;

    Ok(())
```
