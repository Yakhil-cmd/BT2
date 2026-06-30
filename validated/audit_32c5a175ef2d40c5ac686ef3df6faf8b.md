### Title
Unbounded `while` Loop in `Hashchain::move_to_block` Causes Permanent Engine Freeze After Inactivity - (File: `engine-hashchain/src/hashchain.rs`)

---

### Summary

The `Hashchain::move_to_block` function contains an unbounded `while` loop that iterates once per NEAR block elapsed since the last Aurora Engine transaction. When the hashchain feature is active and the engine has been idle for a sufficiently large number of NEAR blocks, the first subsequent transaction will exhaust the 300 Tgas NEAR gas limit inside this loop. Because the hashchain state is only persisted on success, the stored block height is never advanced, so every following transaction also fails. The engine becomes permanently frozen: no EVM transaction, deposit, withdrawal, or XCC call can be processed.

---

### Finding Description

`Hashchain::move_to_block` in `engine-hashchain/src/hashchain.rs` advances the hashchain from its stored block height to the current NEAR block height one block at a time:

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

Each iteration calls `compute_block_hashchain`, which invokes `txs_merkle_tree.compute_hash()` (itself a keccak256 call) and then a second keccak256 over ~400 bytes of concatenated data. Both are NEAR host-function calls that consume NEAR gas. [2](#0-1) 

`load_hashchain` calls `move_to_block` unconditionally whenever the stored height is behind the current block height:

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

`load_hashchain` is called from both `with_hashchain` and `with_logs_hashchain`, which wrap **every** production entrypoint: `submit`, `submit_with_args`, `call`, `deploy_code`, `ft_on_transfer`, `deposit`, `withdraw`, `execute` (XCC), and all admin methods. [4](#0-3) 

There is no cap on the number of loop iterations. The iteration count equals `current_block_height - stored_block_height`, which grows linearly with idle time. NEAR produces approximately one block per second; a gap of a few hundred to a few thousand blocks (minutes to hours of inactivity) is sufficient to exhaust the 300 Tgas per-transaction NEAR gas limit.

Because the hashchain is only written back to storage after the loop completes successfully, a gas-exhausted call leaves the stored height unchanged. Every subsequent call re-enters the same loop with the same (or larger) gap and fails identically.

---

### Impact Explanation

**Critical — Permanent freezing of funds.**

Once the gas limit is exceeded, no Aurora Engine function that wraps `with_hashchain` or `with_logs_hashchain` can succeed. This covers the full set of user-facing operations: EVM transaction submission, ETH/token deposits, withdrawals, and cross-contract calls. All ETH and ERC-20 balances held inside the Aurora Engine become inaccessible. The only recovery path would be an admin upgrade that resets or disables the hashchain, but that upgrade call itself goes through `with_hashchain` and would also fail.

---

### Likelihood Explanation

**Medium-High.** NEAR mainnet produces ~1 block per second. A gap of even a few hundred blocks (a few minutes of zero Aurora activity) can be enough to exhaust 300 Tgas given two keccak256 host-function calls per iteration. Periods of low activity are routine on any live network. The engine being paused by its owner and later resumed is another realistic trigger. No attacker action is required beyond submitting a normal transaction after the gap; the first user to do so triggers the freeze for everyone.

---

### Recommendation

1. **Cap the loop**: Limit `move_to_block` to a maximum number of iterations per call (e.g., 100–500). Return a new error variant if the gap exceeds the cap, and let callers retry in subsequent transactions.
2. **Lazy / amortised advancement**: Instead of catching up all missed blocks in one call, advance only one block per transaction and store the partial state.
3. **Gas guard**: Before entering the loop, estimate the remaining NEAR gas and abort early if insufficient, returning a retriable error rather than panicking.

---

### Proof of Concept

1. Enable the hashchain on a live Aurora Engine instance (`start_hashchain`).
2. Allow the NEAR chain to produce N blocks with no Aurora transactions (N ≈ 500 is sufficient for a conservative estimate; exact threshold depends on NEAR gas pricing for keccak256 host calls).
3. Submit any EVM transaction (e.g., a simple ETH transfer) via `submit`.
4. The call stack is: `submit` → `with_logs_hashchain` → `load_hashchain` → `hashchain.move_to_block(current_block_height)` → `while` loop runs N times → NEAR gas exhausted → transaction fails with a gas error.
5. Repeat step 3: the stored hashchain height is still at the pre-gap value, so the loop runs again with the same (or larger) N and fails again.
6. All user funds are now frozen; no EVM transaction, deposit, or withdrawal can succeed. [5](#0-4) [3](#0-2) [6](#0-5)

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
