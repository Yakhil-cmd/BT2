### Title
Uninitialized `CODE_STAGE_KEY` Allows `deploy_upgrade` to Execute Without Prior `stage_upgrade`, Bypassing the Time-Lock - (`engine/src/lib.rs`)

### Summary

The `deploy_upgrade` entrypoint in Aurora Engine enforces a time-lock by reading a staged block-height from storage key `CODE_STAGE_KEY`. When `CODE_STAGE_KEY` has never been written (i.e., `stage_upgrade` has not been called, or after a previous `deploy_upgrade` erased it), the storage read returns the default value of `0`. The guard condition `block_height <= 0` is false for every block after genesis, so the time-lock is silently bypassed. Because `deploy_upgrade` carries **no caller access-control check**, any unprivileged account can trigger a self-deploy from whatever bytes are stored under `CODE_KEY` at that moment — including empty bytes — permanently wiping the contract and freezing all bridged funds.

---

### Finding Description

The upgrade lifecycle is a two-step process:

**Step 1 — `stage_upgrade`** (owner-only):
Writes the WASM code to `CODE_KEY` and writes `block_height + upgrade_delay_blocks` to `CODE_STAGE_KEY`. [1](#0-0) 

**Step 2 — `deploy_upgrade`** (no access control):
Reads `CODE_STAGE_KEY` via `internal_get_upgrade_index()`, checks whether the current block has passed the staged index, then self-deploys from `CODE_KEY`. [2](#0-1) 

The critical flaw is in `deploy_upgrade`:

```rust
pub extern "C" fn deploy_upgrade() {
    let mut io = Runtime;
    let state = state::get_state(&io).sdk_unwrap();
    require_running(&state).map_err(ContractError::msg).sdk_unwrap();
    let index = internal_get_upgrade_index();   // returns 0 if CODE_STAGE_KEY absent
    if io.block_height() <= index {             // false for any block > 0
        sdk::panic_utf8(errors::ERR_NOT_ALLOWED_TOO_EARLY);
    }
    Runtime::self_deploy(&bytes_to_key(KeyPrefix::Config, CODE_KEY));
    io.remove_storage(&bytes_to_key(KeyPrefix::Config, CODE_STAGE_KEY));
}
``` [3](#0-2) 

There is **no `require_owner_only` call** anywhere in `deploy_upgrade`. The sole protection is the time-lock comparison. When `CODE_STAGE_KEY` is absent from storage, `internal_get_upgrade_index()` returns `0` (the NEAR storage default for a missing key read as `u64`). The condition `block_height <= 0` is false at every real block height, so the guard never fires and `self_deploy` is called unconditionally.

After a legitimate `deploy_upgrade` completes, `CODE_STAGE_KEY` is explicitly erased: [4](#0-3) 

but `CODE_KEY` is **not** erased. This leaves the previously staged WASM permanently readable. Any subsequent call to `deploy_upgrade` — by anyone — will re-deploy that WASM with no delay and no authorization check.

The same window exists from contract genesis until the first `stage_upgrade` call: `CODE_STAGE_KEY` is absent, `CODE_KEY` is absent (empty bytes), and `deploy_upgrade` will self-deploy empty code, erasing the contract entirely.

The `EngineState` struct defaults `upgrade_delay_blocks` to `0`: [5](#0-4) 

meaning even a legitimately staged upgrade with `upgrade_delay_blocks = 0` produces `CODE_STAGE_KEY = current_block`, and the check `block_height <= current_block` is immediately false, so the delay provides no protection in that configuration either.

---

### Impact Explanation

**Critical — Permanent freezing of funds / contract destruction.**

Aurora Engine holds all bridged ETH and ERC-20 balances in its NEAR storage trie. If an attacker calls `deploy_upgrade` when `CODE_KEY` is absent (pre-first-staging window) or contains stale/malicious code, `Runtime::self_deploy` overwrites the live contract WASM. Deploying empty bytes destroys all contract logic; no further calls (`withdraw`, `submit`, `call`) can succeed. All bridged assets become permanently inaccessible.

---

### Likelihood Explanation

**High.** The entry point `deploy_upgrade` is a public, permissionless NEAR contract method callable by any account. The vulnerable window (uninitialized `CODE_STAGE_KEY`) exists:

1. From contract deployment until the first `stage_upgrade` call.
2. Immediately after every successful `deploy_upgrade` (which erases `CODE_STAGE_KEY`).

An attacker monitoring the NEAR chain can detect either window and submit the attack transaction in the very next block. No privileged access, leaked keys, or governance capture is required.

---

### Recommendation

1. **Add caller access control to `deploy_upgrade`**: require `predecessor_account_id == owner_id` (mirroring `stage_upgrade`).
2. **Guard against uninitialized `CODE_STAGE_KEY`**: if `CODE_STAGE_KEY` is absent, `deploy_upgrade` must revert rather than treating the index as `0`.
3. **Clear `CODE_KEY` after deployment**: remove `CODE_KEY` at the end of `deploy_upgrade` so stale WASM cannot be re-deployed in a subsequent unguarded call.

---

### Proof of Concept

**Scenario A — Pre-staging window (contract destruction):**

1. Aurora Engine is deployed; `new()` is called. `CODE_STAGE_KEY` and `CODE_KEY` are absent.
2. Attacker calls `deploy_upgrade()`.
3. `internal_get_upgrade_index()` reads absent `CODE_STAGE_KEY` → returns `0`.
4. `block_height <= 0` is `false` → guard does not fire.
5. `Runtime::self_deploy(CODE_KEY)` deploys empty bytes → contract WASM is wiped.
6. All subsequent calls to the engine panic. All bridged ETH and ERC-20 balances are permanently frozen.

**Scenario B — Post-deploy replay (unauthorized re-deployment):**

1. Owner calls `stage_upgrade` at block B with delay D → `CODE_STAGE_KEY = B + D`, `CODE_KEY = <new WASM>`.
2. At block `B + D + 1`, owner calls `deploy_upgrade` → succeeds; `CODE_STAGE_KEY` is erased, `CODE_KEY` still holds `<new WASM>`.
3. Attacker immediately calls `deploy_upgrade` again → `CODE_STAGE_KEY` absent → index = 0 → guard bypassed → `<new WASM>` is re-deployed with no authorization.

Relevant code references: [2](#0-1) [1](#0-0) [5](#0-4)

### Citations

**File:** engine/src/contract_methods/admin.rs (L154-166)
```rust
pub fn stage_upgrade<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        let delay_block_height = env.block_height() + state.upgrade_delay_blocks;
        require_owner_only(&state, &env.predecessor_account_id())?;
        io.read_input_and_store(&storage::bytes_to_key(KeyPrefix::Config, CODE_KEY));
        io.write_storage(
            &storage::bytes_to_key(KeyPrefix::Config, CODE_STAGE_KEY),
            &delay_block_height.to_le_bytes(),
        );
        Ok(())
    })
```

**File:** engine/src/lib.rs (L169-185)
```rust
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
```

**File:** engine/src/state.rs (L18-31)
```rust
#[derive(Default, Clone, PartialEq, Eq, Debug)]
pub struct EngineState {
    /// Chain id, according to the EIP-155 / ethereum-lists spec.
    pub chain_id: [u8; 32],
    /// Account which can upgrade this contract.
    /// Use empty to disable updatability.
    pub owner_id: AccountId,
    /// How many blocks after staging upgrade can deploy it.
    pub upgrade_delay_blocks: u64,
    /// Flag to pause and unpause the engine.
    pub is_paused: bool,
    /// Relayer key manager.
    pub key_manager: Option<AccountId>,
}
```
