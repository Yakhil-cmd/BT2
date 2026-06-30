### Title
Upgrade and Precompile-Resume Paths Blocked When Contract Is Paused, Forcing Re-Exposure of Active Exploit Window - (File: `engine/src/contract_methods/admin.rs`)

---

### Summary

Both upgrade paths (`upgrade`, `stage_upgrade`, `deploy_upgrade`) and `resume_precompiles` unconditionally call `require_running`, which panics when `is_paused == true`. When the owner pauses the engine in response to an active exploit, every mechanism for deploying a corrective code fix is simultaneously blocked. The only way to unblock upgrades is to call `resume_contract` first — which re-exposes the live exploit — before the fix can be staged or deployed. This is a direct structural analog to the UMA "lack of emergency administration" finding: the safety mechanism (pause) and the remediation mechanism (upgrade) are mutually exclusive, with no out-of-band escape hatch.

---

### Finding Description

`stage_upgrade` enforces `require_running` before accepting new WASM code: [1](#0-0) 

`upgrade` (immediate path) also enforces `require_running`: [2](#0-1) 

`deploy_upgrade` (the public finalisation step for staged upgrades) enforces `require_running` in `lib.rs`: [3](#0-2) 

`resume_precompiles` also enforces `require_running`, so granular precompile state cannot be adjusted while the engine is globally paused: [4](#0-3) 

`require_running` is defined as a hard revert whenever `is_paused` is `true`: [5](#0-4) 

`resume_contract` — the only function that clears `is_paused` — does **not** require `require_running`, so the owner can always resume. However, it does not accept WASM code; it only clears the flag: [6](#0-5) 

The `EngineState` struct confirms `is_paused` is a single boolean that gates all of the above: [7](#0-6) 

The consequence is that the owner faces a forced two-transaction sequence with no atomic alternative:

1. **Tx A** — `resume_contract`: clears `is_paused`, contract is live with the vulnerable code.
2. **Tx B** — `upgrade` / `stage_upgrade` + `deploy_upgrade`: deploys the fix.

Between Tx A and Tx B the engine is fully operational with the unpatched code. Any attacker watching the chain can front-run or race Tx B.

---

### Impact Explanation

**Temporary freezing of funds (High):** While the contract is paused, all EVM execution entry points (`submit`, `call`, `deploy_code`) revert via `require_running`. Users cannot withdraw bridged ETH or ERC-20 tokens through the exit precompiles. If the owner judges the exploit too dangerous to resume even briefly, the pause becomes indefinite and the freeze becomes permanent.

**Potential direct theft of user funds (Critical):** If the original exploit targets the ETH connector or exit precompiles (e.g., a double-spend or accounting bug), the mandatory resume window between Tx A and Tx B gives an attacker a live window to drain funds before the fix lands.

---

### Likelihood Explanation

The scenario requires an exploit serious enough to trigger `pause_contract`. Aurora Engine's bridge holds real ETH and ERC-20 value on mainnet; the pause mechanism exists precisely for this class of event. The forced resume-before-upgrade sequence is not a hypothetical edge case — it is the only available upgrade path, and it is exercised every time a code fix must be deployed to a paused contract. The likelihood of the window being exploited scales directly with the severity of the original bug (high-value bugs attract sophisticated attackers who monitor governance transactions).

---

### Recommendation

Remove `require_running` from `upgrade`, `stage_upgrade`, and `deploy_upgrade`. These functions are already gated by `require_owner_only` (or are public but time-locked), so the running check adds no security benefit while creating the deadlock described above. Alternatively, introduce a dedicated `emergency_upgrade` entry point that bypasses the running check but requires a stricter caller check (e.g., a separate multisig key stored in state), mirroring the recommendation in the UMA report.

---

### Proof of Concept

```
1. Attacker discovers a reentrancy or accounting bug in the exit precompile.
2. Owner calls pause_contract()  →  is_paused = true.
   - All submit/call/exit paths revert with ERR_PAUSED.
   - All user funds are frozen.
3. Owner prepares patched WASM and calls upgrade(patched_wasm).
   - FAILS: require_running() → ERR_PAUSED.
4. Owner calls stage_upgrade(patched_wasm).
   - FAILS: require_running() → ERR_PAUSED.
5. Owner has no choice: calls resume_contract()  →  is_paused = false.
   - Engine is now live with the UNPATCHED code.
6. Attacker (watching mempool) immediately calls the exploit entry point
   before the owner's upgrade transaction is included.
   - Funds are drained.
7. Owner's upgrade(patched_wasm) lands in a later block — too late.
```

### Citations

**File:** engine/src/contract_methods/admin.rs (L154-157)
```rust
pub fn stage_upgrade<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
```

**File:** engine/src/contract_methods/admin.rs (L169-176)
```rust
pub fn upgrade<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<(), ContractError> {
    let state = state::get_state(&io)?;
    require_running(&state)?;
    require_owner_only(&state, &env.predecessor_account_id())?;
```

**File:** engine/src/contract_methods/admin.rs (L209-215)
```rust
pub fn resume_precompiles<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |io| {
        let state = state::get_state(&io)?;
        require_running(&state)?;
        let predecessor_account_id = env.predecessor_account_id();

        require_owner_only(&state, &predecessor_account_id)?;
```

**File:** engine/src/contract_methods/admin.rs (L263-271)
```rust
pub fn resume_contract<I: IO + Copy, E: Env>(io: I, env: &E) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        let mut state = state::get_state(&io)?;
        require_owner_only(&state, &env.predecessor_account_id())?;
        require_paused(&state)?;
        state.is_paused = false;
        state::set_state(&mut io, &state)?;
        Ok(())
    })
```

**File:** engine/src/lib.rs (L171-178)
```rust
    pub extern "C" fn deploy_upgrade() {
        // This function is intentionally not implemented in `contract_methods`
        // because it only makes sense in the context of the NEAR runtime.
        let mut io = Runtime;
        let state = state::get_state(&io).sdk_unwrap();
        require_running(&state)
            .map_err(ContractError::msg)
            .sdk_unwrap();
```

**File:** engine/src/contract_methods/mod.rs (L65-70)
```rust
pub fn require_running(state: &state::EngineState) -> Result<(), ContractError> {
    if state.is_paused {
        return Err(errors::ERR_PAUSED.into());
    }
    Ok(())
}
```

**File:** engine/src/state.rs (L19-31)
```rust
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
