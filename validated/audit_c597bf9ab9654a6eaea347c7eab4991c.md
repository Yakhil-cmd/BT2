### Title
Missing Creation Fee in `deploy_erc20_token` Enables Spam Deployment of ERC-20 Mirror Contracts — (File: `engine/src/contract_methods/connector.rs`)

---

### Summary

The `deploy_erc20_token` public NEAR contract method in Aurora Engine imposes no creation fee and no caller access control beyond a liveness check. Any NEAR account can invoke it at negligible cost to register arbitrary NEP-141 account IDs as ERC-20 mirror contracts, bloating the engine's EVM state and NEAR on-chain storage. Sustained spam can exhaust the engine's NEAR storage budget, preventing it from writing any new state and temporarily freezing all user funds held in the engine.

---

### Finding Description

The entrypoint `deploy_erc20_token()` in `engine/src/lib.rs` delegates directly to `contract_methods::connector::deploy_erc20_token`. [1](#0-0) 

Inside that function the only guard is `require_running`, which checks that the engine is not paused. There is no owner assertion, no minimum attached deposit, and no creation fee of any kind. [2](#0-1) 

For the `Legacy` variant the call flows immediately into `engine::deploy_erc20_token`, which:

1. Constructs an `Engine` whose EVM origin is derived from the NEAR `predecessor_account_id` (not from a signed EVM transaction, so no EVM gas price is enforced by the transaction layer).
2. Deploys the full ERC-20 bytecode into the EVM state via `deploy_code_with_input`.
3. Persists a bidirectional NEP-141 ↔ ERC-20 address mapping in NEAR storage via `register_token`. [3](#0-2) 

By contrast, the XCC infrastructure creation path explicitly enforces a minimum NEAR deposit (`fund_amount >= STORAGE_AMOUNT`) before creating any sub-account, demonstrating that the project is aware of the pattern and applies it selectively. [4](#0-3) 

The `deploy_erc20_token_callback` (the `WithMetadata` path's callback) is protected by `env.assert_private_call()`, but the `Legacy` path has no equivalent guard. [5](#0-4) 

---

### Impact Explanation

Each call to `deploy_erc20_token` writes at minimum:

- The compiled ERC-20 bytecode into EVM contract storage.
- Two NEAR storage entries for the NEP-141 ↔ ERC-20 bidirectional map.

In NEAR Protocol, a contract's usable storage is bounded by its staked NEAR balance. If an attacker floods the engine with spurious `deploy_erc20_token` calls, the engine's storage usage grows without bound. Once the engine's NEAR balance falls below the storage-staking requirement, NEAR Runtime will reject any state-writing operation from the engine contract — including `submit` (EVM transactions), `ft_on_transfer` (bridging), and `withdraw`. This constitutes a **temporary freezing of all user funds** held in the Aurora engine until the storage is reclaimed or the engine's NEAR balance is topped up by the operator.

**Impact: High — Temporary freezing of funds.**

---

### Likelihood Explanation

The attack requires only a NEAR account and enough NEAR to pay per-transaction gas fees (fractions of a cent per call on mainnet). No ETH balance in Aurora is required because the call is a NEAR-native method invocation, not a signed EVM transaction, so no EVM-layer gas price is applied. The attacker does not need any special privilege, whitelisting, or prior relationship with the protocol. The attack is fully automatable with a simple script.

**Likelihood: Medium** — requires sustained effort and NEAR gas spend, but no meaningful economic barrier.

---

### Recommendation

Require a non-trivial attached NEAR deposit for each `deploy_erc20_token` call, analogous to the `STORAGE_AMOUNT` check already present in `fund_xcc_infrastructure`. The deposit should cover at minimum the NEAR storage staking cost of the new EVM contract state and the two mapping entries. Alternatively, restrict the caller to the engine owner or a governance-controlled allowlist, consistent with the comment already present in the `WithMetadata` branch ("this transaction could be executed by the owner of the contract only") and enforce it for the `Legacy` branch as well.

---

### Proof of Concept

```
# Attacker script (pseudocode)
for i in 1..10_000:
    near call aurora.mainnet deploy_erc20_token \
        --args borsh_encode(Legacy("spam_token_{i}.near")) \
        --accountId attacker.near \
        --gas 30000000000000   # 30 TGas, ~$0.001 per call
```

Each iteration:
1. Passes `require_running` (engine is live).
2. Enters the `Legacy` branch — no fee check, no owner check.
3. Deploys the full ERC-20 bytecode into EVM state.
4. Writes two NEAR storage entries for the NEP-141 ↔ ERC-20 map.

After enough iterations the engine's storage staking requirement exceeds its NEAR balance, and all subsequent state-writing calls — including user withdrawals — are rejected by the NEAR runtime, freezing user funds.

### Citations

**File:** engine/src/lib.rs (L613-621)
```rust
    #[unsafe(no_mangle)]
    pub extern "C" fn deploy_erc20_token() {
        let io = Runtime;
        let env = Runtime;
        let mut handler = Runtime;
        contract_methods::connector::deploy_erc20_token(io, &env, &mut handler)
            .map_err(ContractError::msg)
            .sdk_unwrap();
    }
```

**File:** engine/src/contract_methods/connector.rs (L111-131)
```rust
#[named]
pub fn deploy_erc20_token<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<PromiseOrValue<Address>, ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        require_running(&state::get_state(&io)?)?;
        let bytes = io.read_input().to_vec();
        let args =
            DeployErc20TokenArgs::deserialize(&bytes).map_err(|_| errors::ERR_BORSH_DESERIALIZE)?;

        match args {
            DeployErc20TokenArgs::Legacy(nep141) => {
                let address = engine::deploy_erc20_token(nep141, None, io, env, handler)?;

                io.return_output(
                    &borsh::to_vec(address.as_bytes()).map_err(|_| errors::ERR_SERIALIZE)?,
                );
                Ok(PromiseOrValue::Value(address))
            }
```

**File:** engine/src/contract_methods/connector.rs (L161-170)
```rust
#[named]
pub fn deploy_erc20_token_callback<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &mut H,
) -> Result<Address, ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        require_running(&state::get_state(&io)?)?;
        env.assert_private_call()?;

```

**File:** engine/src/engine.rs (L1340-1375)
```rust
pub fn deploy_erc20_token<I: IO + Copy, E: Env, P: PromiseHandler>(
    nep141: AccountId,
    metadata: Option<Erc20Metadata>,
    io: I,
    env: &E,
    handler: &mut P,
) -> Result<Address, DeployErc20Error> {
    let current_account_id = env.current_account_id();
    let input = setup_deploy_erc20_input(&current_account_id, metadata);
    let mut engine: Engine<_, _> = Engine::new(
        aurora_engine_sdk::types::near_account_to_evm_address(
            env.predecessor_account_id().as_bytes(),
        ),
        current_account_id,
        io,
        env,
    )
    .map_err(DeployErc20Error::State)?;

    let address = match engine.deploy_code_with_input(input, None, handler) {
        Ok(result) => match result.status {
            TransactionStatus::Succeed(ret) => {
                Address::new(H160(ret.as_slice().try_into().unwrap()))
            }
            other => return Err(DeployErc20Error::Failed(other)),
        },
        Err(e) => return Err(DeployErc20Error::Engine(e)),
    };

    sdk::log!("Deployed ERC-20 in Aurora at: {:#?}", address);
    engine
        .register_token(address, nep141)
        .map_err(DeployErc20Error::Register)?;

    Ok(address)
}
```

**File:** engine/src/xcc.rs (L115-118)
```rust
        if create_needed {
            if fund_amount < STORAGE_AMOUNT {
                return Err(FundXccError::InsufficientBalance);
            }
```
