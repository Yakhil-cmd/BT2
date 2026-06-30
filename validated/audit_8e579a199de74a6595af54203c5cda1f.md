### Title
Permissionless `deploy_erc20_token` (Legacy) Registers Codeless NEP-141 Accounts, Enabling Unlimited ERC-20 Mirror Token Inflation - (File: `engine/src/contract_methods/connector.rs`)

### Summary

The `deploy_erc20_token` function's `Legacy` path has no access control and no check that the supplied NEP-141 `AccountId` has contract code deployed. Any NEAR account can register an arbitrary, codeless NEAR account as a bridged NEP-141 token, deploy its ERC-20 mirror on Aurora, and then call `ft_on_transfer` directly from that codeless account to mint an unlimited number of ERC-20 mirror tokens to any EVM address.

### Finding Description

**Root cause — `deploy_erc20_token` (Legacy path) is permissionless and performs no code-existence check:** [1](#0-0) 

The only guard is `require_running`. There is no `require_owner_only` and no cross-contract call to verify the NEP-141 account exists or has code. The `WithMetadata` variant does call `ft_metadata` on the target account first (which would fail for a codeless account), but the `Legacy` variant skips this entirely. [2](#0-1) 

`engine::deploy_erc20_token` deploys the ERC-20 bytecode and calls `register_token(address, nep141)` — the only failure mode is `TokenAlreadyRegistered`. No check is made that `nep141` has code.

**Second step — `ft_on_transfer` trusts the registered mapping without verifying the caller is a real NEP-141 contract:** [3](#0-2) 

When `predecessor_account_id` is not the ETH connector, `receive_erc20_tokens` is called. It looks up the ERC-20 address via `get_erc20_from_nep141` — which succeeds because the attacker already registered the mapping — and then calls the ERC-20 `mint` function from the Aurora Engine admin address. [4](#0-3) 

The mint call is made from `erc20_admin_address = current_address(current_account_id)`, which is the Aurora Engine's own EVM address. The ERC-20 contract's mint guard only checks that the caller is the admin, so it succeeds unconditionally.

**Attack chain:**

1. Attacker creates a NEAR account `fake_nep141.near` (no contract code required; a plain NEAR account with a key suffices).
2. Attacker calls `deploy_erc20_token(DeployErc20TokenArgs::Legacy("fake_nep141.near"))` from any account. An ERC-20 mirror is deployed and the mapping `fake_nep141.near → erc20_address` is stored in Aurora's state.
3. Attacker calls `ft_on_transfer` **from** `fake_nep141.near` with `amount = u128::MAX` and `msg = <attacker_evm_address_hex>`.
4. `receive_erc20_tokens` resolves the mapping, calls `mint(attacker_evm_address, u128::MAX)` via the admin path — succeeds.
5. Attacker holds `u128::MAX` ERC-20 mirror tokens backed by zero real NEP-141 tokens.

**Front-run variant (theft of real funds):**

If the attacker knows a legitimate NEP-141 token (`usdc.near`) is about to be bridged to Aurora, they can execute steps 1–5 before the real deployment. When real users later bridge their `usdc.near` tokens (locking them in Aurora Engine's NEP-141 account), the attacker calls `exit_to_near` with their pre-minted ERC-20 tokens, causing Aurora Engine to call `ft_transfer` on the now-deployed `usdc.near` contract and transfer real tokens to the attacker.

### Impact Explanation

**Critical — Direct theft of user funds / insolvency of the bridge.**

An attacker can mint an unbounded quantity of any ERC-20 mirror token. In the front-run scenario, real NEP-141 tokens locked in the bridge can be drained by redeeming the inflated ERC-20 balance via `exit_to_near`. Even without front-running, the inflated ERC-20 balance can be used in any EVM DeFi protocol on Aurora that accepts the token, enabling theft from liquidity providers.

### Likelihood Explanation

**High.** `deploy_erc20_token` (Legacy) is a public, permissionless NEAR function — no special role or key is required. Creating a NEAR account without code is trivial and free beyond the account creation deposit. Calling `ft_on_transfer` directly from a codeless NEAR account requires only a function-call key on that account, which the attacker holds since they created it. No privileged access, oracle, or governance capture is needed.

### Recommendation

1. **Add a code-existence check in `deploy_erc20_token` (Legacy path):** Before registering the NEP-141 → ERC-20 mapping, issue a cross-contract view call to the NEP-141 account (e.g., `ft_metadata`) and only proceed in the callback if the call succeeds — exactly as the `WithMetadata` path already does.
2. **Add access control to `deploy_erc20_token`:** Restrict the caller to the contract owner or a designated allowlist, consistent with how `mirror_erc20_token` is guarded by `require_owner_only`. [5](#0-4) 

`mirror_erc20_token` already demonstrates the correct pattern — `require_owner_only` before any state change.

### Proof of Concept

```rust
// Step 1: Any NEAR account calls deploy_erc20_token with a codeless account ID.
// predecessor = "attacker.near" (no special role)
let args = DeployErc20TokenArgs::Legacy("fake_nep141.near".parse().unwrap());
// → ERC-20 mirror deployed; mapping fake_nep141.near → erc20_addr stored.

// Step 2: Attacker calls ft_on_transfer FROM fake_nep141.near.
// predecessor = "fake_nep141.near" (codeless NEAR account, attacker holds the key)
let args = FtOnTransferArgs {
    sender_id: "attacker.near".parse().unwrap(),
    amount: Balance::new(u128::MAX),
    msg: hex::encode(attacker_evm_address.as_bytes()),
};
// → receive_erc20_tokens called; get_erc20_from_nep141 succeeds;
//   ERC-20 mint(attacker_evm_address, u128::MAX) executed from admin address.
// → Attacker holds u128::MAX ERC-20 mirror tokens backed by zero real NEP-141 tokens.
``` [6](#0-5) [7](#0-6)

### Citations

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

**File:** engine/src/contract_methods/connector.rs (L112-131)
```rust
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

**File:** engine/src/contract_methods/connector.rs (L456-463)
```rust
pub fn mirror_erc20_token<I: IO + Env + Copy, H: PromiseHandler>(
    io: I,
    handler: &mut H,
) -> Result<(), ContractError> {
    let state = state::get_state(&io)?;
    require_running(&state)?;
    // TODO: Add an admin access list of accounts allowed to do it.
    require_owner_only(&state, &io.predecessor_account_id())?;
```

**File:** engine/src/engine.rs (L796-837)
```rust
    pub fn receive_erc20_tokens<P: PromiseHandler>(
        &mut self,
        token: &AccountId,
        args: &FtOnTransferArgs,
        current_account_id: &AccountId,
        handler: &mut P,
    ) -> Result<Option<SubmitResult>, ContractError> {
        let amount = args.amount.as_u128();
        // Parse message to determine recipient
        let mut recipient = {
            // The message should contain the recipient EOA address.
            let message = args.msg.strip_prefix("0x").unwrap_or(&args.msg);
            // Recipient - 40 characters (Address in hex without '0x' prefix)
            if message.len() < 40 {
                return Err(ParseOnTransferMessageError::WrongMessageFormat.into());
            }
            let mut address_bytes = [0; 20];
            hex::decode_to_slice(&message[..40], &mut address_bytes)
                .map_err(|_| ParseOnTransferMessageError::WrongMessageFormat)?;
            Address::from_array(address_bytes)
        };

        if let Some(fallback_address) = silo::get_erc20_fallback_address(&self.io)
            && !silo::is_allow_receive_erc20_tokens(&self.io, &recipient)
        {
            recipient = fallback_address;
        }

        let erc20_token = get_erc20_from_nep141(&self.io, token)?;
        let erc20_admin_address = current_address(current_account_id);
        let result = self
            .call(
                &erc20_admin_address,
                &erc20_token,
                Wei::zero(),
                setup_receive_erc20_tokens_input(&recipient, amount),
                u64::MAX,
                Vec::new(), // TODO: are there values we should put here?
                Vec::new(),
                handler,
            )
            .and_then(submit_result_or_err)?;
```

**File:** engine/src/engine.rs (L1339-1374)
```rust
/// Used to bridge NEP-141 tokens from NEAR to Aurora. On Aurora the NEP-141 becomes an ERC-20.
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
```
