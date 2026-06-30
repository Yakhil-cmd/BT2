### Title
ERC-20 Mirror Minting Uses Caller-Reported `ft_on_transfer` Amount Without Verifying Actual NEP-141 Balance Received — (`engine/src/engine.rs`, `engine/src/contract_methods/connector.rs`)

---

### Summary

The Aurora Engine's NEP-141→ERC-20 bridging path mints ERC-20 tokens based on the `amount` field supplied by the calling NEP-141 contract in the `ft_on_transfer` callback, without ever verifying the actual NEP-141 balance change in Aurora's account. For any fee-on-transfer (deflationary) NEP-141 token, Aurora receives fewer tokens than it mints ERC-20 for, creating a persistent insolvency: the ERC-20 total supply exceeds Aurora's real NEP-141 backing. The true shortfall is only discovered at exit time — an exact structural analog to the yToken `pricePerShare` / withdrawal-time loss realization described in the report.

---

### Finding Description

**Entry point — `ft_on_transfer` (connector.rs, line 62)**

When a NEP-141 token is transferred to Aurora via `ft_transfer_call`, the NEP-141 contract calls `ft_on_transfer` on Aurora. Aurora dispatches to `receive_erc20_tokens` for any non-base token:

```rust
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
``` [1](#0-0) 

**Root cause — `receive_erc20_tokens` (engine.rs, line 803)**

The function reads `args.amount` — the value the NEP-141 contract *claims* was transferred — and mints exactly that many ERC-20 tokens with no balance check:

```rust
let amount = args.amount.as_u128();
...
setup_receive_erc20_tokens_input(&recipient, amount),
``` [2](#0-1) 

There is no read of Aurora's actual NEP-141 balance before and after the transfer to confirm the real credit. The engine unconditionally trusts the caller-supplied `args.amount`. [3](#0-2) 

**Exit path — `withdrawToNear` (EvmErc20.sol, line 53) → `ExitToNear` precompile**

When a user exits, the ERC-20 contract burns the user's tokens and calls the `ExitToNear` precompile with the burned amount. The precompile schedules an `ft_transfer` on the NEP-141 contract for that same amount:

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);
    bytes32 amount_b = bytes32(amount);
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
``` [4](#0-3) 

The precompile then calls `ft_transfer` on the NEP-141 contract for the full burned amount: [5](#0-4) 

If Aurora's actual NEP-141 balance is less than the ERC-20 total supply (due to fee-on-transfer discrepancies accumulated during deposits), the `ft_transfer` call will fail for some users.

**`deploy_erc20_token` is permissionless**

Any account can call `deploy_erc20_token` to create an ERC-20 mirror for any NEP-141 token — there is no `require_owner_only` guard: [6](#0-5) 

---

### Impact Explanation

**Critical — Insolvency.**

For any fee-on-transfer NEP-141 token bridged to Aurora:

- Each `ft_transfer_call` of `N` tokens results in Aurora receiving `N - fee` NEP-141 tokens but minting `N` ERC-20 tokens.
- The ERC-20 total supply grows faster than Aurora's NEP-141 backing.
- When users exit, the first to exit receive full value; later users' `ft_transfer` calls fail because Aurora's NEP-141 balance is exhausted.
- This constitutes direct, permanent loss of funds for ERC-20 holders who cannot exit.

The shortfall is invisible until exit time — exactly the "true value only revealed during withdrawal" pattern from the report.

---

### Likelihood Explanation

**Medium.**

- `deploy_erc20_token` is callable by any account, so any NEP-141 token (including attacker-deployed ones) can be mirrored.
- An attacker can deploy a custom NEP-141 token with a configurable transfer fee, mirror it on Aurora, bridge tokens (Aurora mints more ERC-20 than NEP-141 held), sell the surplus ERC-20 to other users, then exit their own position — leaving other ERC-20 holders with unbacked tokens.
- Legitimate deflationary NEP-141 tokens (which do exist in the NEAR ecosystem) would trigger this naturally without any deliberate attack.
- No privileged access is required.

---

### Recommendation

**Short term:** In `receive_erc20_tokens`, read Aurora's NEP-141 balance for the token before and after the transfer (via a cross-contract view or by comparing the `ft_on_transfer` amount against the actual balance delta) and mint ERC-20 tokens only for the verified received amount.

**Long term:** Establish a protocol-level policy that only NEP-141 tokens without transfer fees are eligible for ERC-20 mirroring on Aurora, or implement a reconciliation mechanism that tracks the actual NEP-141 balance held per token and caps ERC-20 redemptions accordingly.

---

### Proof of Concept

1. Attacker deploys a NEP-141 token `evil.near` that charges a 10% fee on every `ft_transfer_call` (i.e., transfers `0.9 * amount` to the receiver but calls `ft_on_transfer` with `amount`).
2. Attacker calls `deploy_erc20_token` on Aurora for `evil.near` — succeeds with no access control.
3. Attacker calls `evil.near::ft_transfer_call(receiver_id=aurora, amount=1000, msg=<evm_address>)`.
   - `evil.near` transfers 900 tokens to Aurora.
   - `evil.near` calls `aurora::ft_on_transfer(sender_id=attacker, amount=1000, msg=<evm_address>)`.
   - Aurora executes `receive_erc20_tokens` → mints **1000** ERC-20 to attacker's EVM address.
   - Aurora's actual NEP-141 balance: **900**. ERC-20 total supply: **1000**.
4. Attacker calls `withdrawToNear(recipient, 1000)` on the ERC-20 contract.
   - ERC-20 burns 1000 tokens.
   - `ExitToNear` precompile schedules `evil.near::ft_transfer(receiver_id=attacker, amount=1000)`.
   - `evil.near` has only 900 tokens in Aurora's account → `ft_transfer` fails.
5. Attacker retries with 900 → succeeds. The 100-token shortfall is a permanent loss for any other ERC-20 holder of `evil.near`'s mirror.

### Citations

**File:** engine/src/contract_methods/connector.rs (L81-90)
```rust
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
```

**File:** engine/src/contract_methods/connector.rs (L112-130)
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
```

**File:** engine/src/engine.rs (L796-844)
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

        sdk::log!("Mint {amount} ERC-20 tokens for: {}", recipient.encode());

        // Return SubmitResult so that it can be accessed in standalone engine.
        // This is used to help with the indexing of bridge transactions.
        Ok(Some(result))
    }
```

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L53-60)
```text
    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        _burn(_msgSender(), amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
        uint input_size = 1 + 32 + recipient.length;

        assembly {
```

**File:** engine-precompiles/src/native.rs (L627-646)
```rust
        _ => {
            // There is no way to inject json, given the encoding of both arguments
            // as decimal and valid account id respectively.
            (
                nep141_account_id,
                format!(
                    r#"{{"receiver_id":"{}","amount":"{}"}}"#,
                    exit_params.receiver_account_id,
                    exit_params.amount.as_u128()
                ),
                "ft_transfer",
                None,
                events::ExitToNear::Legacy(ExitToNearLegacy {
                    sender: Address::new(erc20_address),
                    erc20_address: Address::new(erc20_address),
                    dest: exit_params.receiver_account_id.to_string(),
                    amount: exit_params.amount,
                }),
            )
        }
```
