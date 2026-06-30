### Title
Divergent `withdrawToNear` Calldata Formats Between `EvmErc20` and `EvmErc20V2` Cause Permanent Fund Freeze on Engine Feature-Flag Upgrade — (File: `etc/eth-contracts/contracts/EvmErc20.sol`, `etc/eth-contracts/contracts/EvmErc20V2.sol`, `engine-precompiles/src/native.rs`, `engine/src/engine.rs`)

---

### Summary

Two separate, nearly-identical ERC-20 bridge contract implementations (`EvmErc20.sol` and `EvmErc20V2.sol`) encode the `withdrawToNear` precompile calldata in incompatible formats. The `ExitToNear` precompile's parser is conditioned on the `error_refund` compile-time feature flag, which also controls which bytecode is deployed for new ERC-20 tokens. Because there is no on-chain upgrade mechanism for already-deployed ERC-20 bridge contracts, toggling the `error_refund` feature in an engine upgrade permanently misaligns the calldata format that existing contracts produce against what the upgraded precompile expects. Any user who subsequently calls `withdrawToNear` on a pre-upgrade ERC-20 contract will have their tokens burned with the NEAR-side transfer either failing or crediting a wildly wrong amount, with any refund directed to the zero address — a permanent fund freeze.

---

### Finding Description

**Two divergent implementations of the same contract:**

`EvmErc20.sol` `withdrawToNear` encodes:
```
\x01 | amount (32 bytes) | recipient (variable)
``` [1](#0-0) 

`EvmErc20V2.sol` `withdrawToNear` encodes:
```
\x01 | sender (20 bytes) | amount (32 bytes) | recipient (variable)
``` [2](#0-1) 

**The precompile parser is compile-time conditioned on the same flag:**

```rust
#[cfg(not(feature = "error_refund"))]
const MIN_INPUT_SIZE: usize = 3;
#[cfg(feature = "error_refund")]
const MIN_INPUT_SIZE: usize = 21;   // 1 flag + 20 refund_address
``` [3](#0-2) 

With `error_refund` enabled the parser reads bytes `[1..21]` as a `refund_address` before reading the 32-byte amount. Without it, bytes `[1..33]` are read directly as the amount.

**The deployed bytecode is also compile-time conditioned on the same flag:**

```rust
#[cfg(feature = "error_refund")]
let erc20_contract = include_bytes!("../../etc/eth-contracts/res/EvmErc20V2.bin");
#[cfg(not(feature = "error_refund"))]
let erc20_contract = include_bytes!("../../etc/eth-contracts/res/EvmErc20.bin");
``` [4](#0-3) 

**There is no upgrade path for already-deployed ERC-20 contracts.** The `factory_update_address_version` mechanism exists only for XCC router sub-accounts, not for ERC-20 bridge contracts. [5](#0-4) 

**Mismatch scenario — V1 contract calls V2 precompile (engine upgraded to add `error_refund`):**

| Byte range | V1 contract sends | V2 precompile reads as |
|---|---|---|
| `[0]` | `\x01` (flag) | flag ✓ |
| `[1..21]` | first 20 bytes of `amount` | `refund_address` ✗ |
| `[21..53]` | last 12 bytes of `amount` + first 20 bytes of `recipient` | `amount` ✗ |
| `[53..]` | rest of `recipient` | `recipient` ✗ |

For a typical small amount (e.g., 1000 tokens), the first 20 bytes of the 32-byte big-endian amount are all zeros, so `refund_address` becomes `address(0)`. The parsed `amount` becomes an astronomically large number (recipient bytes interpreted as high-order amount bytes), causing the NEAR `ft_transfer` to fail because Aurora does not hold that balance. With `error_refund` enabled, the failed transfer triggers a refund — but to `address(0)`, not the user. The ERC-20 tokens are already burned. Funds are permanently frozen.

The symmetric mismatch (V2 contract + V1 precompile, engine downgraded) produces the same class of error: the 20-byte sender field is consumed as the high-order bytes of the amount, producing a nonsensical value.

---

### Impact Explanation

**Permanent freezing of funds.** A user calls `withdrawToNear` on a pre-upgrade ERC-20 bridge contract. The contract burns the user's ERC-20 tokens and calls the `ExitToNear` precompile with V1-format calldata. The upgraded precompile misparsed the calldata, constructs a NEAR `ft_transfer` for a wrong (astronomically large) amount, which fails. The `error_refund` callback fires but credits `address(0)`. The user's ERC-20 tokens are gone and no NEP-141 tokens arrive. There is no recovery path.

---

### Likelihood Explanation

The trigger is an Aurora Engine upgrade that toggles the `error_refund` compile-time feature. This is a realistic maintenance event — the feature exists precisely because it was added after initial deployment. Once the upgrade occurs, every holder of a pre-upgrade ERC-20 bridge token who attempts `withdrawToNear` is affected. No special attacker capability is required beyond being a normal token holder.

---

### Recommendation

1. **Version-stamp deployed ERC-20 contracts** in engine storage and have the `ExitToNear` precompile look up the version of the calling contract to select the correct parsing branch, rather than relying on a single compile-time flag.
2. **Provide an on-chain migration path** (analogous to `factory_update_address_version` for XCC routers) that re-deploys existing ERC-20 bridge contracts to the current bytecode version before activating the new precompile parsing logic.
3. **Consolidate the two implementations** into a single contract with a backward-compatible calldata layout so the parser never needs to branch on a compile-time flag.

---

### Proof of Concept

1. Compile and deploy the Aurora Engine **without** `error_refund`. All ERC-20 tokens deployed at this stage use `EvmErc20` (V1) bytecode.
2. Bridge a NEP-141 token: call `deploy_erc20_token` → `ft_transfer_call` → `ft_on_transfer` → `receive_erc20_tokens` mints ERC-20 tokens to a user address. [6](#0-5) 
3. Upgrade the engine binary **with** `error_refund` enabled. The `ExitToNear` precompile now expects `\x01 | refund_address(20) | amount(32) | recipient`. The already-deployed ERC-20 contract bytecode is unchanged.
4. User calls `withdrawToNear(recipient, amount)` on the V1 ERC-20 contract. The contract executes `_burn` (tokens destroyed) then calls the precompile with `\x01 | amount(32) | recipient`. [1](#0-0) 
5. The precompile reads bytes `[1..21]` (first 20 bytes of the 32-byte amount) as `refund_address` = `address(0)` for any amount < 2^160. It reads bytes `[21..53]` as the transfer amount — a value that includes recipient ASCII bytes in the high-order positions, producing a number far exceeding Aurora's NEP-141 balance. [7](#0-6) 
6. The NEAR `ft_transfer` fails. The `exit_to_near_precompile_callback` fires, detects failure, and calls `refund_on_error` targeting `address(0)`. [8](#0-7) 
7. User's ERC-20 tokens are permanently destroyed. No NEP-141 tokens are received. No refund reaches the user.

### Citations

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L53-63)
```text
    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        _burn(_msgSender(), amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
        uint input_size = 1 + 32 + recipient.length;

        assembly {
            let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        }
    }
```

**File:** etc/eth-contracts/contracts/EvmErc20V2.sol (L53-64)
```text
    function withdrawToNear(bytes memory recipient, uint256 amount) external override {
        address sender = _msgSender();
        _burn(sender, amount);

        bytes32 amount_b = bytes32(amount);
        bytes memory input = abi.encodePacked("\x01", sender, amount_b, recipient);
        uint input_size = 1 + 20 + 32 + recipient.length;

        assembly {
            let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, 0, add(input, 32), input_size, 0, 32)
        }
    }
```

**File:** engine-precompiles/src/native.rs (L36-40)
```rust
#[cfg(not(feature = "error_refund"))]
const MIN_INPUT_SIZE: usize = 3;
#[cfg(feature = "error_refund")]
const MIN_INPUT_SIZE: usize = 21;
const MAX_INPUT_SIZE: usize = 1_024;
```

**File:** engine-precompiles/src/native.rs (L386-501)
```rust
    #[allow(clippy::too_many_lines)]
    fn run(
        &self,
        input: &[u8],
        target_gas: Option<EthGas>,
        context: &Context,
        is_static: bool,
    ) -> EvmPrecompileResult {
        // ETH (base) transfer input format: (85 bytes)
        //  - flag (1 byte)
        //  - refund_address (20 bytes), present if the feature "error_refund" is enabled
        //  - recipient_account_id (max MAX_INPUT_SIZE - 20 - 1 bytes)
        // ERC-20 transfer input format: (124 bytes)
        //  - flag (1 byte)
        //  - refund_address (20 bytes), present if the feature "error_refund" is enabled.
        //  - amount (32 bytes)
        //  - recipient_account_id (max MAX_INPUT_SIZE - 1 - (20) - 32 bytes)
        //  - `:unwrap` suffix in a case of wNEAR (7 bytes)
        let required_gas = Self::required_gas(input)?;

        if let Some(target_gas) = target_gas
            && required_gas > target_gas
        {
            return Err(ExitError::OutOfGas);
        }

        // It's not allowed to call exit precompiles in static mode
        if is_static {
            return Err(ExitError::Other(Cow::from("ERR_INVALID_IN_STATIC")));
        } else if context.address != exit_to_near::ADDRESS.raw() {
            return Err(ExitError::Other(Cow::from("ERR_INVALID_IN_DELEGATE")));
        }

        let exit_to_near_params = ExitToNearParams::try_from(input)?;

        let (nep141_address, args, exit_event, method, transfer_near_args) =
            match exit_to_near_params {
                // ETH(base) token transfer
                //
                // Input slice format:
                //  recipient_account_id (bytes) - the NEAR recipient account which will receive
                //  NEP-141 (base) tokens, or also can contain the `:unwrap` suffix in case of
                //  withdrawing wNEAR, or another message of JSON in case of OMNI, or address of
                //  receiver in case of transfer tokens to another engine contract.
                ExitToNearParams::BaseToken(ref exit_params) => {
                    let eth_connector_account_id = self.get_eth_connector_contract_account()?;
                    exit_base_token_to_near(eth_connector_account_id, context, exit_params)?
                }
                // ERC-20 token transfer
                //
                // This precompile branch is expected to be called from the ERC-20 burn function.
                //
                // Input slice format:
                //  amount (U256 big-endian bytes) - the amount that was burned
                //  recipient_account_id (bytes) - the NEAR recipient account which will receive
                //  NEP-141 tokens, or also can contain the `:unwrap` suffix in case of withdrawing
                //  wNEAR, or another message of JSON in case of OMNI, or address of receiver in case
                //  of transfer tokens to another engine contract.
                ExitToNearParams::Erc20TokenParams(ref exit_params) => {
                    exit_erc20_token_to_near(context, exit_params, &self.io)?
                }
            };

        let callback_args = ExitToNearPrecompileCallbackArgs {
            #[cfg(feature = "error_refund")]
            refund: refund_call_args(&exit_to_near_params, &exit_event),
            #[cfg(not(feature = "error_refund"))]
            refund: None,
            transfer_near: transfer_near_args,
        };
        let attached_gas = if method == "ft_transfer_call" {
            costs::FT_TRANSFER_CALL_GAS
        } else {
            costs::FT_TRANSFER_GAS
        };

        let transfer_promise = PromiseCreateArgs {
            target_account_id: nep141_address,
            method,
            args: args.into_bytes(),
            attached_balance: Yocto::new(1),
            attached_gas,
        };

        let promise = if callback_args == ExitToNearPrecompileCallbackArgs::default() {
            PromiseArgs::Create(transfer_promise)
        } else {
            PromiseArgs::Callback(PromiseWithCallbackArgs {
                base: transfer_promise,
                callback: PromiseCreateArgs {
                    target_account_id: self.current_account_id.clone(),
                    method: "exit_to_near_precompile_callback".to_string(),
                    args: borsh::to_vec(&callback_args).unwrap(),
                    attached_balance: Yocto::new(0),
                    attached_gas: costs::EXIT_TO_NEAR_CALLBACK_GAS,
                },
            })
        };
        let promise_log = Log {
            address: exit_to_near::ADDRESS.raw(),
            topics: Vec::new(),
            data: borsh::to_vec(&promise).unwrap(),
        };
        let ethabi::RawLog { topics, data } = exit_event.encode();
        let exit_event_log = Log {
            address: exit_to_near::ADDRESS.raw(),
            topics: topics.into_iter().map(|h| H256::from(h.0)).collect(),
            data,
        };

        Ok(PrecompileOutput {
            logs: vec![promise_log, exit_event_log],
            cost: required_gas,
            output: Vec::new(),
        })
    }
```

**File:** engine/src/engine.rs (L796-843)
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
```

**File:** engine/src/engine.rs (L1321-1324)
```rust
    #[cfg(feature = "error_refund")]
    let erc20_contract = include_bytes!("../../etc/eth-contracts/res/EvmErc20V2.bin");
    #[cfg(not(feature = "error_refund"))]
    let erc20_contract = include_bytes!("../../etc/eth-contracts/res/EvmErc20.bin");
```

**File:** engine/src/contract_methods/xcc.rs (L81-99)
```rust
pub fn factory_update_address_version<I: IO + Copy, E: Env, H: PromiseHandler>(
    io: I,
    env: &E,
    handler: &H,
) -> Result<(), ContractError> {
    with_hashchain(io, env, function_name!(), |mut io| {
        require_running(&state::get_state(&io)?)?;
        // The function is only set to be private, otherwise callback error will happen.
        env.assert_private_call()?;
        let check_deploy: Result<(), &[u8]> = match handler.promise_result_check() {
            Some(true) => Ok(()),
            Some(false) => Err(b"ERR_ROUTER_DEPLOY_FAILED"),
            None => Err(b"ERR_ROUTER_UPDATE_NOT_CALLBACK"),
        };
        check_deploy?;
        let args: xcc::AddressVersionUpdateArgs = io.read_input_borsh()?;
        xcc::set_code_version_of_address(&mut io, &args.address, args.version);
        Ok(())
    })
```

**File:** engine/src/contract_methods/connector.rs (L231-239)
```rust
        } else if let Some(args) = args.refund {
            // Exit call failed; need to refund tokens
            let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;

            if !refund_result.status.is_ok() {
                return Err(errors::ERR_REFUND_FAILURE.into());
            }

            Some(refund_result)
```
