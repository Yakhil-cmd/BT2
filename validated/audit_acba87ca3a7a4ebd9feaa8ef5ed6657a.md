### Title
ERC-20 Tokens Permanently Burned Without Guaranteed Cross-Chain Transfer on Failed Exit - (`etc/eth-contracts/contracts/EvmErc20.sol`)

### Summary

`EvmErc20.withdrawToNear` and `EvmErc20.withdrawToEthereum` unconditionally burn the caller's ERC-20 tokens before invoking the exit precompile, and never check the precompile call's return value. When the subsequent NEAR-side promise (`ft_transfer` or `withdraw`) fails, the burned ERC-20 tokens are permanently destroyed with no recovery path, because the `error_refund` feature — the only mechanism that would re-mint them — is structurally incompatible with the calldata format used by `EvmErc20.sol`.

---

### Finding Description

**Step 1 — Burn-before-transfer with unchecked return value**

In `etc/eth-contracts/contracts/EvmErc20.sol`, both exit functions burn tokens first and then call the precompile via inline assembly, but the `res` value is declared and never used to revert:

```solidity
function withdrawToNear(bytes memory recipient, uint256 amount) external override {
    _burn(_msgSender(), amount);                          // tokens destroyed here
    bytes memory input = abi.encodePacked("\x01", amount_b, recipient);
    assembly {
        let res := call(gas(), 0xe9217bc70b7ed1f598ddd3199e80b093fa71124f, ...)
        // res is never checked — no revert on failure
    }
}
``` [1](#0-0) [2](#0-1) 

If the precompile call fails at the EVM level (e.g., out of gas, invalid input), the burn has already committed and the transaction does not revert.

**Step 2 — No refund callback in the default (production-compatible) build**

The `ExitToNear` precompile schedules a NEAR promise for `ft_transfer`. Whether a refund callback is attached depends on the `error_refund` compile-time feature:

```rust
let callback_args = ExitToNearPrecompileCallbackArgs {
    #[cfg(feature = "error_refund")]
    refund: refund_call_args(&exit_to_near_params, &exit_event),
    #[cfg(not(feature = "error_refund"))]
    refund: None,
    transfer_near: transfer_near_args,
};
``` [3](#0-2) 

For a regular ERC-20 exit (not wNEAR unwrap), `transfer_near` is also `None`, so `callback_args == default()` and only a bare `PromiseArgs::Create` is scheduled — no callback at all: [4](#0-3) 

**Step 3 — `error_refund` is not a default feature AND is structurally incompatible with `EvmErc20.sol`**

`error_refund` is absent from the `default` feature set in both crates: [5](#0-4) [6](#0-5) 

More critically, enabling `error_refund` changes the expected calldata layout: the precompile would parse bytes `[1..21]` as a 20-byte refund address before the amount. `EvmErc20.sol` encodes `[flag(1), amount(32), recipient(bytes)]` — no refund address slot. Enabling `error_refund` with the existing `EvmErc20.sol` would cause the precompile to misparse the amount as a refund address and corrupt the transfer, making the two components mutually exclusive. [7](#0-6) 

**Step 4 — `ExitToEthereum` has no callback mechanism at all**

The `ExitToEthereum` precompile always uses `PromiseArgs::Create` with no callback: [8](#0-7) 

If the ETH connector's `withdraw` promise fails, the burned ERC-20 tokens are permanently lost with no recovery path.

**Step 5 — The codebase itself documents this loss**

The test `test_exit_to_near_refund` explicitly confirms that without `error_refund`, burned tokens are not returned:

```rust
// If the refund feature is not enabled then there is no refund in the EVM
#[cfg(not(feature = "error_refund"))]
let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();
``` [9](#0-8) 

---

### Impact Explanation

**Permanent freezing of funds (Critical).** Any user who calls `withdrawToNear` with a recipient account not registered with the NEP-141 token (or any other condition that causes `ft_transfer` to fail on the NEAR side) will have their ERC-20 tokens burned with no recovery. The NEP-141 tokens remain locked in the Aurora engine contract. The same applies to `withdrawToEthereum` if the ETH connector's `withdraw` promise fails. There is no admin escape hatch, no retry mechanism, and no re-mint path in the default build.

---

### Likelihood Explanation

**High.** The failure condition (`ft_transfer` to an unregistered recipient) is a normal, user-triggerable scenario requiring no special privileges. Any EVM user holding bridged ERC-20 tokens can trigger this by calling `withdrawToNear` with a NEAR account that has not called `storage_deposit` on the NEP-141 contract. The codebase's own test (`test_exit_to_near_refund`) demonstrates this exact scenario as a known, reproducible path.

---

### Recommendation

1. In `EvmErc20.withdrawToNear` and `EvmErc20.withdrawToEthereum`, check the return value of the assembly `call` and revert if it returns 0:
   ```solidity
   assembly {
       let res := call(...)
       if iszero(res) { revert(0, 0) }
   }
   ```
   This ensures the burn is atomically rolled back if the precompile call fails at the EVM level.

2. For the NEAR-side promise failure path: update `EvmErc20.sol` to include the refund address in its calldata (matching the `error_refund` input format) and enable the `error_refund` feature in the production build. The `exit_to_near_precompile_callback` already contains the correct re-mint logic via `engine::refund_on_error`. [10](#0-9) 

---

### Proof of Concept

1. User holds 100 bridged ERC-20 tokens on Aurora (backed by 100 NEP-141 tokens held by the Aurora engine account).
2. User calls `erc20.withdrawToNear("unregistered.near", 100)`.
3. `_burn(msg.sender, 100)` executes — ERC-20 balance goes to 0.
4. The `ExitToNear` precompile schedules `ft_transfer` to `unregistered.near` on the NEP-141 contract.
5. `ft_transfer` fails because `unregistered.near` has no storage deposit.
6. No callback is scheduled (default build, `refund: None`, `transfer_near: None` → bare `PromiseArgs::Create`).
7. Result: 100 ERC-20 tokens are permanently burned; 100 NEP-141 tokens remain locked in the Aurora engine account forever. The user has lost their funds. [1](#0-0) [11](#0-10) [12](#0-11)

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

**File:** etc/eth-contracts/contracts/EvmErc20.sol (L65-76)
```text
    function withdrawToEthereum(address recipient, uint256 amount) external override {
        _burn(_msgSender(), amount);

        bytes32 amount_b = bytes32(amount);
        bytes20 recipient_b = bytes20(recipient);
        bytes memory input = abi.encodePacked("\x01", amount_b, recipient_b);
        uint input_size = 1 + 32 + 20;

        assembly {
            let res := call(gas(), 0xb0bd02f6a392af548bdf1cfaee5dfa0eefcc8eab, 0, add(input, 32), input_size, 0, 32)
        }
    }
```

**File:** engine-precompiles/src/native.rs (L449-483)
```rust
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
```

**File:** engine-precompiles/src/native.rs (L739-791)
```rust
        #[cfg(feature = "error_refund")]
        let (refund_address, input) = parse_input(input)?;
        #[cfg(not(feature = "error_refund"))]
        let input = parse_input(input)?;

        match flag {
            0x0 => {
                let Recipient {
                    receiver_account_id,
                    message,
                } = parse_recipient(input)?;

                Ok(Self::BaseToken(BaseTokenParams {
                    #[cfg(feature = "error_refund")]
                    refund_address,
                    receiver_account_id,
                    message,
                }))
            }
            0x1 => {
                let amount = parse_amount(&input[..32])?;
                let Recipient {
                    receiver_account_id,
                    message,
                } = parse_recipient(&input[32..])?;

                Ok(Self::Erc20TokenParams(Erc20TokenParams {
                    #[cfg(feature = "error_refund")]
                    refund_address,
                    receiver_account_id,
                    amount,
                    message,
                }))
            }
            _ => Err(ExitError::Other(Cow::from("ERR_INVALID_FLAG"))),
        }
    }
}

#[cfg(feature = "error_refund")]
fn parse_input(input: &[u8]) -> Result<(Address, &[u8]), ExitError> {
    validate_input_size(input, MIN_INPUT_SIZE, MAX_INPUT_SIZE)?;
    let mut buffer = [0; 20];
    buffer.copy_from_slice(&input[1..21]);
    let refund_address = Address::from_array(buffer);
    Ok((refund_address, &input[21..]))
}

#[cfg(not(feature = "error_refund"))]
fn parse_input(input: &[u8]) -> Result<&[u8], ExitError> {
    validate_input_size(input, MIN_INPUT_SIZE, MAX_INPUT_SIZE)?;
    Ok(&input[1..])
}
```

**File:** engine-precompiles/src/native.rs (L977-990)
```rust
        let withdraw_promise = PromiseCreateArgs {
            target_account_id: nep141_address,
            method: "withdraw".to_string(),
            args: serialized_args,
            attached_balance: Yocto::new(1),
            attached_gas: costs::WITHDRAWAL_GAS,
        };

        let promise = borsh::to_vec(&PromiseArgs::Create(withdraw_promise)).unwrap();
        let promise_log = Log {
            address: exit_to_ethereum::ADDRESS.raw(),
            topics: Vec::new(),
            data: promise,
        };
```

**File:** engine-precompiles/Cargo.toml (L34-39)
```text
[features]
default = ["std"]
std = ["aurora-engine-types/std", "aurora-engine-sdk/bls", "aurora-engine-sdk/std", "aurora-engine-modexp/std", "aurora-evm/std", "ethabi/std", "serde/std", "serde_json/std"]
contract = ["aurora-engine-sdk/contract", "aurora-engine-sdk/bls"]
log = []
error_refund = []
```

**File:** engine/Cargo.toml (L42-49)
```text
[features]
default = ["std"]
std = ["aurora-engine-types/std", "aurora-engine-hashchain/std", "aurora-engine-sdk/std", "aurora-engine-precompiles/std", "aurora-engine-transactions/std", "ethabi/std", "aurora-evm/std", "hex/std", "rlp/std", "serde/std", "serde_json/std"]
contract = ["log", "aurora-engine-sdk/contract", "aurora-engine-precompiles/contract"]
log = ["aurora-engine-sdk/log", "aurora-engine-precompiles/log"]
tracing = ["aurora-evm/tracing"]
error_refund = ["aurora-engine-precompiles/error_refund"]
integration-test = ["log"]
```

**File:** engine-tests/src/tests/erc20_connector.rs (L623-665)
```rust
    #[tokio::test]
    async fn test_exit_to_near_refund() {
        // Deploy Aurora; deploy NEP-141; bridge NEP-141 to ERC-20 on Aurora
        let TestExitToNearContext {
            ft_owner,
            ft_owner_address,
            nep_141,
            erc20,
            aurora,
            ..
        } = test_exit_to_near_common().await.unwrap();

        // Call exit on ERC-20; ft_transfer promise fails; expect refund on Aurora;
        exit_to_near(
            &ft_owner,
            // The ft_transfer will fail because this account is not registered with the NEP-141
            "unregistered.near",
            FT_EXIT_AMOUNT,
            &erc20,
            &aurora,
        )
        .await
        .unwrap();

        assert_eq!(
            nep_141_balance_of(&nep_141, &ft_owner.id()).await,
            FT_TOTAL_SUPPLY - FT_TRANSFER_AMOUNT
        );
        assert_eq!(
            nep_141_balance_of(&nep_141, &aurora.id()).await,
            FT_TRANSFER_AMOUNT
        );

        #[cfg(feature = "error_refund")]
        let balance = FT_TRANSFER_AMOUNT.into();
        // If the refund feature is not enabled then there is no refund in the EVM
        #[cfg(not(feature = "error_refund"))]
        let balance = (FT_TRANSFER_AMOUNT - FT_EXIT_AMOUNT).into();

        assert_eq!(
            erc20_balance(&erc20, ft_owner_address, &aurora).await,
            balance
        );
```

**File:** engine/src/contract_methods/connector.rs (L231-242)
```rust
        } else if let Some(args) = args.refund {
            // Exit call failed; need to refund tokens
            let refund_result = engine::refund_on_error(io, env, state, &args, handler)?;

            if !refund_result.status.is_ok() {
                return Err(errors::ERR_REFUND_FAILURE.into());
            }

            Some(refund_result)
        } else {
            None
        };
```
