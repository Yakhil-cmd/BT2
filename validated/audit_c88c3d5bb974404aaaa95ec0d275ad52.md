### Title
Non-Deterministic ERC-20 Mirror Token Deployment via `CreateScheme::Legacy` Susceptible to NEAR Reorg - (`engine/src/engine.rs`)

---

### Summary

`deploy_erc20_token` in `engine/src/engine.rs` deploys ERC-20 mirror contracts for bridged NEP-141 tokens using the non-deterministic EVM `CREATE` opcode (`CreateScheme::Legacy`). The resulting address is a function of `(caller_evm_address, nonce)`. If a NEAR block reorg occurs before finality, the nonce at re-execution time may differ, causing the ERC-20 mirror to land at a different address. Users who already received ERC-20 tokens at the pre-reorg address permanently lose those tokens.

---

### Finding Description

`deploy_erc20_token` constructs an `Engine` whose origin is the EVM address derived from the NEAR predecessor account, then calls `deploy_code_with_input` with `address = None`: [1](#0-0) 

Inside `deploy_code`, `None` selects `CreateScheme::Legacy`: [2](#0-1) 

`CreateScheme::Legacy` is the EVM `CREATE` opcode — address is `keccak256(rlp([sender, nonce]))[12:]`. The nonce is the number of contracts previously deployed from that EVM address and is stored in Aurora's EVM state. The unit test explicitly confirms this scheme: [3](#0-2) 

After deployment, the address is written into the bidirectional NEP-141↔ERC-20 registry via `register_token`: [4](#0-3) 

The public entry points that reach this path are `deploy_erc20_token` (Legacy path, direct) and `deploy_erc20_token_callback` (WithMetadata path, via promise): [5](#0-4) [6](#0-5) 

`CreateScheme::Create2` is present in the codebase but is explicitly marked `unreachable!()` in the `deploy_code` dispatch, meaning it is never used for ERC-20 mirror deployment: [7](#0-6) 

---

### Impact Explanation

NEAR Protocol uses Nightshade consensus with doomslug finality. Blocks are considered final after two subsequent blocks (roughly 2 seconds), but before that window closes, short reorgs are possible. If a reorg reverts the block containing `deploy_erc20_token`:

1. The ERC-20 mirror was deployed at address **A** (derived from nonce **N**).
2. Any user who bridged NEP-141 tokens in the same or a subsequent pre-finality block received ERC-20 tokens credited to address **A** in Aurora's EVM state.
3. After the reorg, the re-executed `deploy_erc20_token` may use a different nonce **N′** (because other EVM state-changing transactions in the reverted block are also gone), producing address **B ≠ A**.
4. Address **A** no longer holds a deployed contract. The ERC-20 balances users held there are permanently inaccessible — **permanent fund freeze / loss of bridged assets**.

Impact: **Critical — permanent freezing of bridged user funds.**

---

### Likelihood Explanation

NEAR reorgs before finality are rare but documented. The window is short (~2 seconds / 2 blocks). The risk is elevated during periods of network instability or validator downtime. Because `deploy_erc20_token` is callable by any NEAR account (no access control beyond `require_running`), the deployment can happen at any time, including during a reorg-prone window. No attacker action is required beyond the reorg itself; the vulnerability is structural.

---

### Recommendation

Replace `CreateScheme::Legacy` with `CreateScheme::Create2` for ERC-20 mirror token deployment. The salt should be derived deterministically from the NEP-141 account ID (e.g., `keccak256(nep141_account_id_bytes)`), making the ERC-20 address independent of the deployer nonce and therefore stable across reorgs.

In `deploy_erc20_token` (`engine/src/engine.rs`), pass a deterministic address computed via `CREATE2` semantics instead of `None` to `deploy_code_with_input`, or extend `deploy_code` to accept a `CreateScheme::Create2` variant and route accordingly (removing the `unreachable!()` guard).

---

### Proof of Concept

1. NEAR account `alice.near` calls `deploy_erc20_token` for NEP-141 token `usdc.near`. The engine's EVM nonce for `near_account_to_evm_address("aurora")` is **N**. ERC-20 mirror is deployed at address **A = CREATE(aurora_evm_addr, N)**. The NEP-141↔ERC-20 registry records `usdc.near → A`.

2. In the same NEAR block, user `bob.near` bridges 1000 USDC via `ft_on_transfer`. Aurora mints 1000 ERC-20 tokens to Bob's EVM address at contract **A**.

3. A NEAR reorg reverts this block. Another transaction that incremented the EVM nonce (e.g., a different contract deployment) is also reverted, so the nonce is now **N′ ≠ N**.

4. The block is re-executed. `deploy_erc20_token` runs again, deploying at **B = CREATE(aurora_evm_addr, N′)**. The registry now records `usdc.near → B`.

5. Bob's 1000 ERC-20 tokens were at address **A**, which no longer exists. Bob's funds are permanently frozen. [8](#0-7) [2](#0-1)

### Citations

**File:** engine/src/engine.rs (L544-548)
```rust
        let scheme = address.map_or_else(
            || CreateScheme::Legacy {
                caller: origin.raw(),
            },
            |address| CreateScheme::Fixed(address.raw()),
```

**File:** engine/src/engine.rs (L563-563)
```rust
            CreateScheme::Create2 { .. } => unreachable!(),
```

**File:** engine/src/engine.rs (L1349-1367)
```rust
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
```

**File:** engine/src/engine.rs (L1370-1372)
```rust
    engine
        .register_token(address, nep141)
        .map_err(DeployErc20Error::Register)?;
```

**File:** engine/src/engine.rs (L2443-2448)
```rust
        let nonce = U256::zero();
        let expected_address = create_legacy_address(&origin, &nonce);
        let actual_address =
            deploy_erc20_token(nep141_token, None, io, &env, &mut handler).unwrap();

        assert_eq!(expected_address, actual_address);
```

**File:** engine/src/contract_methods/connector.rs (L124-130)
```rust
            DeployErc20TokenArgs::Legacy(nep141) => {
                let address = engine::deploy_erc20_token(nep141, None, io, env, handler)?;

                io.return_output(
                    &borsh::to_vec(address.as_bytes()).map_err(|_| errors::ERR_SERIALIZE)?,
                );
                Ok(PromiseOrValue::Value(address))
```

**File:** engine/src/contract_methods/connector.rs (L188-192)
```rust
        let address = engine::deploy_erc20_token(nep141, Some(erc20_metadata), io, env, handler)?;

        io.return_output(&borsh::to_vec(address.as_bytes()).map_err(|_| errors::ERR_SERIALIZE)?);
        Ok(address)
    })
```
