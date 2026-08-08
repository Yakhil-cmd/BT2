This confirms the on-chain enforcement exists independently of the CLI. The `require_rent_exempt_split_destination` feature gate in `feature-set/src/lib.rs` documents that the stake program itself ("Require stake split destination account to be rent exempt") enforces rent-exemption of the split destination on-chain, independent of whatever `--rent-exempt-reserve-sol` value the CLI happens to use for its convenience pre-funding transfer. [1](#0-0) 

The `--rent-exempt-reserve-sol` flag and the `rent_exempt_reserve` parameter only affect `process_split_stake` in the CLI, which uses that value merely to construct an optional `system_instruction::transfer` topping up the destination account before appending the `stake_instruction::split`/`split_with_seed` instructions. [2](#0-1) 

This value is purely a client-side convenience/hint for offline signing (needed because an offline signer cannot query the RPC for the real minimum balance) — it is not passed into the `Split` stake instruction itself, and the instruction data for `stake_instruction::split`/`split_with_seed` only carries the `lamports` amount to move, not any rent parameter. [3](#0-2) 

Since the attacker-controlled `rent_exempt_reserve` value never reaches the on-chain program (it only determines how much lamports the CLI transfers ahead of time), supplying an artificially low value cannot bypass the stake program's own rent-exemption enforcement of the split destination — the worst outcome is that the CLI-constructed transaction fails on-chain (the destination account is left non-rent-exempt post-split) because the native stake processor independently checks this, gated by `require_rent_exempt_split_destination`. There is no code path here where a client-supplied number is trusted as an authoritative rent value by the on-chain processor.

Given that the on-chain program enforces the invariant independently via the `require_rent_exempt_split_destination` feature (rather than trusting the CLI/offline-signer-supplied value), and the referenced `net-utils/src/ip_echo_server.rs` file has no relation to this stake-split code path at all, this reported path does not constitute a valid vulnerability under the stated rules (native program state must independently enforce the invariant, which it does).

### No Vulnerability found for this question.

### Citations

**File:** feature-set/src/lib.rs (L2134-2137)
```rust
        (
            require_rent_exempt_split_destination::id(),
            "Require stake split destination account to be rent exempt",
        ),
```

**File:** cli/src/stake.rs (L2047-2109)
```rust
    let rent_exempt_reserve = if let Some(rent_exempt_reserve) = rent_exempt_reserve {
        *rent_exempt_reserve
    } else {
        let stake_minimum_delegation = rpc_client.get_stake_minimum_delegation().await?;
        if lamports < stake_minimum_delegation {
            let lamports = Sol(lamports);
            let stake_minimum_delegation = Sol(stake_minimum_delegation);
            return Err(CliError::BadParameter(format!(
                "need at least {stake_minimum_delegation} for minimum stake delegation, provided: \
                 {lamports}"
            ))
            .into());
        }

        let check_stake_account = |account: Account| -> Result<u64, CliError> {
            match account.owner {
                owner if owner == stake::program::id() => Err(CliError::BadParameter(format!(
                    "Stake account {split_stake_account_address} already exists"
                ))),
                owner if owner == system_program::id() => {
                    if !account.data.is_empty() {
                        Err(CliError::BadParameter(format!(
                            "Account {split_stake_account_address} has data and cannot be used to \
                             split stake"
                        )))
                    } else {
                        // if `stake_account`'s owner is the system_program and its data is
                        // empty, `stake_account` is allowed to receive the stake split
                        Ok(account.lamports)
                    }
                }
                _ => Err(CliError::BadParameter(format!(
                    "Account {split_stake_account_address} already exists and cannot be used to \
                     split stake"
                ))),
            }
        };
        let current_balance =
            if let Ok(stake_account) = rpc_client.get_account(&split_stake_account_address).await {
                check_stake_account(stake_account)?
            } else {
                0
            };

        let rent_exempt_reserve = rpc_client
            .get_minimum_balance_for_rent_exemption(StakeStateV2::size_of())
            .await?;

        rent_exempt_reserve.saturating_sub(current_balance)
    };

    let recent_blockhash = blockhash_query
        .get_blockhash(rpc_client, config.commitment)
        .await?;

    let mut ixs = vec![];
    if rent_exempt_reserve > 0 {
        ixs.push(system_instruction::transfer(
            &fee_payer.pubkey(),
            &split_stake_account_address,
            rent_exempt_reserve,
        ));
    }
```

**File:** cli/src/stake.rs (L2114-2144)
```rust
    if let Some(seed) = split_stake_account_seed {
        ixs.append(
            &mut stake_instruction::split_with_seed(
                stake_account_pubkey,
                &stake_authority.pubkey(),
                lamports,
                &split_stake_account_address,
                &split_stake_account.pubkey(),
                seed,
            )
            .with_memo(memo)
            .with_compute_unit_config(&ComputeUnitConfig {
                compute_unit_price,
                compute_unit_limit,
            }),
        )
    } else {
        ixs.append(
            &mut stake_instruction::split(
                stake_account_pubkey,
                &stake_authority.pubkey(),
                lamports,
                &split_stake_account_address,
            )
            .with_memo(memo)
            .with_compute_unit_config(&ComputeUnitConfig {
                compute_unit_price,
                compute_unit_limit,
            }),
        )
    };
```
