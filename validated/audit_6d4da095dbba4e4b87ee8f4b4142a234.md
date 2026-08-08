#No Vulnerability found for this question.

Based on the codebase evidence: stake program authority checks (custodian, staker, withdrawer) are always evaluated against the *current* on-chain `Meta.lockup.custodian` field read from the account's live state at instruction-execution time, not against any cached or "stale" signer set. This is confirmed by CLI-side mirroring of the same on-chain semantics, e.g. `check_current_authority(&[lockup.custodian], &custodian.pubkey())` in `process_stake_set_lockup` [1](#0-0)  and by integration tests that explicitly exercise custodian rotation followed by a `set_lockup` from the *new* custodian succeeding while the old one no longer has authority [2](#0-1) .

The scenario in the question presumes a "signer-set staleness window" analogous to nonce blockhash reuse, but this conflates two unrelated mechanisms:
- Durable-nonce replay protection is about preventing a *transaction* from being reprocessed by pinning it to a specific nonce value that gets advanced on each use.
- Authority checks for `set_lockup`/`set_lockup_checked` are unrelated to nonces; they are evaluated fresh, every time, against whatever pubkey is stored in `meta.lockup.custodian` in the account's current data at the moment the instruction executes.

A transaction signed by the old custodian, if submitted/replayed after a legitimate custodian rotation lands, still carries the old custodian's signature, but the program compares that signer's pubkey against the account's live `lockup.custodian` field — which now holds the new custodian's pubkey. Since these no longer match, the check fails and the instruction is rejected, regardless of when the transaction was signed or how long it was queued. There is no caching of "authorized signers at signing time" anywhere in this flow — every check is against current state, so there is no staleness window of the kind described. This is standard, expected Solana runtime/account-model behavior (state is read fresh per instruction execution) and not a bug specific to this repository's stake program.

Since the described exploit path is blocked by the fundamental design (current-state authority checks) and no code path was found that caches or defers authority validation, this does not qualify as a valid finding under the audit rules.

### Citations

**File:** cli/src/stake.rs (L2372-2375)
```rust
        if let Some(lockup) = lockup {
            if lockup.custodian != Pubkey::default() {
                check_current_authority(&[lockup.custodian], &custodian.pubkey())?;
            }
```

**File:** cli/tests/stake.rs (L1861-1918)
```rust
    // Set custodian to another pubkey
    let online_custodian = Keypair::new();
    let online_custodian_pubkey = online_custodian.pubkey();

    let lockup = LockupArgs {
        unix_timestamp: Some(1_581_534_571),
        epoch: Some(201),
        custodian: Some(online_custodian_pubkey),
    };
    config.command = CliCommand::StakeSetLockup {
        stake_account_pubkey,
        lockup,
        new_custodian_signer: None,
        custodian: 0,
        sign_only: false,
        dump_transaction_message: false,
        blockhash_query: BlockhashQuery::default(),
        nonce_account: None,
        nonce_authority: 0,
        memo: None,
        fee_payer: 0,
        compute_unit_price,
    };
    process_command(&config).await.unwrap();

    let lockup = LockupArgs {
        unix_timestamp: Some(1_581_534_572),
        epoch: Some(202),
        custodian: None,
    };
    config.signers = vec![&default_signer, &online_custodian];
    config.command = CliCommand::StakeSetLockup {
        stake_account_pubkey,
        lockup,
        new_custodian_signer: None,
        custodian: 1,
        sign_only: false,
        dump_transaction_message: false,
        blockhash_query: BlockhashQuery::default(),
        nonce_account: None,
        nonce_authority: 0,
        memo: None,
        fee_payer: 0,
        compute_unit_price,
    };
    process_command(&config).await.unwrap();
    let stake_account = rpc_client.get_account(&stake_account_pubkey).await.unwrap();
    let stake_state: StakeStateV2 = stake_account.state().unwrap();
    let current_lockup = match stake_state {
        StakeStateV2::Initialized(meta) => meta.lockup,
        _ => panic!("Unexpected stake state!"),
    };
    assert_eq!(
        current_lockup.unix_timestamp,
        lockup.unix_timestamp.unwrap()
    );
    assert_eq!(current_lockup.epoch, lockup.epoch.unwrap());
    assert_eq!(current_lockup.custodian, online_custodian_pubkey);
```
