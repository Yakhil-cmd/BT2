# Q0629: pox_lock_extend_v4: sip-031 claim computes claimable beyond vested+received

## Question
Can an unprivileged attacker reach `pox_lock_extend_v4` (in `pox-locking/src/pox_4.rs`) via a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts, such that `calc-claimable-amount` over-credits vesting or per-tenure mints, breaking the invariant that claimable == vested + received - already-claimed — leading to draining the SIP-031 reserve?

## Target
- File/function: `pox-locking/src/pox_4.rs` -> `pox_lock_extend_v4`
- Entrypoint: a pox-5 `contract-call?` (stake / register-for-bond / unstake / unstake-sbtc / stake-update / claim-rewards) or a burnchain stacking op the attacker crafts
- Attacker controls: every call argument, the attacker-deployed signer-manager contract, the L1 Bitcoin lockup proof, the sBTC amount, and the ordering of their own transactions
- Exploit idea: `calc-claimable-amount` over-credits vesting or per-tenure mints
- Invariant to test: claimable == vested + received - already-claimed
- Expected Immunefi impact: Critical - draining the SIP-031 reserve
- Fast validation: test a claim asserting claimable formula
