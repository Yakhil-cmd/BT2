[1](#0-0) [2](#0-1)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/mod.rs (L1-1)
```rust
// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L1-60)
```text
(define-constant ERR_UNAUTHORIZED (err u1))
(define-constant ERR_CANNOT_SETUP_BOND_TOO_SOON (err u2))
(define-constant ERR_CANNOT_SETUP_BOND_TOO_LATE (err u3))
(define-constant ERR_BOND_ALREADY_SETUP (err u4))
(define-constant ERR_STAKER_ALREADY_ADDED (err u5))
(define-constant ERR_BOND_NOT_FOUND (err u7))
(define-constant ERR_INSUFFICIENT_STX (err u8))
(define-constant ERR_ALREADY_REGISTERED (err u9))
(define-constant ERR_TOO_MUCH_SATS (err u10))
(define-constant ERR_NOT_ALLOWLISTED (err u11))
(define-constant ERR_SIGNER_KEY_GRANT_USED (err u12))
(define-constant ERR_INVALID_SIGNATURE_RECOVER (err u13))
(define-constant ERR_INVALID_SIGNATURE_PUBKEY (err u14))
(define-constant ERR_SIGNER_KEY_GRANT_NOT_FOUND (err u17))
(define-constant ERR_ALREADY_STAKED (err u19))
(define-constant ERR_INVALID_NUM_CYCLES (err u20))
(define-constant ERR_SIGNER_NOT_FOUND (err u23))
(define-constant ERR_INVALID_START_BURN_HEIGHT (err u24))
(define-constant ERR_UNAUTHORIZED_SIGNER_REGISTRATION (err u26))
(define-constant ERR_NOT_STAKING (err u27))
(define-constant ERR_UNSTAKE_IN_PREPARE_PHASE (err u28))
;; Trying to pay out to bonds in an invalid order
(define-constant ERR_INVALID_BOND_PERIOD_ORDERING (err u29))
;; We already calculated at the start of this cycle
(define-constant ERR_DISTRIBUTION_ALREADY_COMPUTED (err u30))
(define-constant ERR_BOND_NOT_ACTIVE (err u31))
(define-constant ERR_NO_CLAIMABLE_REWARDS (err u32))
(define-constant ERR_ACTIVE_BOND_NOT_INCLUDED (err u33))
;; Not actively in a bond
(define-constant ERR_NOT_BOND_PARTICIPANT (err u34))
;; A call to announce an early unlock was made
;; for a bond membership that has an L2 lockup
(define-constant ERR_CANNOT_ANNOUNCE_L1_EARLY_UNLOCK (err u35))
;; The argument provided does not match the staker's signer
(define-constant ERR_INVALID_OLD_SIGNER_MANAGER (err u36))
;; The amount of sats provided to unstake is invalid
(define-constant ERR_INVALID_UNSTAKE_SBTC_AMOUNT (err u37))
;; The bond participant did not stake sBTC
(define-constant ERR_CANNOT_UNSTAKE_SBTC (err u38))
;; A parse error occurred when reading a Bitcoin header
(define-constant ERR_READ_TX_OUT_OF_BOUNDS (err u39))
;; An incorrect Bitcoin header was provided as part of a lockup proof
(define-constant ERR_INVALID_BTC_HEADER (err u40))
;; An incorrect merkle proof was provided as part of a lockup proof
(define-constant ERR_INVALID_MERKLE_PROOF (err u41))
;; The output script provided is incorrect
(define-constant ERR_INVALID_LOCKUP_SCRIPT (err u42))
;; A staker tried to register for a bond after it already started
(define-constant ERR_BOND_ALREADY_STARTED (err u43))
;; Cannot call `update-bond-registration` with the same signer
(define-constant ERR_UPDATE_BOND_SAME_SIGNER (err u44))
;; The lockup amount does not match the specified amount of sats
(define-constant ERR_INVALID_LOCKUP_AMOUNT (err u45))
;; The same Bitcoin outpoint (txid + output-index) appeared twice in
;; the L1 lockup proof list submitted to `register-for-bond`.
(define-constant ERR_DUPLICATE_LOCKUP_OUTPOINT (err u46))
;; A staker tried to modify the next reward cycle's state during the prepare
;; phase.
(define-constant ERR_STAKE_IN_PREPARE_PHASE (err u47))
;; A staker tried to rollover a bond too early
```
