[1](#0-0)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L247-333)
```text
;; State to track the per-share rewards earned for bond periods
;; and reward cycles. This value must only increment
(define-map rewards-per-token-for-cycle
    {
        reward-cycle: uint,
        bond-index: (optional uint),
    }
    uint
)

;; Total shares (either ustx or sats) staked in a given
;; bond or stx-only cycle
(define-map total-shares-staked-for-cycle
    {
        reward-cycle: uint,
        bond-index: (optional uint),
    }
    uint
)

;; State to track the per-staker shares for a given signer.
(define-map staker-shares-staked-for-cycle
    {
        reward-cycle: uint,
        bond-index: (optional uint),
        staker: principal,
        signer: principal,
    }
    uint
)

;; Amount of shares staked for a given signer in a given cycle.
;; This is strictly for reward calculations -
;; i.e. when is-bond is false, only the STX from STX-only staking
;; is accounted for here, not the STX from bonds.
(define-map signer-shares-staked-for-cycle
    {
        reward-cycle: uint,
        bond-index: (optional uint),
        signer: principal,
    }
    uint
)

;; Represents a snapshot of `rewards-per-token` at the last
;; time of rewards settlement for this specific signer
(define-map signer-rewards-per-token-settled-for-cycle
    {
        reward-cycle: uint,
        bond-index: (optional uint),
        signer: principal,
    }
    uint
)

;; Represents pending, but unclaimed rewards for a signer
(define-map signer-unclaimed-rewards-for-cycle
    {
        reward-cycle: uint,
        bond-index: (optional uint),
        signer: principal,
    }
    uint
)

;; Represents a snapshot of `rewards-per-token` at the last
;; time of rewards settlement for this specific staker
(define-map staker-rewards-per-token-settled-for-cycle
    {
        reward-cycle: uint,
        bond-index: (optional uint),
        signer: principal,
        staker: principal,
    }
    uint
)

;; Represents pending, but unclaimed rewards for a staker
(define-map staker-unclaimed-rewards-for-cycle
    {
        reward-cycle: uint,
        bond-index: (optional uint),
        signer: principal,
        staker: principal,
    }
    uint
)
```
