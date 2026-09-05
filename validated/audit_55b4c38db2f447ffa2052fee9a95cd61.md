[1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L363-366)
```text
(define-data-var pox-reward-cycle-length uint (if is-in-mainnet
    u2100
    u1050
))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L375-387)
```text
;; The last accounted balance of rewards. Used to keep
;; track of which sBTC is just for rewards, vs from
;; staking.
(define-data-var last-accounted-rewards-only uint u0)

;; The last burn height in which rewards were calculated
(define-data-var last-reward-compute-height uint u0)

;; the amount of sBTC claimable by the reserve
(define-data-var reserve-balance uint u0)

;; The total amount of sBTC staked
(define-data-var total-sbtc-staked uint u0)
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2924-2942)
```text
;; At a given burn height, what distribution cycle are we in?
;; This is zero-indexed at the first reward-cycle
(define-read-only (burn-height-to-distribution-index (height uint))
    (/ (- height (var-get first-burnchain-block-height))
        (/ (var-get pox-reward-cycle-length) u2)
    )
)

;; What's the current distribution cycle?
(define-read-only (current-distribution-cycle)
    (burn-height-to-distribution-index burn-block-height)
)

;; The start burn height of a given distribution cycle
(define-read-only (distribution-cycle-to-burn-height (cycle uint))
    (+ (var-get first-burnchain-block-height)
        (* cycle (/ (var-get pox-reward-cycle-length) u2))
    )
)
```
