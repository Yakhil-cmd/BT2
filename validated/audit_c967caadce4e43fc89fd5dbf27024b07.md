[1](#0-0) [2](#0-1)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L54-56)
```text
;; The same Bitcoin outpoint (txid + output-index) appeared twice in
;; the L1 lockup proof list submitted to `register-for-bond`.
(define-constant ERR_DUPLICATE_LOCKUP_OUTPOINT (err u46))
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L68-69)
```text
;; The L1 lockup unlock height is lower than this bond's minimum unlock height
(define-constant ERR_INVALID_UNLOCK_HEIGHT (err u52))
```
