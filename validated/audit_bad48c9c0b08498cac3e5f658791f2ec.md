[1](#0-0)

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L110-120)
```text
(define-map protocol-bonds
    uint
    {
        ;; target yield rate (apy) in basis points
        target-rate: uint,
        ;; representation of STX:BTC price
        ;; this value is equal to "ustx per 100 sats", which
        ;; also translates to `(BTCUSD / STXUSD)`.
        ;; used to determine bond priority
        stx-value-ratio: uint,
        ;; minimum amount of STX that must be locked
```
