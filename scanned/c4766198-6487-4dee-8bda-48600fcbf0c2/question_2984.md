# Q2984: L1 total-supply message ordering and spoofing

## Question
Can an unprivileged attacker exploit `L1 handler update_total_supply(from_address, total_supply)` with the same message replayed after the state already advanced and thereby push `total_supply` used by `yearly_mint` to an unintended value, so that a validator with both STRK and BTC-wrapper delegation receives inflated or suppressed rewards through the minting curve?

## Target
- File/function: src/minting_curve/minting_curve.cairo::update_total_supply
- Entrypoint: L1 handler update_total_supply(from_address, total_supply)
- Attacker controls: L1 message ordering, replay, delay, chosen total_supply payload if sender checks can be bypassed
- Exploit idea: Stress sender validation, replay resistance, and monotonicity assumptions around the L1 handler, then propagate the resulting supply value into the next reward calculation.
- Invariant to test: Only authentic, monotonic total-supply updates from the designated L1 reward supplier should influence the minting curve.
- Expected Immunefi impact: Critical - Protocol insolvency
- Fast validation: Construct ordered, delayed, and replayed message sequences in tests, then compare the observed yearly mint and downstream reward amounts against the expected monotonic supply.
