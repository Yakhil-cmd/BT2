### Title
`MintingCurve.total_supply` Cannot Decrease After L1 Burns, Permanently Inflating Yearly Mint — (File: `src/minting_curve/minting_curve.cairo`)

---

### Summary

The `update_total_supply` L1 handler in `MintingCurve` contains a strict monotonicity guard: it silently discards any L1→L2 message where the reported total supply is not strictly greater than the currently stored value. If STRK tokens are burned on L1 — reducing the L1 total supply below the stored L2 value — the L2 `MintingCurve.total_supply` is permanently stuck at the pre-burn figure. Because the minting formula is `yearly_mint = C × √(total_stake × total_supply)`, a permanently overestimated `total_supply` causes