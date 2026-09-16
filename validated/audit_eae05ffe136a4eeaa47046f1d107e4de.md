### Title
Unbounded `count_coins` × `denomination` multiplication in asset cap validation causes silent floating-point overflow, corrupting the declared asset `cap` - ([File: validation.js])

### Summary
`validateAssetDefinition()` computes the declared cap of a fixed-denomination asset by summing `count_coins * denomination` across all denominations, but `count_coins` has no upper bound check (only `isPositiveInteger`), unlike `denomination`, which is capped at `constants.MAX_CAP`. Because JavaScript performs this arithmetic as IEEE-754 double-precision floats (53-bit safe-integer range, ~9.007×10^15), an attacker who posts an `asset` definition message can choose a `count_coins` value large enough that the product (or the running sum) silently exceeds `Number.MAX_SAFE_INTEGER`, losing precision. This is the exact bug class described in the Phoenix report: a multiplication of quantities without imposing an upper bound on one factor, causing the numeric type used for accounting to silently misrepresent the true value.

### Finding Description
In `validateAssetDefinition`, denomination entries are validated as: [1](#0-0) 

`denomInfo.denomination` is bounded by `constants.MAX_CAP`: [2](#0-1) 

but `denomInfo.count_coins` is only checked with `isPositiveInteger`, which permits any positive integer up to `Number.MAX_SAFE_INTEGER` with **no cap relative to `MAX_CAP` or to keep the product safe**: [3](#0-2) [4](#0-3) 

The computed `total_cap_from_denominations` is later required to equal the declared `payload.cap`: [5](#0-4) 

Because both the validation-time computation and any later reproduction of that arithmetic use plain JS number multiplication/addition (not arbitrary-precision `Decimal`), a sufficiently large `count_coins` for any denomination causes `denomInfo.count_coins * denomInfo.denomination` (or its accumulation into `total_cap_from_denominations`) to silently round to the nearest representable double once it exceeds 2^53, rather than throwing or being rejected. This lets an attacker craft a `denominations` array whose *declared* `cap` does not match the mathematically true sum of `count_coins × denomination`, yet still passes validation because the corrupted (rounded) computed sum happens to equal the attacker-chosen `cap`.

This directly parallels the reported Phoenix issue: `adjusted_quote_lot_budget` is the product of several factors stored in a fixed-width type (`u64`) with no explicit bound on the individual multiplicands, allowing the true value to exceed what the type can represent. Here the "type" is JS's float64 safe-integer range, and the missing bound is on `count_coins`.

### Impact Explanation
`payload.cap` is a value trusted throughout the system — it is exposed to oscript/AA logic via the `asset[...].cap` getter (confirmed in `test/formula.test.js`), used by AAs to reason about total/maximum asset supply (e.g., proportional payout formulas, market-maker contracts). If the validated `cap` does not correspond to the true achievable sum of `count_coins × denomination` per denomination (due to silent float precision loss), any AA or user logic that relies on `asset[...].cap` as an authoritative maximum supply can be deceived, leading to miscalculated payouts, incorrect share/ratio computations in AA-held funds, or AA fund loss/freezing when the assumptions used to size withdrawal/exchange amounts (as seen in `uniswap_like_market_maker.oscript` and `order_book_exchange.oscript`, which reason over asset balances/caps) no longer hold. This qualifies as an impact within the accepted categories (AA fund loss/miscalculation tied to a corrupted, trusted on-chain accounting value).

### Likelihood Explanation
Any unprivileged asset issuer can post an `asset` definition unit with `fixed_denominations: true` and a crafted `denominations` array — this requires no special privileges, matching the reachable "asset issuance" surface. The only requirement is choosing `count_coins` and `denomination` values whose product straddles the `Number.MAX_SAFE_INTEGER` boundary while `denomination` itself still individually satisfies `<= MAX_CAP`. Since `count_coins` is unconstrained, this is straightforward to construct, making exploitation for a determined attacker to have low complexity, though it depends on downstream contracts actually consuming `asset[...].cap` for security-relevant math.

### Recommendation
- Enforce `denomInfo.count_coins <= constants.MAX_CAP` (or `denomInfo.count_coins * denomInfo.denomination <= constants.MAX_CAP`) explicitly, rejecting denominations whose product could approach or exceed `Number.MAX_SAFE_INTEGER`.
- Perform the cap-sum accumulation (`total_cap_from_denominations`) using an arbitrary-precision arithmetic library (e.g., the same `Decimal` used in `formula/evaluation.js`) instead of native JS numbers, and reject/throw if the computed decimal value is not an exact safe integer.
- Add an explicit check that each individual product and the running sum never silently exceed `Number.MAX_SAFE_INTEGER`.

### Proof of Concept
1. Attacker composes an `asset` definition unit (`app: 'asset'`) with:
   - `fixed_denominations: true`
   - `issued_by_definer_only: true`
   - `denominations: [{ denomination: D, count_coins: N }, ...]` where `D <= constants.MAX_CAP` but `N` is chosen such that `D * N` (or the cumulative `total_cap_from_denominations`) exceeds `Number.MAX_SAFE_INTEGER` (2^53−1), causing IEEE-754 rounding.
   - `cap`: set to the *rounded* JS-computed value of `total_cap_from_denominations` (attacker can compute this offline in Node.js to know exactly what value the validator will accept).
2. `validateAssetDefinition` (`validation.js:2757-2792`) accepts the definition because the rounded computed sum equals the attacker-chosen `cap`, even though the "true" mathematical sum of `count_coins × denomination` differs.
3. Any AA or oscript logic that later reads `asset[<hash>].cap` to reason about the asset's total supply operates on a value inconsistent with the actual denomination table content, enabling miscalculation in AA-held-fund logic that depends on it.

### Citations

**File:** validation.js (L2769-2778)
```javascript
			if (!isPositiveInteger(denomInfo.denomination))
				return callback("invalid denomination");
			if (denomInfo.denomination > constants.MAX_CAP && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
				return callback("denomination exceeds MAX_CAP");
			if (denomInfo.denomination <= prev_denom)
				return callback("denominations unsorted");
			if ("count_coins" in denomInfo){
				if (!isPositiveInteger(denomInfo.count_coins))
					return callback("invalid count_coins");
				total_cap_from_denominations += denomInfo.count_coins * denomInfo.denomination;
```

**File:** validation.js (L2788-2791)
```javascript
		if (total_cap_from_denominations && !payload.cap)
			return callback("has no cap but denominations are capped");
		if (total_cap_from_denominations && payload.cap !== total_cap_from_denominations)
			return callback("cap doesn't match sum of denominations");
```

**File:** validation_utils.js (L27-29)
```javascript
function isPositiveInteger(int){
	return (isInteger(int) && int > 0);
}
```
