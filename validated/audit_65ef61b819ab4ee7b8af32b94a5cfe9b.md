Confirmed: `isPositiveInteger` only checks `typeof value === 'number' && isFinite(value) && Math.floor(value) === value && int > 0` — it does **not** bound the value against `constants.MAX_CAP` or `Number.MAX_SAFE_INTEGER`. This confirms the finding below: `denomInfo.count_coins` is validated only with `isPositiveInteger`, unlike `denomInfo.denomination`, which is explicitly capped against `constants.MAX_CAP`.

### Title
Integer-precision overflow (wraparound) in indivisible-asset denomination cap validation allows supply-inflating asset definitions - ([File: validation.js])

### Summary
`validateAssetDefinition()` in `validation.js` validates an asset's `denominations` array by summing `count_coins * denomination` for each entry into `total_cap_from_denominations`, then compares that sum to the asset's declared `cap`. `count_coins` is checked only with `isPositiveInteger()`, which enforces integer-ness and positivity but has no upper bound (unlike `denomination`, which is explicitly checked against `constants.MAX_CAP`). Because JS numbers are IEEE-754 doubles, multiplying/accumulating unbounded `count_coins * denomination` values can silently lose precision once results exceed `Number.MAX_SAFE_INTEGER` (2^53), which is the JS analog of C's integer wraparound in the referenced kernel CVE (silent truncation instead of an explicit error).

### Finding Description [1](#0-0) 

- `denomInfo.denomination` is bounded: `if (denomInfo.denomination > constants.MAX_CAP ...) return callback("denomination exceeds MAX_CAP")` [2](#0-1) .
- `denomInfo.count_coins` has **no equivalent MAX_CAP check** — only `isPositiveInteger(denomInfo.count_coins)` [3](#0-2) , and `isPositiveInteger` merely verifies `Number.isInteger` and `> 0` with no upper bound [4](#0-3) .
- The running total is accumulated as a plain floating point sum: `total_cap_from_denominations += denomInfo.count_coins * denomInfo.denomination;` [5](#0-4) . With up to `constants.MAX_DENOMINATIONS_PER_ASSET_DEFINITION` entries and per-entry products individually valid but jointly exceeding `2^53`, this sum silently rounds instead of throwing, exactly analogous to unsigned wraparound truncating a large value to a smaller, attacker-chosen one.
- The rounded `total_cap_from_denominations` is then compared for exact equality against `payload.cap`: `if (total_cap_from_denominations && payload.cap !== total_cap_from_denominations) return callback("cap doesn't match sum of denominations");` [6](#0-5) . An attacker can craft `count_coins`/`denomination` pairs whose true product sum is astronomically larger than `MAX_CAP` but whose floating-point-rounded sum coincidentally equals a chosen, validator-accepted `cap` value (which is itself bounded to `MAX_CAP`), passing this check.
- The `count_coins` values are persisted verbatim into `asset_denominations.count_coins` (schema `BIGINT`) and later used unmodified during indivisible-asset issuance to compute `issue_amount = count_coins * denomination` in `indivisible_asset.js`'s `issueNextCoin()` [7](#0-6) , and the per-input issue amount is separately bound-checked only against `constants.MAX_CAP` in `validation.js`'s issue-input handling [8](#0-7) . This creates a discrepancy between the asset's declared/validated `cap` (accepted due to floating-point coincidence) and the actual enumerable coin supply implied by `count_coins`, which every node computes identically (deterministic JS arithmetic), so this is not a simple crash/DoS but a consensus-consistent but economically incorrect acceptance of a malformed asset definition, enabling issuance of more total coin value across serial numbers than the nominal cap implies.

### Impact Explanation
This allows a single, unprivileged unit poster (asset definer) to register a fixed-denomination asset whose true enumerable supply is inconsistent with (i.e., can exceed) the value asserted by `cap`, since the sum-matching check that is supposed to guarantee `cap == Σ(count_coins × denomination)` can be satisfied only in floating-point-truncated arithmetic while the real integer supply is far larger. Because `count_coins` is stored as-is and used unmodified when issuing coins per denomination bucket, this can result in the asset's issuable supply silently diverging from its declared cap — a form of supply inflation for capped, fixed-denomination indivisible assets.

### Likelihood Explanation
Exploitation requires an attacker to author an `asset` message (`app: 'asset'`) with `fixed_denominations: true`, up to `constants.MAX_DENOMINATIONS_PER_ASSET_DEFINITION` denomination/count_coins pairs, and carefully chosen values so that the floating-point sum matches a chosen `cap`. This is fully reachable by any address posting a unit (single-authored asset definitions), requires no special privileges, no network/peer trust assumptions, and no interaction with other parties. The main barrier is the numeric engineering needed to find `count_coins`/`denomination` combinations whose true sum overflows `2^53` while floating-point rounding coincidentally equals the target `cap` — feasible with off-chain computation before submission.

### Recommendation
- Bound `denomInfo.count_coins` explicitly by `constants.MAX_CAP` (or by `MAX_CAP / denomInfo.denomination`), mirroring the existing check on `denomInfo.denomination`.
- Perform the running-sum accumulation and cap comparison using exact/big-integer arithmetic (e.g., `BigInt`) instead of native `+=`/`*` on `Number`, or reject as soon as any partial product or running sum would exceed `Number.MAX_SAFE_INTEGER` / `MAX_CAP`.
- Add a defensive check immediately after computing `total_cap_from_denominations` that it never exceeds `constants.MAX_CAP`, independent of whether it happens to equal `payload.cap`.

### Proof of Concept
1. Craft an `asset` definition unit with `fixed_denominations: true`, `cap: X` (a value ≤ `MAX_CAP` chosen by the attacker), and a `denominations` array containing entries `{denomination: d_i, count_coins: c_i}` where each `d_i ≤ MAX_CAP` and each `c_i` is a large positive integer with no upper-bound check.
2. Choose `c_i, d_i` pairs (feasible offline via brute-force/search over IEEE-754 rounding behavior) such that the true integer sum `Σ(c_i * d_i)` is far larger than `Number.MAX_SAFE_INTEGER`/`X`, but the JS floating-point evaluation of `total_cap_from_denominations += c_i * d_i` rounds to exactly `X`.
3. Submit the unit; `validateAssetDefinition` passes because `payload.cap === total_cap_from_denominations` numerically in floating point [6](#0-5) , even though the real enumerable supply across denominations is inconsistent with `X`.
4. Subsequent issuance of each denomination bucket uses the unmodified, oversized `count_coins` value to compute `issue_amount` [7](#0-6) , allowing the asset's real circulating supply to diverge from its nominally validated `cap`.

**Note on verification limits**: I was not able to execute the actual floating-point search to confirm a concrete numeric example (`c_i`, `d_i`, `X` triple) that reproduces the exact rounding coincidence, since I only have static code access, not a runtime to test JS float arithmetic. The root-cause code path (unbounded `count_coins`, floating-point summation, exact-equality cap check) is confirmed directly from the source, but confirming an exploitable numeric example would require running the arithmetic in a JS environment.

### Citations

**File:** validation.js (L2315-2318)
```javascript
					if (!isPositiveInteger(input.amount))
						return cb("amount must be positive");
					if (input.amount > constants.MAX_CAP)
						return cb("issue amount too large: " + input.amount)
```

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

**File:** validation.js (L2790-2791)
```javascript
		if (total_cap_from_denominations && payload.cap !== total_cap_from_denominations)
			return callback("cap doesn't match sum of denominations");
```

**File:** validation_utils.js (L20-29)
```javascript
function isInteger(value){
	return typeof value === 'number' && isFinite(value) && Math.floor(value) === value;
};

/**
 * True if int is an integer strictly greater than zero.
 */
function isPositiveInteger(int){
	return (isInteger(int) && int > 0);
}
```

**File:** indivisible_asset.js (L535-536)
```javascript
					var count_coins_to_issue = row.count_coins || Math.floor((remaining_amount+tolerance_plus)/denomination);
					var issue_amount = count_coins_to_issue * denomination;
```
