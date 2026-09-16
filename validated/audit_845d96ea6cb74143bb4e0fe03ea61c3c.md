### Title
Asset cap can silently diverge from actual denomination supply due to unchecked multiplication precision loss - (File: validation.js)

### Summary
`validateAssetDefinition` sums up the total supply implied by a `denominations` array using plain JS multiplication (`count_coins * denomination`) and compares it against the declared `cap` field. Both `denomination` and `count_coins` are only checked to be positive integers with no joint bound on their product, so an attacker can construct a denominations array whose true product exceeds `Number.MAX_SAFE_INTEGER` (2^53-1), causing IEEE-754 floating-point rounding of the accumulated `total_cap_from_denominations`. This is the same "unchecked multiplication of two attacker-controlled large integers" bug class as the reported Sherlock issue (`strikePrice * amount` overflow in `FixedStrikeOptionTeller.sol`), here manifesting as silent precision loss instead of a revert.

### Finding Description [1](#0-0) 

- `denomInfo.denomination` is bounded only by `constants.MAX_CAP` [2](#0-1) .
- `denomInfo.count_coins` is validated only via `isPositiveInteger(denomInfo.count_coins)`, with **no upper bound at all** [3](#0-2) .
- The running total is accumulated as `total_cap_from_denominations += denomInfo.count_coins * denomInfo.denomination;` using ordinary JS number multiplication, which silently loses precision once the product exceeds 2^53 [4](#0-3) .
- The only integrity check performed is `payload.cap !== total_cap_from_denominations` [5](#0-4) , which can be made to pass with a `cap` value that does not correspond to the real sum of `count_coins * denomination` across all denomination tiers, because the rounded floating-point sum can coincidentally (or by attacker-crafted inputs) equal the attacker-chosen `cap`.
- The same unguarded multiplication pattern is reused at issuance time in `indivisible_asset.js`, where `issue_amount = count_coins_to_issue * denomination` (and the equivalent check in `validateIndivisibleIssue` at `validation.js:2224`, `input.amount !== denomination * denomInfo.count_coins`) determines how many asset units are actually minted per issue input [6](#0-5) .

Because the multiplication is deterministic IEEE-754 arithmetic, all nodes compute the same (possibly wrong) value, so this does not directly cause a fork/consensus split. However, it breaks the invariant that `payload.cap` accurately represents the true, human/AA-verifiable total supply implied by the `denominations` schedule: an asset definer can pass validation with a `cap` value that misrepresents the actual issuable/minted total once the numbers are large enough to exceed safe-integer precision.

### Impact Explanation
`asset[...].cap` is a value that other on-chain logic (including AA oscript formulas, e.g. `asset[var['asset']].cap` seen in `test/aa_composer.test.js:518`) and off-chain consumers rely on to reason about total possible supply of an indivisible, denominated asset. If the declared `cap` can be decoupled from the real denomination-derived supply via float overflow, contracts/AAs and users that trust `cap` to bound issuance can be misled about the true maximum supply of the asset, which is a supply-integrity violation for asset issuance — potentially enabling supply inflation beyond the value that downstream logic (e.g., AA-issued/backed assets) assumes as the cap.

### Likelihood Explanation
Reaching this requires only posting a normal `asset` definition message with a crafted `denominations` array — something any unprivileged unit poster or AA-defined asset can do (asset definitions are permissionless, single-authored messages). The values needed to trigger float-precision loss (products beyond 2^53 ≈ 9.007×10^15) are within the space allowed by `isPositiveInteger` and the `MAX_CAP`-bounded `denomination` field combined with an unbounded `count_coins`, making the exploit constructible without special privileges.

### Recommendation
- Bound `count_coins` explicitly (e.g., by `constants.MAX_CAP` or a value that keeps `count_coins * denomination` within `Number.MAX_SAFE_INTEGER`).
- Perform the multiplication and running-sum checks using an overflow-safe method (e.g., BigInt, or explicit `product > Number.MAX_SAFE_INTEGER` checks) both in `validateAssetDefinition` (`validation.js`) and in the issuance-time check `validateIndivisibleIssue` / `indivisible_asset.js`, rejecting any denomination schedule whose true product cannot be represented exactly as a JS number.

### Proof of Concept
1. Craft an `asset` definition message with `fixed_denominations: true` and a `denominations` array containing an entry with `denomination` and `count_coins` such that their exact product exceeds `Number.MAX_SAFE_INTEGER` (2^53−1 ≈ 9.007×10^15), e.g. `denomination = 100000000` (1e8, ≤ MAX_CAP) and `count_coins = 100000000000` (1e11), whose true product is 1e19, far beyond safe-integer precision.
2. Set `cap` in the same payload to the floating-point-rounded value that JS actually computes for `count_coins * denomination` (obtainable by evaluating the same expression in a JS console), rather than the true mathematical product.
3. Submit the asset-definition unit; `validateAssetDefinition` in `validation.js:2757-2792` accepts it because `total_cap_from_denominations === payload.cap` holds under floating-point rounding, even though the declared `cap` does not equal the true `count_coins * denomination` product.
4. This asset is now live with a `cap` field that misrepresents the real denomination-implied supply, which downstream AA logic and wallets read via `asset[...].cap` as an authoritative bound.

### Citations

**File:** validation.js (L2757-2792)
```javascript
	if (payload.denominations){
		if (payload.denominations.length > constants.MAX_DENOMINATIONS_PER_ASSET_DEFINITION)
			return callback("too many denominations");
		var total_cap_from_denominations = 0;
		var bHasUncappedDenominations = false;
		var prev_denom = 0;
		for (var i=0; i<payload.denominations.length; i++){
			var denomInfo = payload.denominations[i];
			if (!isNonemptyObject(denomInfo))
				return callback("denomination must be a non-empty object: " + JSON.stringify(denomInfo));
			if (hasFieldsExcept(denomInfo, ["denomination", "count_coins"]))
				return callback("unknown fields in denomination: " + JSON.stringify(denomInfo));
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
			}
			else
				bHasUncappedDenominations = true;
			prev_denom = denomInfo.denomination;
		}
		if (bHasUncappedDenominations && total_cap_from_denominations)
			return callback("some denominations are capped, some uncapped");
		if (bHasUncappedDenominations && payload.cap)
			return callback("has cap but some denominations are uncapped");
		if (total_cap_from_denominations && !payload.cap)
			return callback("has no cap but denominations are capped");
		if (total_cap_from_denominations && payload.cap !== total_cap_from_denominations)
			return callback("cap doesn't match sum of denominations");
	}
```

**File:** indivisible_asset.js (L533-536)
```javascript
					var denomination = row.denomination;
					var serial_number = row.max_issued_serial_number+1;
					var count_coins_to_issue = row.count_coins || Math.floor((remaining_amount+tolerance_plus)/denomination);
					var issue_amount = count_coins_to_issue * denomination;
```
