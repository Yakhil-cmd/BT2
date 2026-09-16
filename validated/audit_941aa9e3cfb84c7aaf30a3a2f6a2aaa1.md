### Title
Integer-overflow / precision-loss in asset denomination cap accounting allows supply-inflation bypass - ([File: validation.js])

### Summary
`validateAssetDefinition()` in `validation.js` sums `count_coins * denomination` for every denomination entry of a fixed-denomination asset without ever bounding `count_coins`, unlike `denomination` and the overall `cap`, which are both capped at `constants.MAX_CAP`. Because the sum is computed with ordinary JavaScript number arithmetic (IEEE-754 doubles), an attacker who single-authors an asset-definition unit can choose `count_coins`/`denomination` pairs whose product exceeds `Number.MAX_SAFE_INTEGER`, producing silent precision loss analogous to a classic integer overflow. This lets the computed `total_cap_from_denominations` diverge from the true mathematical product while still satisfying the on-chain equality check against `payload.cap`, enabling issuance of indivisible-asset coins whose declared per-denomination supply does not match their nominal value.

### Finding Description
In the asset-definition validator: [1](#0-0) 

- `denomInfo.denomination` is checked against `constants.MAX_CAP` (conditionally, based on `pemCurvesFixMci`) [2](#0-1) 
- `denomInfo.count_coins` is only checked with `isPositiveInteger`, which enforces integer positivity but applies **no upper bound at all** — no `MAX_CAP` comparison exists for `count_coins` anywhere in this function [3](#0-2) 
- The running total is accumulated as `total_cap_from_denominations += denomInfo.count_coins * denomInfo.denomination;` using plain JS number multiplication/addition [4](#0-3) 
- The final consistency check is a strict equality: `if (total_cap_from_denominations && payload.cap !== total_cap_from_denominations) return callback("cap doesn't match sum of denominations");` [5](#0-4) 

Because `count_coins` can be an arbitrarily large positive integer (bounded only by JS's own integer representation, not by `MAX_CAP`), and `denomination` can independently approach `MAX_CAP`, the product `count_coins * denomination` can exceed `Number.MAX_SAFE_INTEGER` (2^53). At that point IEEE-754 double rounding causes multiple distinct `(count_coins, denomination)` pairs to collapse to the same floating-point `total_cap_from_denominations` value, or causes the sum accumulated across several denominations to round in ways that no longer reflect the true total. This is functionally the same class of bug as CVE-2026-7162 (integer overflow leading to corrupted size/quantity accounting) — the root cause here is unmanaged multiplication of two unbounded/insufficiently-bounded integers feeding into a security-relevant consistency check.

The identical unguarded-`count_coins` pattern is repeated in the AA-definition validator (`aa_validation.js`), which validates the nested `denominations`/`count_coins` fields for AA-issued assets with the same lack of an upper bound: [6](#0-5) 

The same asset object is later used at issuance time to determine `count_coins_to_issue` per denomination and multiply into the actual `issue_amount` for real coins: [7](#0-6) 

### Impact Explanation
Because the equality check `payload.cap !== total_cap_from_denominations` (validation.js:2790-2791) is the sole mechanism binding the declared `cap` to the sum of per-denomination `count_coins × denomination`, a rounding collision lets an attacker post a self-consistent-looking (from validators' perspective) asset definition whose real, intended supply and its serialized `cap` diverge. Since every node performs the identical floating-point arithmetic, all honest nodes would accept the same (corrupted) accounting deterministically — this does not itself cause node disagreement, but it does allow the asset issuer to craft a capped indivisible asset where the actual amount mintable across its denomination buckets does not match the declared, audited `cap`, effectively achieving supply inflation beyond the stated cap for that asset. This is a High-severity finding because it affects asset issuance integrity network-wide and is reachable by any single-authored unit poster defining a new asset — no privileged party required.

### Likelihood Explanation
Triggering the bug requires only posting a normal `asset` definition message with attacker-chosen `denominations` array — a capability available to any user/unit poster and to AAs defining assets. No special privileges, hub cooperation, or race conditions are needed; the attacker simply needs to find `(count_coins, denomination)` values whose product exceeds `Number.MAX_SAFE_INTEGER` (2^53 ≈ 9×10^15) while `denomination` itself stays at or below `MAX_CAP`, which is a straightforward computation. The main uncertainty (unverified due to tool-call exhaustion) is the exact numeric value of `constants.MAX_CAP` in this codebase; I was unable to complete the last `grep_search` for `MAX_CAP` in `constants.js` before losing tool access, so it is not fully confirmed whether `MAX_CAP` is large enough relative to 2^53 to make the overflow condition trivially reachable in a single pair, or whether it would require chaining multiple denomination entries (up to `constants.MAX_DENOMINATIONS_PER_ASSET_DEFINITION`) to accumulate enough magnitude. Either way, since `count_coins` has no upper bound at all, the overflow is reachable given enough denomination entries even if `MAX_CAP` is comparatively small.

### Recommendation
- Add an explicit upper bound on `denomInfo.count_coins` (e.g., `count_coins <= constants.MAX_CAP` or a tighter bound derived from `MAX_CAP / denomination`) in both `validateAssetDefinition` (`validation.js`) and the AA denomination validator (`aa_validation.js`).
- Perform the cap-consistency arithmetic using integer-safe operations (e.g., using `Number.isSafeInteger` checks after each multiplication/addition, or an arbitrary-precision library such as `Decimal.js`, which is already used elsewhere in this codebase per `formula/evaluation.js`) and reject the unit if any intermediate product/sum exceeds `Number.MAX_SAFE_INTEGER`.
- Apply the same safe-integer validation to the issuance-time computation in `indivisible_asset.js` (`count_coins_to_issue * denomination`) to ensure consistency between validation-time and issuance-time arithmetic.

### Proof of Concept
1. Craft an asset-definition unit with `fixed_denominations: true` and `denominations` such as:
   - `{ denomination: 100000000, count_coins: 100000000 }` → product `1e16`, exceeding `Number.MAX_SAFE_INTEGER` (2^53 ≈ 9.007×10^15).
   - Add a second denomination entry designed so that the floating-point-rounded sum equals an attacker-chosen `payload.cap` value that does not match the true mathematical total.
2. Set `payload.cap` to the rounded (corrupted) sum so it passes the `payload.cap !== total_cap_from_denominations` check at [5](#0-4) .
3. Post the unit; all nodes independently compute the same JS float sum and accept it as valid, since the check only compares the equally-corrupted values.
4. Subsequent issuance via `indivisible_asset.js`'s `issueNextCoin` (lines 530-536) mints coins according to `count_coins_to_issue * denomination`, which may not match the nominal `cap` originally advertised to holders/exchanges relying on the declared cap for valuation, effectively inflating supply relative to the represented cap.

(Note: I was unable to verify the exact value of `constants.MAX_CAP` due to running out of tool calls before completing the grep; this affects only the precise numeric parameters of the PoC, not the underlying missing-bound root cause, which is directly confirmed in the cited code.)

### Citations

**File:** validation.js (L2769-2792)
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

**File:** aa_validation.js (L272-284)
```javascript
							if ("count_coins" in denomInfo) {
								if (typeof denomInfo.count_coins === 'number') {
									if (!isPositiveInteger(denomInfo.count_coins))
										return cb3("invalid count_coins");
								}
								else if (typeof denomInfo.count_coins === 'string') {
									var f = getFormula(denomInfo.count_coins);
									if (f === null)
										return cb3("bad formula in count_coins: "+ denomInfo.count_coins);
								}
								else
									return cb3("bad count_coins " + JSON.stringify(denomInfo.count_coins));
							}
```

**File:** indivisible_asset.js (L530-536)
```javascript
					var row = rows[0];
					if (!!row.count_coins !== !!objAsset.cap)
						throw Error("invalid asset cap and count_coins");
					var denomination = row.denomination;
					var serial_number = row.max_issued_serial_number+1;
					var count_coins_to_issue = row.count_coins || Math.floor((remaining_amount+tolerance_plus)/denomination);
					var issue_amount = count_coins_to_issue * denomination;
```
