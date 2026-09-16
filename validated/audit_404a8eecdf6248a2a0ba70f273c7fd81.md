### Title
Unbounded `count_coins` × `denomination` multiplication can lose precision and bypass indivisible-asset cap/issue checks - ([File: validation.js])

### Summary
The CVE describes a wrong `row_factor` multiplication in libpng that overflows and produces an incorrect value used in a later security-relevant check (leading to a divide-by-zero). The analogous pattern in ocore is the multiplication `denomInfo.count_coins * denomInfo.denomination` used both when an asset issuer defines fixed denominations and when validating an indivisible-asset issue input, where the operands are only checked with `isPositiveInteger`/`isInteger`, which permits arbitrarily large "integer-like" floating point values with no upper bound.

### Finding Description
In `validateAssetDefinition`, when an asset issuer defines fixed denominations, each `denomInfo.count_coins` is validated only with `isPositiveInteger`, i.e. `Math.floor(value) === value && value > 0` [1](#0-0) 
There is no upper bound placed on `count_coins` itself (only `denomination` is bounded by `MAX_CAP`), and the sum is accumulated with plain floating point multiplication: [2](#0-1) 
Because JavaScript numbers are IEEE-754 doubles, an attacker-controlled `count_coins` value larger than `Number.MAX_SAFE_INTEGER` (2^53) still satisfies `Math.floor(x) === x` (since precision beyond 2^53 is lost, not fractional), so `isPositiveInteger` accepts it. Multiplying such a value by `denomination` can silently lose precision, producing a `total_cap_from_denominations` that does not reflect the issuer's actual declared/intended numbers, analogous to the wrong `row_factor` calculation in the CVE that silently produced an incorrect size value used downstream.

This same class of unchecked multiplication is repeated at issuance time in `validateIndivisibleIssue`, which checks the issue input amount against the stored denomination record: [3](#0-2) 
Here `denomInfo.count_coins` originates from the `asset_denominations` table, populated from the asset-definition message accepted at definition time. If a definition with an oversized `count_coins` were accepted (due to the missing bound above), the equality check `input.amount !== denomination * denomInfo.count_coins` could pass for an `input.amount` that does not correspond to the mathematically correct product, because both sides are computed via the same lossy floating-point multiplication and can coincidentally agree at the reduced double precision — while other paths (e.g. `payload.cap` comparisons, wallets displaying the true supply) use the untruncated intended totals.

### Impact Explanation
If this precision loss can be engineered by an asset issuer to make the recorded `cap`/`count_coins` bookkeeping and the actual issued amount diverge, this constitutes a supply-inflation-class issue restricted to the issuer's own custom asset (fixed-denomination, capped, indivisible), potentially letting the issuer mint/issue coins in a way inconsistent with the on-chain declared cap, causing downstream consumers relying on the cap (`payload.cap`) or on the denomination table to disagree with the true circulating amount.

### Likelihood Explanation
Exploitability requires the asset issuer to choose `denomination`/`count_coins` pairs that both (a) pass the current checks (`isPositiveInteger`, `denomination <= MAX_CAP`, sorted/uncapped-vs-capped consistency) and (b) produce a double-precision multiplication result that diverges from the mathematically intended value in a way that's exploitable at issuance. This requires very large `count_coins` (> 2^53 / denomination), which is an unusual value for realistic asset definitions, and I could not confirm within the available files whether any additional bound is enforced elsewhere (e.g., in `indivisible_asset.js` composer-side checks, or storage insert constraints) that would prevent such values from ever being written to `asset_denominations`. This uncertainty limits confidence in full exploitability.

### Recommendation
Add an explicit upper bound on `denomInfo.count_coins` (e.g., `count_coins <= Number.MAX_SAFE_INTEGER / denomination` or bound `count_coins * denomination <= constants.MAX_CAP` using safe-integer arithmetic or `BigInt`) in `validateAssetDefinition`, mirroring the existing `denomination > constants.MAX_CAP` check. Additionally, perform the issuance-time comparison in `validateIndivisibleIssue` (`input.amount !== denomination * denomInfo.count_coins`) using `BigInt` or an explicit safe-integer-range guard to avoid any floating-point precision loss affecting the equality check.

### Proof of Concept
Not independently verified end-to-end (would require confirming no additional bound exists elsewhere in `indivisible_asset.js`/`writer.js` before the value reaches `asset_denominations`); conceptually:
1. Issuer defines an asset with `fixed_denominations: true`, `denominations: [{ denomination: 1, count_coins: 9007199254740993 }]` (2^53+1, which is representable/accepted by `isPositiveInteger` due to double rounding to 9007199254740992).
2. `total_cap_from_denominations` is computed as `1 * 9007199254740992` (already the closest representable double), and `payload.cap` must equal this rounded value, not the issuer's originally intended 9007199254740993.
3. At issue time, `validateIndivisibleIssue` compares `input.amount !== denomination * denomInfo.count_coins`, i.e., `input.amount !== 9007199254740992`, allowing an issue input of exactly the rounded (not originally intended) value to pass — demonstrating that the check's correctness silently depends on double-precision rounding rather than the issuer's declared integer value.

### Citations

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

**File:** validation.js (L2218-2226)
```javascript
				var denomInfo = rows[0];
				if (denomInfo.count_coins === null){ // uncapped
					if (input.amount % denomination !== 0)
						return cb("issue amount must be multiple of denomination");
				}
				else{
					if (input.amount !== denomination * denomInfo.count_coins)
						return cb("wrong size of issue of denomination "+denomination);
				}
```

**File:** validation.js (L2775-2779)
```javascript
			if ("count_coins" in denomInfo){
				if (!isPositiveInteger(denomInfo.count_coins))
					return callback("invalid count_coins");
				total_cap_from_denominations += denomInfo.count_coins * denomInfo.denomination;
			}
```
