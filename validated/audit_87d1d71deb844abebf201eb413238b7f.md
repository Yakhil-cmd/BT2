### Title
AA asset definitions skip cap-vs-denominations consistency check, letting `cap` diverge from actual issuable supply - (File: aa_validation.js)

### Summary
When an autonomous agent (AA) defines a new asset via an `asset` message, `aa_validation.js` validates the `cap` and `denominations` fields independently but never verifies that `cap` actually equals the sum of `denominations[i].count_coins * denominations[i].denomination`. This mirrors the reported bug class: a "scale"/summary value (`cap`, analogous to `_uScale`) is accepted without being reconciled against the underlying granular data (`denominations`, analogous to `vaultCurrency.decimals()`), producing a value that downstream consumers wrongly assume is consistent.

### Finding Description
For ordinary (non-AA) asset definitions, `validateAssetDefinition()` in `validation.js` performs an explicit cross-check between `cap` and `denominations`: [1](#0-0) 

This ensures `payload.cap` always matches the sum of issuable coins implied by `denominations`.

The AA-definition schema validator, however, has no equivalent check. It validates `cap`'s type/format: [2](#0-1) 

and validates `denominations`' shape via `validateDenominations`, which only checks per-entry types/ordering, never accumulating a total and comparing it to `cap`: [3](#0-2) 

The two validated fields are wired together only as independent syntactic checks in the `case 'asset':` branch, with no reconciliation step: [4](#0-3) 

An AA author can therefore publish an asset-issuing AA whose `cap` (a plain number or a formula) does not correspond to the actual sum of `count_coins * denomination` across `denominations`. Nothing in `aa_validation.js` rejects this at definition time, unlike the human-authored path.

### Impact Explanation
`asset[...].cap` is a first-class field read by the oscript formula engine and relied upon by other logic (AAs and end users alike) to compute proportional amounts, e.g. paying out based on `asset[var['asset']].cap`: [5](#0-4) [6](#0-5) 

If `cap` is inconsistent with the true issuable supply defined by `denominations`, any AA/user formula that uses `cap` to size a payment, compute a ratio, or bound an issuance will compute wrong amounts — either overpaying (fund loss for the AA) or underpaying/locking funds, directly analogous to the reported vault `shares`/`value` miscalculation from a mismatched `exchangeRate`/`uScale`.

### Likelihood Explanation
Any unprivileged user can define and deploy an AA containing an `asset` message (a normal, permissionless action), and since `aa_validation.js` performs no cross-check, an inconsistent `cap`/`denominations` pair will pass definition validation and be accepted into the DAG. The condition is trivially reachable — no privileged role, network timing, or race condition is required.

### Recommendation
Add the same reconciliation logic used in `validateAssetDefinition()` (`validation.js` lines 2757-2792) to the AA `case 'asset':` branch in `aa_validation.js`: when both `cap` and `denominations` are literal (non-formula) values, sum `count_coins * denomination` and require it to equal `cap` (rejecting the definition otherwise); for formula-based `cap`/`denominations`, add an equivalent evaluation-time consistency check (e.g., in `aa_composer.js` when materializing the `asset` message) before writing the asset row, mirroring the non-AA path's guarantees.

### Proof of Concept
1. Author an AA with an `asset` message:
```
{
  app: 'asset',
  payload: {
    cap: 1000000,
    is_private: false,
    is_transferrable: true,
    auto_destroy: false,
    fixed_denominations: true,
    issued_by_definer_only: true,
    cosigned_by_definer: false,
    spender_attested: false,
    denominations: [{ denomination: 1, count_coins: 10 }]  // real total = 10, not 1000000
  }
}
```
2. This passes `aa_validation.js`'s `case 'asset':` checks since `cap` and `denominations` are validated independently (`aa_validation.js` lines 230-287), with no cross-check.
3. Any downstream AA/user logic reading `asset[asset_id].cap` (as in `test/aa_composer.test.js` lines 511-521) will use `1000000` as the supply/scale, while only `10` units can ever actually be issued — producing miscalculated payouts/ratios wherever `cap` is trusted as the true scale.

### Citations

**File:** validation.js (L2784-2791)
```javascript
		if (bHasUncappedDenominations && total_cap_from_denominations)
			return callback("some denominations are capped, some uncapped");
		if (bHasUncappedDenominations && payload.cap)
			return callback("has cap but some denominations are uncapped");
		if (total_cap_from_denominations && !payload.cap)
			return callback("has no cap but denominations are capped");
		if (total_cap_from_denominations && payload.cap !== total_cap_from_denominations)
			return callback("cap doesn't match sum of denominations");
```

**File:** aa_validation.js (L230-242)
```javascript
					if ("cap" in payload) {
						if (typeof payload.cap === 'number') {
							if (!(isPositiveInteger(payload.cap) && payload.cap <= constants.MAX_CAP))
								return cb2("invalid cap: " + payload.cap);
						}
						else if (typeof payload.cap === 'string') {
							var f = getFormula(payload.cap);
							if (f === null)
								return cb2("bad formula in cap: " + payload.cap);
						}
						else
							return cb2("wrong cap: " + JSON.stringify(payload.cap));
					}
```

**File:** aa_validation.js (L244-287)
```javascript
					function validateDenominations(denominations, cb3) {
						if (isNonemptyString(denominations)) {
							var f = getFormula(denominations);
							if (f === null)
								return cb3("denominations is a string but not formula: " + denominations);
							return cb3();
						}
						if (!isNonemptyArray(denominations))
							return cb3("wrong denominations: " + JSON.stringify(denominations));
						if (denominations.length > constants.MAX_DENOMINATIONS_PER_ASSET_DEFINITION)
							return cb3("too many denominations");
						for (var i=0; i<denominations.length; i++){
							var denomInfo = denominations[i];
							if (!isNonemptyObject(denomInfo))
								return cb3("denomination must be a non-empty object: " + JSON.stringify(denomInfo));
							if (hasFieldsExcept(denomInfo, ["denomination", "count_coins"]))
								return cb3("unknown fields in denomination: " + JSON.stringify(denomInfo));
							if (typeof denomInfo.denomination === 'number') {
								if (!isPositiveInteger(denomInfo.denomination))
									return cb3("invalid denomination");
							}
							else if (typeof denomInfo.denomination === 'string') {
								var f = getFormula(denomInfo.denomination);
								if (f === null)
									return cb3("bad formula in denomination: "+ denomInfo.denomination);
							}
							else
								return cb3("bad denomination " + JSON.stringify(denomInfo.denomination));
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
						}
						cb3();
					}
```

**File:** aa_validation.js (L317-333)
```javascript
							async.series([
								function (cb3) {
									if (!("attestors" in payload))
										return cb3();
									validateFieldWrappedInCases(payload, 'attestors', validateAttestors, cb3);
								},
								function (cb3) {
									if (!("denominations" in payload))
										return cb3();
									validateFieldWrappedInCases(payload, 'denominations', validateDenominations, cb3);
								}
							],
							function (err) {
								if (err)
									return cb2(err);
								cb2();
							});
```

**File:** formula/evaluation.js (L1553-1557)
```javascript
							if (objAsset.sequence !== "good")
								return cb(false);
							if (field === 'cap') // can be null
								return cb(convertValue(objAsset.cap || 0));
							if (field === 'definer_address')
```

**File:** test/aa_composer.test.js (L511-521)
```javascript
				{
					if: `{trigger.address == '${bouncer_address}' AND var['asset']}`,
					messages: [{
						app: 'payment',
						payload: {
							asset: "{var['asset']}",
							outputs: [
								{address: "{trigger.initial_address}", amount: "{asset[var['asset']].cap}"}
							]
						}
					}]
```
