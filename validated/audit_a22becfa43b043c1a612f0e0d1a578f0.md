### Title
AA asset-issuance definition does not enforce "capped asset must be issuer-only" - allowing uncontrolled supply inflation - (File: aa_validation.js)

### Summary
The external report flags Aera Vault's constructor for not validating enough of its input parameters (manager, notice period, management fee, etc.), letting a privileged deployer create a vault whose "obviously required" invariants (e.g., manager ≠ owner, minimum notice period) are silently missing. The equivalent class of bug in ocore is a definition/constructor path that skips an invariant check that the "canonical" validator enforces elsewhere. I found exactly this pattern in the AA "asset" message template validator.

### Finding Description
When a regular (non-AA) unit defines an asset via `app: "asset"`, `validateAssetDefinition()` in `validation.js` enforces:
```
if (payload.cap && !payload.issued_by_definer_only)
    return callback("if capped, must be issued by definer only");
``` [1](#0-0) 

This invariant exists because the runtime issue-input double-spend key only scopes issuance uniqueness by `address` when `issued_by_definer_only` is false:
```
if (objAsset && !objAsset.issued_by_definer_only){
    doubleSpendWhere += " AND address=?";
    doubleSpendVars.push(address);
}
...
if (objAsset.cap && !objAsset.fixed_denominations && input.amount !== objAsset.cap)
    return cb("issue must be equal to cap");
``` [2](#0-1) 

In other words, for a capped asset that is *not* `issued_by_definer_only`, the "issue must equal the full cap" rule is checked **per address**, not globally: every distinct address that authors an `issue` input can independently issue the *entire* cap amount once, because the double-spend uniqueness key includes `address`. This is precisely why `cap` requires `issued_by_definer_only` for regular asset definitions — without that pairing, the cap is meaningless and can be multiplied by the number of distinct issuing addresses.

However, when an **AA (Autonomous Agent) definition** declares that it will issue an `asset` message (an "unprivileged AA author" scenario, directly analogous to the Treasury deploying the vault), the structural validator for the AA's asset-message template — `aa_validation.js`'s `case 'asset':` branch inside `validateAADefinition()` — checks `cap` value bounds, denominations, boolean fields, etc., but never enforces that `cap` implies `issued_by_definer_only`: [3](#0-2) [4](#0-3) 

Compare this to the equivalent, complete check that exists for ordinary units in `validateAssetDefinition`: [5](#0-4) [1](#0-0) 

The AA-definition validator's `asset` branch is missing this exact cross-field constraint, so an AA author can post an AA whose template asset message sets `cap` (a positive integer or a formula) while leaving `issued_by_definer_only` false (or a formula that can evaluate to false). `validateAADefinition()` will accept this definition as valid.

### Impact Explanation
If an AA is deployed with a capped, non-issuer-only asset, then whenever the AA emits that `asset` "issue" behavior for different trigger addresses, each distinct issuing address can independently mint the full `cap` amount (because uniqueness is keyed by `address`, not globally, once `issued_by_definer_only` is false). This breaks the fundamental "fixed total supply" guarantee of a capped asset: the effective supply becomes `cap * (number of distinct issuing addresses)` instead of `cap`, i.e., unbounded supply inflation of an asset that users/AAs are led to believe is capped. Any AA-composed asset relying on the "capped ⇒ fixed total supply" property (collateral accounting, wrapped-asset pegs, voting weight, etc.) can be drained or devalued, causing concrete unauthorized value creation/fund loss for holders and counterparties of that asset — the same class of impact ("could give full unintended power/loss due to an unchecked constructor parameter") the external report is concerned about, just manifesting as supply inflation instead of vault takeover.

### Likelihood Explanation
Reaching this requires only posting a normal AA-definition unit (an `app: "definition"` message with a `definition` template containing an `asset` message that sets `cap` and omits/negates `issued_by_definer_only`) — something any unprivileged unit poster/AA author can do; no special privileges, witnesses, or hub cooperation are needed. The gap is a straightforward omission of a cross-field check that already exists one file away for the non-AA code path, which strongly suggests the AA path was never updated to mirror it. Likelihood of triggering the missing branch is high for any developer/attacker who authors such an AA; the actual "instantiation" of the inflation still needs the AA logic to run (i.e., for multiple distinct addresses to actually invoke the asset-issuing message), but that requires no bypass — it's the intended trigger flow of an AA.

### Recommendation
Add the same cross-field invariant to `aa_validation.js`'s `case 'asset':` branch that exists in `validation.js`'s `validateAssetDefinition`:
```
if (payload.cap && payload.issued_by_definer_only !== true)
    return cb2("if capped, must be issued by definer only");
```
Because `cap` and `issued_by_definer_only` in the AA template may be formulas (evaluated at runtime), this check should also be re-verified at the point where the AA actually composes/emits the `asset` message at runtime (wherever the AA response unit's asset-issuance side effects are persisted), not only at AA-definition validation time, to prevent formulas from producing a capped/non-issuer-only combination that bypasses a purely static check.

### Proof of Concept
1. Define AA `X` whose template contains an `asset` message such as:
```json
{
  "app": "asset",
  "payload": {
    "cap": 1000000,
    "is_private": false,
    "is_transferrable": true,
    "auto_destroy": false,
    "fixed_denominations": false,
    "issued_by_definer_only": false,
    "cosigned_by_definer": false,
    "spender_attested": false
  }
}
```
`validateAADefinition()` accepts this because it never checks `cap` against `issued_by_definer_only` (see cited code, `aa_validation.js:225-336`).
2. Deploy AA `X`. Design its `messages` so that, depending on `trigger.address`, it issues this asset (an `issue` input in a payment message for the asset) crediting the triggering address.
3. Multiple distinct addresses (`A1`, `A2`, `A3`, …) each trigger AA `X` once. For each distinct address, the runtime double-spend key in `validation.js` (`doubleSpendWhere += " AND address=?"` because `issued_by_definer_only` is false) permits a fresh, full-`cap` issuance per address, since uniqueness is scoped per-address rather than globally.
4. Result: total circulating supply of the asset becomes `cap * N` (N = number of distinct issuing addresses) instead of the intended `cap`, silently violating the asset's advertised fixed-supply guarantee.

*Note: I was unable to fully trace, within the available tool budget, the exact function in `aa_composer.js`/`storage.js` that persists an AA-emitted `asset` "issue" message to confirm whether it re-runs `validateAssetDefinition`'s full checks or relies solely on the AA-definition-time structural check in `aa_validation.js`. This proof of concept assumes the AA-definition-time gap is the only gate (which is the pattern used for all other fields in that same branch, e.g. `cosigned_by_definer`, `is_private`+`fixed_denominations` combination), consistent with how the rest of that function is structured.*

### Citations

**File:** validation.js (L2344-2373)
```javascript
					if (objAsset){
						if (objAsset.cap && !objAsset.fixed_denominations && input.amount !== objAsset.cap)
							return cb("issue must be equal to cap");
					}
					else{
						if (!storage.isGenesisUnit(objUnit.unit))
							return cb("only genesis can issue base asset");
						if (input.amount !== constants.TOTAL_WHITEBYTES)
							return cb("issue must be equal to cap");
					}
					total_input += input.amount;
					
					var input_key = (payload.asset || "base") + "-" + denomination + "-" + address + "-" + input.serial_number;
					if (objValidationState.arrInputKeys.indexOf(input_key) >= 0)
						return callback("input "+input_key+" already used");
					objValidationState.arrInputKeys.push(input_key);
					doubleSpendWhere = "type='issue'";
					doubleSpendVars = [];
				//	if (objAsset && objAsset.fixed_denominations){
						doubleSpendWhere += " AND denomination=?";
						doubleSpendVars.push(denomination);
				//	}
					if (objAsset){
						doubleSpendWhere += " AND serial_number=?";
						doubleSpendVars.push(input.serial_number);
					}
					if (objAsset && !objAsset.issued_by_definer_only){
						doubleSpendWhere += " AND address=?";
						doubleSpendVars.push(address);
					}
```

**File:** validation.js (L2725-2736)
```javascript
function validateAssetDefinition(conn, payload, objUnit, objValidationState, callback){
	if (objUnit.authors.length !== 1)
		return callback("asset definition must be single-authored");
	if (!isNonemptyObject(payload))
		return callback("asset definition must be a non-empty object");
	if (hasFieldsExcept(payload, ["cap", "is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested", "issue_condition", "transfer_condition", "attestors", "denominations"]))
		return callback("unknown fields in asset definition");
	if (typeof payload.is_private !== "boolean" || typeof payload.is_transferrable !== "boolean" || typeof payload.auto_destroy !== "boolean" || typeof payload.fixed_denominations !== "boolean" || typeof payload.issued_by_definer_only !== "boolean" || typeof payload.cosigned_by_definer !== "boolean" || typeof payload.spender_attested !== "boolean")
		return callback("some required fields in asset definition are missing");

	if ("cap" in payload && !(isPositiveInteger(payload.cap) && payload.cap <= constants.MAX_CAP))
		return callback("invalid cap");
```

**File:** validation.js (L2802-2803)
```javascript
	if (payload.cap && !payload.issued_by_definer_only)
		return callback("if capped, must be issued by definer only");
```

**File:** aa_validation.js (L225-243)
```javascript
				case 'asset':
					if (hasFieldsExcept(payload, ["cap", "is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested", "issue_condition", "transfer_condition", "attestors", "denominations", "init"]))
						return cb2("unknown fields in asset definition in AA");
					if (payload.fixed_denominations === true && !isNonemptyArray(payload.denominations))
						return cb2("denominations not defined");
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

**File:** aa_validation.js (L297-336)
```javascript
					if (payload.cosigned_by_definer !== false)
						return cb2("cosigned_by_definer must be false because AA can't cosign");
					if (payload.issued_by_definer_only === true && (payload.is_private !== false || payload.fixed_denominations !== false))
						return cb2("asset issued by AA definer cannot be private or fixed denominations");
					async.eachSeries(
						["is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested"],
						function (field, cb3) {
							if (typeof payload[field] === 'boolean')
								return cb3();
							if (typeof payload[field] === 'string') {
								var f = getFormula(payload[field]);
								if (f === null)
									return cb3("bad formula for " + field + " in asset");
								return cb3();
							}
							cb3(field + " is missing or of wrong type");
						},
						function (err) {
							if (err)
								return cb2(err);
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
						}
					);
					break;
```
