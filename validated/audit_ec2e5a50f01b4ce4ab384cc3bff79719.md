### Title
Missing Upper-Bound Validation on `timestamp`/`mci`/`age` Values in Asset `issue_condition`/`transfer_condition` Can Permanently Freeze Asset Transfers - (File: definition.js)

### Summary
When an asset issuer defines `issue_condition` or `transfer_condition` for a new asset, these definitions may contain `timestamp`, `mci`, or `age` comparison operators. The validator only checks that the comparison value is a non-negative integer, with no upper bound, allowing the issuer to set an astronomically large threshold. Because `issue_condition`/`transfer_condition` are immutable once the asset is defined and are evaluated on every subsequent issue/transfer for that asset, an unbounded value can permanently and irreversibly block issuance/transfer for all current and future holders of the asset — directly analogous to the reported `_shortStopTime`/`shortStopDuration` issue where an unvalidated, unbounded time parameter can render a process (repurchase) practically infeasible forever.

### Finding Description
In `definition.js`, the `validateDefinition` evaluator handles the `mci`/`age`/`timestamp` address/asset-condition operators: [1](#0-0) 

The only numeric check performed is `isNonnegativeInteger(value)` — there is no maximum bound comparable to something like a sane "few years from now" cap or a maximum `age`/`mci` delta. This validation path is explicitly reachable for **asset conditions** (`bAssetCondition=true`), not just ordinary address definitions.

`validateAssetDefinition` invokes exactly this validator for the asset's `issue_condition` and `transfer_condition` when *any* user defines a new asset (asset definition is an unprivileged, single-authored unit message open to any wallet): [2](#0-1) 

These conditions are persisted immutably with the asset (no update mechanism exists for `issue_condition`/`transfer_condition` after asset definition): [3](#0-2) 

Every subsequent issue or transfer of that asset re-evaluates the condition via `Definition.evaluateAssetCondition`, and if it fails, the payment is rejected outright: [4](#0-3) 

The `timestamp`/`mci` evaluation logic compares against `objValidationState.last_ball_timestamp`/`last_ball_mci`, which grow only with real DAG progress over time: [5](#0-4) 

Because `last_ball_timestamp` cannot be manipulated (it is bounded by real elapsed time via unit timestamp checks in `validate()`), an issuer who sets `['timestamp', ['>', <huge_value>]]` as the `transfer_condition` (or an unbounded `age` requirement) effectively creates a condition that can never be satisfied within any realistic timeframe, freezing transfers/issuance of the entire asset for every holder, not just the issuer.

### Impact Explanation
This is the asset-level equivalent of the reported bug: a single actor (the asset definer, an ordinary unprivileged unit poster) sets a time-based parameter that is used to gate an operation (here, transfer/issuance) affecting other parties (all asset holders), and the code fails to bound that value to a reasonable range. The result can be a de-facto permanent freeze of a public/tradeable asset's transferability, which is a fund-freezing condition that impacts every holder of the asset, not only the definer, and cannot be corrected afterward since `issue_condition`/`transfer_condition` are immutable.

### Likelihood Explanation
Any wallet can post an `asset` definition message (unprivileged, single-author unit) with a crafted `transfer_condition`/`issue_condition` containing an unbounded `timestamp`, `mci`, or `age` operator. No special privilege, hub cooperation, or network manipulation is required — it only requires passing `validateAssetDefinition`, which currently accepts any non-negative integer for these operators.

### Recommendation
Add explicit upper-bound checks in the `mci`/`age`/`timestamp` case of `validateDefinition` in `definition.js` (particularly when `bAssetCondition` is true), e.g., rejecting `timestamp` values far beyond a reasonable future horizon (mirroring the existing `max_seconds_into_the_future_to_accept` style bound used for unit timestamps), and capping `age`/`mci` deltas to a sane maximum number of blocks, so that asset conditions cannot be crafted to be practically unsatisfiable forever.

### Proof of Concept
1. Attacker (asset definer) submits an `asset` definition message with:
```
transfer_condition: ["timestamp", [">", 99999999999]]  // year ~5138, unreachable in this generation
```
2. `validateAssetDefinition` → `Definition.validateDefinition(conn, payload.transfer_condition, ..., true, cb)` passes because `99999999999` satisfies `isNonnegativeInteger(value)` with no upper bound (`definition.js` lines 480-495).
3. The asset is created and, per `writer.js` lines 218-228, `transfer_condition` is persisted immutably.
4. Every subsequent transfer of this asset by any holder calls `validatePaymentInputsAndOutputs` → `Definition.evaluateAssetCondition` (`validation.js` lines 2643-2658), which evaluates `timestamp > 99999999999` against `objValidationState.last_ball_timestamp`. Since real-world timestamps cannot reach this value for millennia, `bSatisfiesCondition` is always `false`, and every transfer is rejected with `"transfer or issue condition not satisfied"` — freezing the asset for all current and future holders indefinitely.

### Citations

**File:** definition.js (L480-495)
```javascript
			case 'mci':
			case 'age':
			case 'timestamp':
				if (!isArrayOfLength(args, 2) && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
					return cb(op + " must have 2 args");
				var relation = args[0];
				var value = args[1];
				if (!isNonemptyString(relation))
					return cb("no relation");
				if (["=", ">", "<", ">=", "<=", "!="].indexOf(relation) === -1)
					return cb("invalid relation: " + JSON.stringify(relation));
				if (!isNonnegativeInteger(value))
					return cb(op+" must be a non-neg number");
				if (op === 'timestamp' && objValidationState.last_ball_mci < constants.timestampUpgradeMci)
					return cb('timestamp op not allowed yet');
				return cb();
```

**File:** definition.js (L1036-1048)
```javascript
			case 'timestamp':
				var relation = args[0];
				var timestamp = args[1];
				switch(relation){
					case '>': return cb2(objValidationState.last_ball_timestamp > timestamp);
					case '>=': return cb2(objValidationState.last_ball_timestamp >= timestamp);
					case '<': return cb2(objValidationState.last_ball_timestamp < timestamp);
					case '<=': return cb2(objValidationState.last_ball_timestamp <= timestamp);
					case '=': return cb2(objValidationState.last_ball_timestamp === timestamp);
					case '!=': return cb2(objValidationState.last_ball_timestamp !== timestamp);
					default: throw Error('unknown relation in mci: '+relation);
				}
				break;
```

**File:** validation.js (L2643-2658)
```javascript
					function(cb){
						var arrCondition = bIssue ? objAsset.issue_condition : objAsset.transfer_condition;
						if (!arrCondition)
							return cb();
						Definition.evaluateAssetCondition(
							conn, payload.asset, arrCondition, objUnit, objValidationState, 
							function(cond_err, bSatisfiesCondition){
								if (cond_err)
									return cb(cond_err);
								if (!bSatisfiesCondition)
									return cb("transfer or issue condition not satisfied");
								console.log("validatePaymentInputsAndOutputs with transfer/issue conditions done");
								cb();
							}
						);
					}
```

**File:** validation.js (L2815-2827)
```javascript
	async.series([
		function(cb){
			if (!("issue_condition" in payload))
				return cb();
			Definition.validateDefinition(conn, payload.issue_condition, objUnit, objValidationState, null, true, cb);
		},
		function(cb){
			if (!("transfer_condition" in payload))
				return cb();
			Definition.validateDefinition(conn, payload.transfer_condition, objUnit, objValidationState, null, true, cb);
		}
	], callback);
}
```

**File:** writer.js (L218-228)
```javascript
						case "asset":
							var asset = message.payload;
							conn.addQuery(arrQueries, "INSERT INTO assets (unit, message_index, \n\
								cap, is_private, is_transferrable, auto_destroy, fixed_denominations, \n\
								issued_by_definer_only, cosigned_by_definer, spender_attested, \n\
								issue_condition, transfer_condition) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", 
								[objUnit.unit, i, 
								asset.cap, asset.is_private?1:0, asset.is_transferrable?1:0, asset.auto_destroy?1:0, asset.fixed_denominations?1:0, 
								asset.issued_by_definer_only?1:0, asset.cosigned_by_definer?1:0, asset.spender_attested?1:0, 
								asset.issue_condition ? JSON.stringify(asset.issue_condition) : null,
								asset.transfer_condition ? JSON.stringify(asset.transfer_condition) : null]);
```
