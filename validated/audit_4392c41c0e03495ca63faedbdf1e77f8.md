### Title
AA-issued asset `issue_condition`/`transfer_condition` are not validated against asset-condition policy, allowing structurally-invalid spend conditions - (File: aa_validation.js)

### Summary
When an Autonomous Agent (AA) posts a bounce-message that defines a new asset, `validateAADefinition()`'s `asset` case only checks that `issue_condition`/`transfer_condition` are 2-element arrays; it never runs them through `Definition.validateDefinition()` with `bAssetCondition=true`, unlike the equivalent path for ordinary (non-AA) asset-definition units.

### Finding Description
For a normal `asset` definition message, `validateAssetDefinition()` fully parses `issue_condition`/`transfer_condition` through `Definition.validateDefinition(conn, payload.issue_condition, objUnit, objValidationState, null, true, cb)`, which recursively walks every operator and enforces the asset-condition policy (e.g. rejecting `sig`, `hash`, `cosigned by`, `address`, and other authentication-style operators that must not appear in an asset condition) [1](#0-0) , with the actual per-operator policy enforced in `evaluate()` (e.g. `case 'sig': ... if (bAssetCondition) return cb("asset condition cannot have "+op);`) [2](#0-1) .

For an AA-issued `asset` message, `aa_validation.js` only performs a shallow structural check on `issue_condition`/`transfer_condition`: `if (!isArrayOfLength(payload.issue_condition, 2)) return cb2("wrong issue condition...")`, with no call into `Definition.validateDefinition`/`evaluate` at all [3](#0-2) . This mirrors the WebAuthn advisory's root cause: the server-side handler accepts the client (here, the AA definer/trigger sender)-supplied structure without validating it against the policy rules enforced elsewhere in the same codebase for the semantically identical operation.

This validation gap is confirmed by comparing the two call sites for `validateDefinition`, one with the asset-condition restrictions applied at definition time (`validation.js`) and one entirely bypassed (`aa_validation.js`).

### Impact Explanation
Because the asset-condition policy checks (disallowing `sig`, `hash`, `cosigned by`, `address`, and other operators inappropriate for a transfer/issue condition) are skipped for AA-defined assets, an AA definer can encode a malformed or policy-violating `issue_condition`/`transfer_condition` into the stored asset record via `storage.readAsset`/`writer.js`. Later, at actual payment time, `Definition.evaluateAssetCondition()` is invoked to decide whether a transfer/issue is authorized [4](#0-3) . If that evaluation path does not itself re-apply the `bAssetCondition` restrictions the way the validation-time `evaluate()` does, an attacker-controlled AA could smuggle in operators (e.g., `sig`/`cosigned by`) that were never checked for correctness (pubkey length, algo, etc.) at definition time, or malformed nested structures that behave unpredictably at evaluation time. This can lead to node disagreement on whether a transfer/issue condition is satisfied (validity/stability disagreement) or to conditions that unexpectedly pass/fail, enabling unauthorized transfer or issuance of the AA-defined asset.

### Likelihood Explanation
Any unprivileged AA author can trigger this by writing an AA `messages` array whose `asset` payload contains a crafted `issue_condition`/`transfer_condition`, and any user can then send a trigger causing the AA to emit that asset-definition bounce message — no special privileges or witness/oracle cooperation required, matching the "authenticated/unprivileged user manipulates client-controlled data" pattern from the advisory.

### Recommendation
In `aa_validation.js`'s `asset` case, route `payload.issue_condition` and `payload.transfer_condition` through the same `Definition.validateDefinition(conn, condition, objUnit, objValidationState, null, true, cb)` call (with `bAssetCondition=true`) used in `validateAssetDefinition()` in `validation.js`, instead of the shallow `isArrayOfLength` check, so AA-issued assets are held to the same policy as regular asset definitions.

### Proof of Concept
1. Deploy an AA whose `messages` include an `asset` message with `issue_condition: ["sig", {"pubkey": "<44-byte-b64>"}]` (an operator explicitly disallowed for asset conditions).
2. `validateAADefinition()` accepts this AA definition because it only checks `isArrayOfLength(payload.issue_condition, 2)` [5](#0-4) , whereas the same structure submitted via a plain `asset` definition unit would be rejected by `Definition.validateDefinition` with `"asset condition cannot have sig"` [6](#0-5) .
3. Trigger the AA so it emits the asset-definition bounce message; the malformed condition is persisted for the asset.
4. Any later transfer/issue of that asset is checked via `Definition.evaluateAssetCondition` [4](#0-3) , which is now evaluating an operator/structure that was never validated for correctness or policy compliance — behavior at this stage was not fully traceable within index limits, so exact exploitation mechanics (crash vs. bypass vs. fork) should be confirmed by tracing `Definition.evaluateAssetCondition`'s implementation directly in the repository.

### Citations

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

**File:** validation.js (L2815-2826)
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
```

**File:** definition.js (L235-251)
```javascript
			case 'sig':
				if (bInNegation)
					return cb(op+" cannot be negated");
				if (bAssetCondition)
					return cb("asset condition cannot have "+op);
				if (!isNonemptyObject(args))
					return cb(op + " args must be a non-empty object");
				if (hasFieldsExcept(args, ["algo", "pubkey"]))
					return cb("unknown fields in "+op);
				if (args.algo === "secp256k1")
					return cb("default algo must not be explicitly specified");
				if ("algo" in args && args.algo !== "secp256k1")
					return cb("unsupported sig algo");
				if (!isStringOfLength(args.pubkey, constants.PUBKEY_LENGTH))
					return cb("wrong pubkey length");
				return cb(null, true);
				
```

**File:** aa_validation.js (L289-296)
```javascript
					if ("issue_condition" in payload) {
						if (!isArrayOfLength(payload.issue_condition, 2))
							return cb2("wrong issue condition: " + JSON.stringify(payload.issue_condition));
					}
					if ("transfer_condition" in payload) {
						if (!isArrayOfLength(payload.transfer_condition, 2))
							return cb2("wrong transfer condition: " + JSON.stringify(payload.transfer_condition));
					}
```
