### Title
Missing "capped assets must be issued_by_definer_only" constraint in AA asset definitions allows unbounded multi-address issuance of a "capped" asset - ([File: aa_validation.js])

### Summary
When an autonomous agent (AA) defines a new asset via an `asset` message, `aa_validation.js` fails to enforce the invariant that capped assets must set `issued_by_definer_only: true`. This invariant is enforced for normal (non-AA) asset definitions in `validation.js`, but the equivalent check is absent in `aa_validation.js`'s `case 'asset':` block. Because the divisible-payment issuance logic in `validation.js` only restricts issuance uniqueness to a single global issuer when `issued_by_definer_only` is true, an AA-defined capped asset with `issued_by_definer_only: false` allows an unbounded number of distinct addresses to each independently issue a full "cap"-sized amount of the asset, inflating total supply far beyond the stated cap.

### Finding Description
For ordinary asset definitions, `validateAssetDefinition` explicitly rejects capped assets that are not restricted to definer-only issuance: [1](#0-0) 

This rule exists because the payment-validation double-spend/uniqueness logic for `issue` inputs treats a capped asset as safe from multi-issuance only by relying on a single, well-known issuer (the definer). Specifically, in `validatePaymentInputsAndOutputs`, for a capped asset the `serial_number` must be `1`: [2](#0-1) 

and the amount must equal the cap exactly: [3](#0-2) 

But the double-spend key that prevents the *same* issue from being repeated only includes the issuer `address` when the asset is **not** `issued_by_definer_only`: [4](#0-3) 

This means that when `issued_by_definer_only` is `false`, uniqueness of `serial_number=1` issuance is scoped per-address rather than globally per-asset — every distinct address is free to submit its own `type: "issue"` input with `serial_number=1` and `amount === cap`, and each will be accepted as a distinct, non-conflicting issuance. The corresponding authorization check in `validatePayment` only blocks non-definer issuance when `issued_by_definer_only` is true: [5](#0-4) 

so when it's false, **any address** can be an issuer.

For normal user-submitted `asset` definitions, this dangerous combination (`cap` set but `issued_by_definer_only` false) is explicitly forbidden by the check cited above (`validation.js:2802-2803`). However, `aa_validation.js`'s `case 'asset':` block, which validates `asset` messages inside AA definitions, performs cap-type and format checks but never checks the relationship between `cap` and `issued_by_definer_only`: [6](#0-5) 

Because an AA is an "unprivileged unit poster" from the perspective of anyone who defines it (any user can post an AA definition unit containing an `asset` message), an attacker can craft an AA whose `asset` message sets `cap: <N>` and `issued_by_definer_only: false` (with `is_transferrable`/other required boolean fields set appropriately) and get it accepted by consensus, since `aa_validation.js` does not reject this combination. Once the asset exists, any subsequent, unprivileged unit author can post a `payment` message that issues the capped amount using their own address as the issuer, and repeat this from further fresh addresses, since each address's issuance is treated as independent by the double-spend check.

### Impact Explanation
This is a direct analog of the Stellar inflation bug in the report: a validation gap allows the creation of asset supply beyond its declared, intended cap. Any address can mint a full "cap" worth of the asset repeatedly (one full cap per distinct address used), leading to unconstrained supply inflation for any AA-defined capped asset that uses `issued_by_definer_only: false`. This can be used to devalue or manipulate markets/contracts that rely on the stated cap as a scarcity guarantee (e.g., AA-based DeFi/AMM contracts, ICOs), directly causing token holders' economic loss and breaking the fundamental "capped supply" invariant that downstream AAs and oscript logic (e.g., `asset[...].cap` checks) depend on.

### Likelihood Explanation
Exploitation requires only: (1) posting an AA definition unit containing an `asset` message with `cap` set and `issued_by_definer_only: false` — a standard, unprivileged action available to any user; and (2) after the AA is triggered/deployed and the asset is defined, posting ordinary `payment` messages of type `issue` from arbitrary addresses. No special privileges, witness/hub collusion, or timing/race conditions are needed — this is achievable by any regular network participant, making it a Medium-to-High likelihood defect once the missing check is understood, since it is a straightforward, repeatable path in unit/AA validation logic.

### Recommendation
Add the same constraint enforced in `validation.js:2802-2803` to `aa_validation.js`'s `case 'asset':` block: reject the AA `asset` payload if `cap` is present (or a cap-producing formula is used) while `issued_by_definer_only` is not explicitly `true` (or evaluates to `true` at execution). Additionally, consider hardening `validatePaymentInputsAndOutputs` so that the double-spend uniqueness of `serial_number=1` for any `cap`-bearing asset is always scoped globally per-asset (not per-address), independent of `issued_by_definer_only`, to eliminate this class of issue entirely regardless of how the asset was defined (AA-based or not).

### Proof of Concept
1. Compose and post an AA definition unit whose definition includes an `asset` message:
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
`aa_validation.js` accepts this definition because it never checks the `cap`/`issued_by_definer_only` relationship (contrast with `validation.js:2802-2803`, which would reject the same combination for a plain, non-AA asset definition).
2. Trigger the AA so the asset gets defined (obtaining `asset` = the AA response unit hash per existing test patterns, e.g. `test/aa_composer.test.js:450-526` for defining/issuing AA-owned assets).
3. From address A, post a `payment` message for this `asset` with `inputs: [{type:"issue", amount:1000000, serial_number:1}]` and `outputs:[{address:A, amount:1000000}]`. This validates successfully per `validatePaymentInputsAndOutputs` (amount equals cap, serial_number=1, address A is not restricted since `issued_by_definer_only` is false).
4. From a different address B, repeat step 3 with the same asset, `serial_number:1`, `amount:1000000`, output to B. Because `doubleSpendWhere` includes `address=?` (validation.js:2370-2373) when `issued_by_definer_only` is false, this issuance from B does not collide with A's issuance and is also accepted.
5. Repeat with addresses C, D, ... N — each successfully issues another `1000000` units, inflating total supply to `N × 1000000`, far beyond the declared `cap` of `1000000`. [7](#0-6) [1](#0-0) [8](#0-7) [9](#0-8)

### Citations

**File:** validation.js (L2109-2111)
```javascript
			if (objAsset.issued_by_definer_only && issuer_address !== objAsset.definer_address)
				return callback("only definer can issue this asset");
		}
```

**File:** validation.js (L2321-2373)
```javascript
					if (!objAsset || objAsset.cap){
						if (input.serial_number !== 1)
							return cb("for capped asset serial_number must be 1");
					}
					if (bIssue)
						return cb("only one issue per message allowed");
					bIssue = true;
					
					var address = null;
					if (arrAuthorAddresses.length === 1){
						if ("address" in input)
							return cb("when single-authored, must not put address in issue input");
						address = arrAuthorAddresses[0];
					}
					else{
						if (typeof input.address !== "string")
							return cb("when multi-authored, must put address in issue input");
						if (arrAuthorAddresses.indexOf(input.address) === -1)
							return cb("issue input address "+input.address+" is not an author");
						address = input.address;
					}
					
					arrInputAddresses = [address];
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

**File:** validation.js (L2802-2803)
```javascript
	if (payload.cap && !payload.issued_by_definer_only)
		return callback("if capped, must be issued by definer only");
```

**File:** aa_validation.js (L225-336)
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

					if ("issue_condition" in payload) {
						if (!isArrayOfLength(payload.issue_condition, 2))
							return cb2("wrong issue condition: " + JSON.stringify(payload.issue_condition));
					}
					if ("transfer_condition" in payload) {
						if (!isArrayOfLength(payload.transfer_condition, 2))
							return cb2("wrong transfer condition: " + JSON.stringify(payload.transfer_condition));
					}
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
