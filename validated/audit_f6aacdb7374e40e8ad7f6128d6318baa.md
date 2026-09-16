## Title
AA-defined assets bypass the cap/denominations consistency check enforced on user-defined assets - ([File: aa_validation.js])

### Summary
`validateAssetDefinition()` in `validation.js` enforces a strict invariant for any `asset` message: if `fixed_denominations`/`denominations` are used together with `cap`, the sum of `count_coins * denomination` across all capped denominations must exactly equal `cap` [1](#0-0) . This invariant is depended upon later by the indivisible-asset issuance code, which assumes `count_coins` is set precisely when `cap` is set (`if (!!row.count_coins !== !!objAsset.cap) throw Error("invalid asset cap and count_coins")`) [2](#0-1) .

However, when an Autonomous Agent (AA) defines an asset via a `message.app === 'asset'` template, the definition is checked by a *different* validator, `validateAADefinition()`'s `case 'asset':` block in `aa_validation.js`. That block validates `cap` and `denominations` independently (including allowing them to be dynamic formulas), but never cross-checks that the sum of capped `count_coins * denomination` equals `cap` [3](#0-2) . This is analogous to the ext4 bug class: an invariant that is enforced on one code path (mount/definition path A) but silently assumed and relied upon elsewhere without being validated on another reachable path (path B, here AA-authored asset definitions), where formulas make the mismatch reachable only at evaluation time.

### Finding Description
For ordinary (non-AA) `asset` messages, `validateAssetDefinition()` walks `payload.denominations`, sums `count_coins * denomination` for every capped denomination into `total_cap_from_denominations`, and rejects the unit unless this total exactly equals `payload.cap` [4](#0-3) .

For AA-defined assets, `aa_validation.js`'s `validateAADefinition()` handles the `'asset'` message type entirely differently: `cap` and each `denominations[i].denomination` / `count_coins` may each independently be a number or an oscript formula string (evaluated later, at trigger-execution time) [5](#0-4) . No equivalent "cap must equal sum of denominations' count_coins*denomination" check exists anywhere in this block, nor is one visible at the point the AA-generated `asset` message is finally emitted as a real unit in `aa_composer.js` (`handleTrigger` only sorts `denominations`/`attestors` before calling `sendUnit(messages)`, it does not re-validate cap-vs-denominations consistency) [6](#0-5) .

Because `cap`, `denomination`, and `count_coins` can each be independent oscript formulas evaluated using AA state variables / trigger data / balances at execution time, an AA author can construct an asset definition where the formulas evaluate to a `cap` that does not match the sum of `count_coins * denomination` for the resulting `denominations` array — a combination that would be rejected outright for a normal user-composed asset, but sails through the AA-specific validator.

### Impact Explanation
`indivisible_asset.js`'s issuance path assumes this invariant unconditionally as a runtime `throw Error` rather than a validation-time rejection: `if (!!row.count_coins !== !!objAsset.cap) throw Error("invalid asset cap and count_coins")` [2](#0-1) . More importantly, `issue_amount = count_coins_to_issue * denomination` is computed purely from `asset_denominations` table rows without ever re-checking against `objAsset.cap` [7](#0-6) , and the network-wide double-issue guard in `validation.js` for capped assets relies on `serial_number` uniqueness assuming `cap` correctly bounds total issuable supply (`for capped asset serial_number must be 1`, `issue must be equal to cap`) [8](#0-7) . If an AA can create a fixed-denomination, capped asset where the true issuable supply (sum of denomination*count_coins) exceeds the advertised `cap` used elsewhere for accounting/display/formula evaluation (`asset[$asset].cap` in oscript, read via `asset[]` evaluation returning `objAsset.cap`) [9](#0-8) , this results in a supply-inflation-class inconsistency: the effective circulating cap diverges from the value nodes and AAs treat as the asset's cap, which can be leveraged for unauthorized over-issuance of an asset beyond its stated cap or AA fund-accounting errors that lead to fund loss/freezing for AAs that trust `asset[..].cap`.

### Likelihood Explanation
Reachable by any unprivileged AA author: an AA definition is posted by any wallet, and an AA can define an `asset` message with `cap`, `fixed_denominations: true`, and `denominations` all specified as formulas, none of which are cross-validated for consistency at definition time. This requires no special privilege, hub, or node compromise — only crafting a normal AA and triggering it, matching the "AA definitions and triggers" and "asset issuance and transfer conditions" reachable-surface criteria.

### Recommendation
Add the same consistency check used in `validateAssetDefinition()` (`validation.js` lines 2757-2791) to the `'asset'` case of `validateAADefinition()` in `aa_validation.js`: when both `cap` and `denominations` are static (non-formula) values, verify `total_cap_from_denominations === cap`; and additionally re-validate this invariant at the point the final `asset` message is emitted/evaluated after formulas are resolved to concrete numbers (e.g., in `aa_composer.js` before `sendUnit`, or as part of the normal unit `validate()` path that all response units still traverse), so that a mismatch causes the AA response to bounce rather than being written with an inconsistent cap/denomination configuration.

### Proof of Concept
1. Define an AA whose `messages` include an `app: 'asset'` message with `fixed_denominations: true`, `cap: 1000`, and `denominations: [{denomination: 1, count_coins: 2000}]` — i.e., `count_coins * denomination` (2000) intentionally exceeds `cap` (1000), or use formulas such as `cap: "{trigger.data.cap}"` and `count_coins: "{trigger.data.count}"` so the mismatch is only realized at execution time with attacker-supplied trigger data.
2. `validateAADefinition()`'s `case 'asset':` block accepts this definition because it never sums `count_coins * denomination` against `cap` [3](#0-2) , unlike `validateAssetDefinition()` used for regular units [1](#0-0) .
3. Trigger the AA; it emits the `asset` message which is written to the `assets`/`asset_denominations` tables via `writer.js` without re-checking the invariant [10](#0-9) .
4. Subsequent issuance in `indivisible_asset.js` issues coins based on `count_coins * denomination` (2000), while any code/oscript that reads `asset[asset].cap` reports 1000, creating an inconsistency between advertised cap and actually issuable/circulating supply that can be exploited by other AAs or wallets that trust the `cap` field for accounting.

### Citations

**File:** validation.js (L2321-2352)
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
```

**File:** validation.js (L2757-2791)
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
```

**File:** indivisible_asset.js (L530-532)
```javascript
					var row = rows[0];
					if (!!row.count_coins !== !!objAsset.cap)
						throw Error("invalid asset cap and count_coins");
```

**File:** indivisible_asset.js (L533-536)
```javascript
					var denomination = row.denomination;
					var serial_number = row.max_issued_serial_number+1;
					var count_coins_to_issue = row.count_coins || Math.floor((remaining_amount+tolerance_plus)/denomination);
					var issue_amount = count_coins_to_issue * denomination;
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

**File:** aa_composer.js (L1878-1885)
```javascript
			messages.forEach(function (message) {
				var payload = message.payload;
				if (message.app === 'asset' && isNonemptyArray(payload.denominations) && payload.denominations.every(d => isNonemptyObject(d) && ValidationUtils.isPositiveInteger(d.denomination)))
					payload.denominations.sort(sortDenominations);
				if ((message.app === 'asset' || message.app === 'asset_attestors') && isNonemptyArray(payload.attestors) && payload.attestors.every(ValidationUtils.isValidAddress))
					payload.attestors.sort();
			});
			sendUnit(messages);
```

**File:** formula/evaluation.js (L1553-1556)
```javascript
							if (objAsset.sequence !== "good")
								return cb(false);
							if (field === 'cap') // can be null
								return cb(convertValue(objAsset.cap || 0));
```

**File:** writer.js (L218-242)
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
							if (asset.attestors){
								for (var j=0; j<asset.attestors.length; j++){
									conn.addQuery(arrQueries, 
										"INSERT INTO asset_attestors (unit, message_index, asset, attestor_address) VALUES(?,?,?,?)",
										[objUnit.unit, i, objUnit.unit, asset.attestors[j]]);
								}
							}
							if (asset.denominations){
								for (var j=0; j<asset.denominations.length; j++){
									conn.addQuery(arrQueries, 
										"INSERT INTO asset_denominations (asset, denomination, count_coins) VALUES(?,?,?)",
										[objUnit.unit, asset.denominations[j].denomination, asset.denominations[j].count_coins]);
								}
							}
```
