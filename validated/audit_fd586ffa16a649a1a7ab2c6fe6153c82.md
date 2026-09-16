### Title
Malicious asset with a controllable `transfer_condition` can force an AA to bounce its entire payout, freezing all bundled assets/bytes for the recipient - (File: `aa_composer.js`)

### Summary
When an Autonomous Agent (AA) responds to a trigger by sending several payment messages (base bytes plus one or more custom assets) in the same response unit, `sendUnit()` builds **one single unit** containing all of these messages and validates/saves it atomically. If validation of *any* one of the payment messages fails — e.g. because an attacker-controlled asset's `transfer_condition` evaluates to `false` — the whole unit is rejected and the AA "bounces" the trigger, so **none** of the outputs (including unrelated, legitimate assets/bytes) are ever paid out. This is the same bug class as the external report: an attacker-supplied token whose transfer reverts blocks the claimant from receiving the other, unrelated funds bundled in the same transaction.

### Finding Description
`sendUnit()` merges all outgoing payment messages of an AA response into a single `objUnit`, including any custom assets the AA is set up to disburse alongside bytes: [1](#0-0) 

That single unit, containing all asset/byte payments together, is passed once to `validateAndSaveUnit()`: [2](#0-1) 

`validateAndSaveUnit()` calls the normal unit validator; any error for **any** message in the unit results in `ifUnitError`, which propagates back as a single `err` to the whole `sendUnit()` flow and triggers `bounce(err)`: [3](#0-2) 

During validation, for each non-fixed-denomination, non-private custom asset payment, the asset's `transfer_condition` (or `issue_condition`) is evaluated, and if it does not hold, that message — and therefore the entire unit — is rejected: [4](#0-3) 

An asset issuer fully controls the `transfer_condition` expression at asset-definition time (an oscript boolean expression, commonly referencing a data feed/oracle they control): [5](#0-4) 

Because `sendUnit()` bundles all payment messages (bytes + every custom asset the AA is paying out) into one atomic unit, an attacker who: (1) gets their asset with a maliciously flip-able `transfer_condition` deposited into/held by an AA (e.g. a vault/bounty/exchange-style AA that on a trigger pays a user in several assets at once), and (2) flips their oracle/condition to `false` at the moment the AA tries to pay out, can force `validateAndSaveUnit` to fail for the whole response unit. The AA then bounces, and the intended recipient receives **none** of the bundled payment — not even the unrelated, legitimate assets or bytes — for that trigger.

### Impact Explanation
This causes AA fund freezing/denial for legitimate users: a single poisoned asset (whose transfer condition is entirely controlled by an attacker-issuer) can be used to indefinitely block payout of all other bundled assets/bytes in the same AA response, as long as the AA's logic keeps trying to disburse that asset together with the rest in one response unit. This matches the "AA fund loss or freezing" impact class — the AA can neither deliver the legitimate funds to the intended recipient nor exclude the malicious asset without a design/logic change, since validation failure of one payment message bounces the entire unit.

### Likelihood Explanation
Any AA design that (a) accepts deposits or definitions of arbitrary assets and (b) later pays out several assets/bytes together in a single response — a common and encouraged pattern for bounty/vault/marketplace/exchange AAs — is exposed. The attacker only needs to be the issuer of an asset with a conditionally-controllable `transfer_condition`/`issue_condition` (fully permitted by `aa_validation.js`) and get it included among the assets an AA will pay out to a target address, then flip the condition at payout time.

### Recommendation
- When an AA response bundles multiple asset payments into one unit, isolate the failure of any single asset's transfer condition so it does not block the payout of the other assets/bytes — e.g., split multi-asset payouts into separate response units per asset (as already technically possible via `handleSecondaryTriggers`/self-triggering) rather than merging all payment messages unconditionally.
- Alternatively, when composing the response unit in `sendUnit()`, pre-validate/pre-check each asset's `transfer_condition` for the specific outputs before merging it with unrelated assets, and drop/skip only the failing asset's message (with logged error) instead of bouncing the entire unit.

### Proof of Concept
1. Attacker defines an asset `M` with `transfer_condition` referencing a data feed they control, e.g. `["in data feed", {oracles:[attacker_oracle], feed_name:"allow", feed_value:1, ...}]`.
2. Attacker funds a target AA (e.g., a vault/bounty AA) with asset `M` together with legitimate bytes/assets, in a way the AA's payout logic will later try to send `M` together with the legitimate funds back to a claimant in one response (`messages` array containing multiple `payment` app entries as processed in `aa_composer.js:1298-1345`).
3. When the claimant triggers the payout, attacker posts a data feed unit setting `allow=0` (or simply never sets `allow=1`), causing `Definition.evaluateAssetCondition` to return `bSatisfiesCondition=false` for asset `M`'s message (`validation.js:2643-2659`).
4. `validateAndSaveUnit` fails for the whole response unit (`aa_composer.js:1405-1413`), causing `bounce(err)`; the claimant receives none of the bundled bytes/assets, even though only asset `M` was malicious.

### Citations

**File:** aa_composer.js (L1298-1345)
```javascript
		async.eachSeries(
			messages,
			function (message, cb) {
				if (message.app !== 'payment') {
					try {
						if (message.app === 'definition')
							message.payload.address = objectHash.getChash160(message.payload.definition);
						completeMessage(message);
					}
					catch (e) { // may error if there are empty objects or arrays inside
						return cb("some hashes failed: " + e.toString());
					}
					return cb();
				}
				var payload = message.payload;
				if (payload.asset === 'base')
					delete payload.asset;
				var asset = payload.asset || null;
				if (asset === null) {
					if (objBasePaymentMessage)
						return cb("already have base payment");
					objBasePaymentMessage = message;
					// we'll add output addresses later, after possibly removing a send-all output
					return cb(); // skip it for now, we can estimate the fees only after all other messages are in place
				}
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
					completePaymentPayload(payload, 0, function (err) {
						if (err)
							return cb(err);
						addOutputAddresses(payload.outputs);
						if (payload.outputs.length > 0) // send-all output might get removed while being the only output
							try {
								completeMessage(message);
							}
							catch (e) {
								return cb("completeMessage failed: " + e.toString());
							}
						cb();
					});
				});
			},
```

**File:** aa_composer.js (L1405-1413)
```javascript
						executeStateUpdateFormula(objUnit, function (err) {
							if (err)
								return bounce(err);
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
								updateFinalAABalances(arrConsumedOutputs, objUnit, function () {
									if (arrOutputAddresses.length === 0)
										return finish(objUnit);
```

**File:** aa_composer.js (L1800-1822)
```javascript
	function validateAndSaveUnit(objUnit, cb) {
		var objJoint = { unit: objUnit, aa: true, aa_mci: mci };
		validation.validate(objJoint, {
			ifJointError: function (err) {
				throw Error("AA validation joint error: " + err);
			},
			ifUnitError: function (err) {
				console.log("AA validation unit error: " + err);
				return cb(err);
			},
			ifTransientError: function (err) {
				throw Error("AA validation transient error: " + err);
			},
			ifNeedHashTree: function () {
				throw Error("AA validation unexpected need hash tree");
			},
			ifNeedParentUnits: function (arrMissingUnits) {
				throw Error("AA validation unexpected dependencies: " + arrMissingUnits.join(", "));
			},
			ifOkUnsigned: function () {
				throw Error("AA validation returned ok unsigned");
			},
			ifOk: function (objAAValidationState, validation_unlock) {
```

**File:** validation.js (L2643-2659)
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
				], callback);
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
