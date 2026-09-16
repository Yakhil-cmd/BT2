### Title
Non-transferable / condition-restricted assets can permanently trap AA funds with no valid response or bounce path - ([File: aa_composer.js])

### Summary
The Autonomous Agent (AA) engine assumes any asset it receives can either be paid out to arbitrary counterparties or, at worst, bounced back to the trigger sender. Ocore's native asset system, however, allows an asset definer to attach arbitrary `is_transferrable`, `transfer_condition`, and `issue_condition` restrictions to an asset [1](#0-0) . `aa_composer.js` only special-cases `is_private` and `fixed_denominations` assets before composing outgoing payments [2](#0-1) ; it never checks `is_transferrable`/`transfer_condition` before building a response, relying instead on the later full-unit validation to catch it. Combined with the single-shot bounce mechanism (`bBouncing` flag), a specially crafted asset can make both the primary response and the fallback bounce payment fail asset-condition validation, so the AA silently keeps the funds with `finish(null)` and never produces any unit at all.

### Finding Description
When an AA composes an outgoing payment for a non-base asset, it loads the asset and only rejects it if it is private; everything else (including `is_transferrable=false` or a `transfer_condition`/`issue_condition`) is passed straight into `completePaymentPayload` and only discovered when the fully composed unit is run through `validateAndSaveUnit` [3](#0-2) . That call invokes full unit validation, which enforces `is_transferrable` and `transfer_condition`/`issue_condition` for the asset [4](#0-3) . If the asset restricts transfers to only the definer address (or requires a condition that the AA's own logic cannot satisfy — e.g. `attested`, `has definition change`, or address-based `sig` conditions that only the asset issuer controls), any AA payment message carrying that asset fails validation and `bounce(err)` is invoked [5](#0-4) .

The `bounce()` function is designed to run only once per trigger: it sets `bBouncing = true` and then attempts to construct a refund payment sending the same restricted asset back to `trigger.address` [6](#0-5) . If that refund itself is invalid under the very same `is_transferrable`/`transfer_condition` rule (which is likely, since `trigger.address` is generally neither the asset definer nor an address satisfying an issuer-controlled condition), `sendUnit()` fails again and calls `bounce(err)` a second time. But the guard `if (bBouncing) return finish(null);` at the top of `bounce()` [7](#0-6)  now short-circuits: no messages are sent, `finish(null)` is called, and the AA simply records an empty/bounced response with no response unit — the trigger's payment inputs, which were already spent into the AA's address by the (valid, already-stable) trigger unit, remain stuck at the AA address with no code path in `aa_composer.js` ever able to move them out again (every future attempt hits the same `is_transferrable`/condition check in `validatePaymentInputsAndOutputs`).

This mirrors the external report's core concern about "specially designed"/malicious tokens defeating a contract's static-balance assumptions: here, the AA's payment-composition logic assumes any asset balance it holds can eventually be moved (to the intended recipient or, failing that, bounced back to the sender), but ocore's flexible, permissionless asset-definition system (`validateAssetDefinition`, allowing arbitrary `transfer_condition`/`issue_condition`/`is_transferrable=false`) lets any user craft an asset that violates this assumption for every possible AA-generated payment.

### Impact Explanation
Any AA that accepts payments in an asset it does not control (a very common pattern — swap/DEX AAs, pools, bonding curves, bridges, oracles paid in custom tokens) can have funds permanently frozen inside its address once a user (attacker or unaware party) pays it with an asset whose `transfer_condition`/`is_transferrable` restrictions the AA cannot satisfy. Because both the intended payout and the bounce fallback are asset-transfer messages subject to the identical condition, the funds become unrecoverable through any AA logic — a permanent AA fund freeze. This satisfies the "AA fund loss or freezing" impact bucket.

### Likelihood Explanation
Any address (not just AA definers) can create arbitrary assets with `transfer_condition`/`issue_condition`/`is_transferrable=false` restrictions using a normal single-authored `asset` message, with no privileged role required [1](#0-0) ; nothing in the AA framework whitelists which assets an AA is willing to receive. An attacker can register such an asset and then send a trigger unit paying that asset into a target AA that has any payment-out logic touching non-base assets. This is directly reachable by an unprivileged poster of an ordinary unit (creating an asset) followed by another unit (the AA trigger) — no special network position, node, or operator privilege is needed.

### Recommendation
- Before composing any outgoing payment message for a non-base asset, `aa_composer.js` should pre-check `is_transferrable`, and evaluate `transfer_condition`/`issue_condition` against the intended recipient(s) using the same logic as `Definition.evaluateAssetCondition`, bouncing early (before consuming the single bounce attempt) if the condition cannot be satisfied.
- Make the bounce fallback asset-aware: when the primary response fails specifically due to an asset-condition violation for one asset, drop only that asset from the bounce payment (as is already partially done for insufficient-fee assets) rather than aborting the whole bounce and losing the ability to refund the remaining assets/bytes.
- Consider tracking "stuck" balances per asset/AA explicitly (e.g., exposing them via `getAAStuckBalances` or similar) so AAs/tools can detect and react to non-transferable-asset deposits instead of silently absorbing them.
- Document prominently (and validate at AA-authoring time) that AAs interacting with arbitrary user-specified assets must anticipate `is_transferrable=false` / conditioned assets, and provide an oscript-level primitive to query these asset properties before accepting/relying on them (partial support exists via `asset[...]` getters as seen in `test/aa_composer.test.js:368-448`, but AA authors are not forced to use it, and the composer itself performs no defensive check).

### Proof of Concept
1. Attacker publishes an `asset` definition unit with `is_transferrable: false, issued_by_definer_only: true, cap: <N>` (or alternatively a `transfer_condition` requiring `["attested", ...]` by an attestor the attacker controls) — this passes `validateAssetDefinition` unmodified [8](#0-7) .
2. Attacker issues units of this asset to themselves (issuer == definer, so issuance succeeds).
3. Attacker sends a trigger unit to a target AA (any AA whose oscript composes a payment message forwarding/paying out a received non-base asset, e.g. a generic swap/pool template) including this restricted asset as part of `trigger.outputs`.
4. Inside `handleTrigger`, the AA logic composes a payment message sending the restricted asset to some third-party address (the swap counterparty). `sendUnit()` proceeds through `completePaymentPayload` (no rejection, since only `is_private`/`fixed_denominations` are pre-checked) and reaches `validateAndSaveUnit`, which fails with `"the asset is not transferrable"` per `validation.js:2616-2628`.
5. `bounce(err)` is invoked; it attempts to refund the asset to `trigger.address`, which is neither the definer nor the attestor-approved address, so this refund payment again fails the same check inside `sendUnit`, calling `bounce()` a second time.
6. The `if (bBouncing) return finish(null);` guard fires, `finish(null)` is called, and the AA response is recorded with no response unit produced — the restricted asset amount deposited by the trigger unit remains permanently held at the AA's address, unreachable by any subsequent AA-generated payment for the same reason.

(Note: due to indexing limits, the exact `bounce_fees` handling for non-base assets and edge cases around `mergeMessagesAndOutputs` were not fully traced line-by-line; a live Devin session with full repo/test access is recommended to construct and run an executable AVA test reproducing steps 3–6 end-to-end and confirm the exact balance-freezing outcome.)

### Citations

**File:** validation.js (L2613-2659)
```javascript
			if (objAsset){
				if (total_input !== total_output)
					return callback("inputs and outputs do not balance: "+total_input+" !== "+total_output);
				if (!objAsset.is_transferrable){ // the condition holds for issues too
					if (arrInputAddresses.length === 1 && arrInputAddresses[0] === objAsset.definer_address
					   || arrOutputAddresses.length === 1 && arrOutputAddresses[0] === objAsset.definer_address
						// sending payment to the definer and the change back to oneself
					   || !(objAsset.fixed_denominations && objAsset.is_private) 
							&& arrInputAddresses.length === 1 && arrOutputAddresses.length === 2 
							&& arrOutputAddresses.indexOf(objAsset.definer_address) >= 0
							&& arrOutputAddresses.indexOf(arrInputAddresses[0]) >= 0
					   ){
						// good
					}
					else
						return callback("the asset is not transferrable");
				}
				async.series([
					function(cb){
						if (!objAsset.spender_attested)
							return cb();
						storage.filterAttestedAddresses(
							conn, objAsset, objValidationState.last_ball_mci, arrOutputAddresses, 
							function(arrAttestedOutputAddresses){
								if (arrAttestedOutputAddresses.length !== arrOutputAddresses.length)
									return cb("some output addresses are not attested");
								cb();
							}
						);
					},
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

**File:** validation.js (L2725-2803)
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

	if (objValidationState.bAA) {
		if (payload.cosigned_by_definer !== false)
			return callback("cosigned_by_definer must be false because AAs can't cosign");
		if (payload.issued_by_definer_only === true && (payload.is_private !== false || payload.fixed_denominations !== false))
			return callback("assets issued by AA definer cannot be private or fixed denominations");
	}

	// attestors
	var err;
	if ( payload.spender_attested && (err=checkAttestorList(payload.attestors)) )
		return callback(err);
	if (!payload.spender_attested && "attestors" in payload && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
		return callback("attestors should not be defined when spender_attested is false");

	// denominations
	if (payload.fixed_denominations && !isNonemptyArray(payload.denominations))
		return callback("denominations not defined");
	if (!payload.fixed_denominations && "denominations" in payload)
		return callback("denominations should not be defined when fixed");
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
	
	if (payload.is_private && payload.is_transferrable && !payload.fixed_denominations)
		return callback("if private and transferrable, must have fixed denominations");
	if (payload.is_private && !payload.fixed_denominations){
		if (!(payload.auto_destroy && !payload.is_transferrable))
			return callback("if private and divisible, must also be auto-destroy and non-transferrable");
	}
	if (payload.is_private && ("issue_condition" in payload || "transfer_condition" in payload) && (objValidationState.last_ball_mci >= constants.noPrivateAssetsWithConditionsUpgradeMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.noPrivateAssetsWithConditionsUpgradeMci))
		return callback("if private, cannot have issue or transfer conditions");
	if (payload.cap && !payload.issued_by_definer_only)
		return callback("if capped, must be issued by definer only");
```

**File:** aa_composer.js (L909-945)
```javascript
	var bBouncing = false;
	function bounce(error) {
		console.log('bouncing with error', error, new Error().stack);
		objStateUpdate = null;
		error_message = error_message ? (error_message + ', then ' + error) : error;
		if (trigger_opts.bAir) {
			assignObject(stateVars, originalStateVars); // restore state vars
			assignObject(trigger_opts.assocBalances, originalBalances); // restore balances
			if (!bSecondary) {
				for (let a in trigger.outputs)
					if (bounce_fees[a])
						trigger_opts.assocBalances[address][a] = (trigger_opts.assocBalances[address][a] || 0) + bounce_fees[a];
			}
		}
		if (bBouncing)
			return finish(null);
		bBouncing = true;
		if (bSecondary)
			return finish(null);
		if ((trigger.outputs.base || 0) < bounce_fees.base)
			return finish(null);
		var messages = [];
		// iteration order is standardized since ECMAScript 2020
		for (var asset in trigger.outputs) {
			var amount = trigger.outputs[asset];
			var fee = bounce_fees[asset] || 0;
			if (fee > amount)
				return finish(null);
			if (fee === amount)
				continue;
			var bounced_amount = amount - fee;
			messages.push({app: 'payment', payload: {asset: asset, outputs: [{address: trigger.address, amount: bounced_amount}]}});
		}
		if (messages.length === 0)
			return finish(null);
		sendUnit(messages);
	}
```

**File:** aa_composer.js (L1323-1330)
```javascript
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
```

**File:** aa_composer.js (L1405-1410)
```javascript
						executeStateUpdateFormula(objUnit, function (err) {
							if (err)
								return bounce(err);
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
```
