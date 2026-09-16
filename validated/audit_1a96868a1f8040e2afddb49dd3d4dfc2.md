### Title
AA multi-party settlement can be permanently blocked by an unattested output address in a `spender_attested` asset - ([File: validation.js])

### Summary
An Autonomous Agent (AA) that settles funds between two or more parties in a single atomic response (e.g., paying one party while returning funds/collateral to another) can be made to bounce indefinitely if the debt/settlement asset is `spender_attested` and one of the intended recipients loses eligibility with (or is never attested by) the asset's attestor(s). This mirrors the reported bug class: a token-level access-control feature (blacklist/whitelist) controlled by a third party can block an entire atomic transfer that should benefit an uninvolved counterparty.

### Finding Description
When an asset is defined with `spender_attested: true`, every output address in a payment of that asset must be attested by one of the asset's designated attestors, or the whole payment message is rejected: [1](#0-0) 

This check is applied to `outputs` collectively — if even a single output address in the payment is not (or no longer) covered by a fresh/valid attestation, `validatePaymentInputsAndOutputs` returns `"some output addresses are not attested"` and the whole payment message fails validation: [2](#0-1) 

An AA that composes a payment message with several outputs (e.g., one output going to a counterparty being repaid, another returning residual funds/collateral to the trigger's address) builds and validates this unit inside `sendUnit()`/`completePaymentPayload()`/`validateAndSaveUnit()`: [3](#0-2) 

If `validateAndSaveUnit` fails for any reason — including the attestor-based check above — the failure propagates as an error into `bounce(err)`: [4](#0-3) 

`bounce()` reverts all state changes for the primary trigger and, at best, refunds only the bounce fee back to the triggering address — it does not attempt to complete a partial/alternate distribution to the other legitimate party: [5](#0-4) 

`revert()` additionally rolls back to the savepoint and clears any state var changes made so far before bouncing: [6](#0-5) 

Because `spender_attested` requires ALL output addresses of a message to be attested, and attestation of a given address is entirely controlled by external attestor addresses named in the asset definition (`asset.attestors`) as validated in `validateAssetDefinition`/`checkAttestorList`, an attestor can effectively act as the "blacklisting" entity from the original report: refusing (or delaying) to attest one party's address blocks the entire combined payment from that AA, exactly as USDC's blacklist blocked `repay()` from completing in the original finding. [7](#0-6) [8](#0-7) 

### Impact Explanation
Any AA-based lending/escrow/settlement design built on a `spender_attested` asset that pays multiple parties in one atomic unit is exposed: as long as one recipient is not attested, the AA can never send the response, so the party who should legitimately receive their share (collateral return, change, repayment) is denied it, while the AA's balance for that asset/base becomes stuck (only bounce fees are recycled). This is a fund-freezing condition reachable purely by a normal AA trigger sender combined with an attestor (or the target address itself, if it can choose not to seek/renew attestation) refusing to cooperate — no privileged node/hub/peer role is required.

### Likelihood Explanation
This requires (1) an AA design that uses a `spender_attested` asset to move funds to more than one address in a single response, and (2) at least one recipient address lacking a valid attestation from the asset's attestor set. Both are realistic and foreseeable in real AAs (KYC/whitelisted stablecoins, permissioned tokens) built on top of ocore, and the attestor/party controlling attestation of their own or a counterparty's address can trigger the block deliberately, similar to a lender purposely getting blacklisted in the original report.

### Recommendation
When an AA must pay multiple independent parties using a `spender_attested` (or otherwise conditionally-transferable) asset, avoid bundling all outputs into a single atomic payment message whose failure reverts every party's transfer. Instead, split logically-independent transfers into separate messages/units where feasible, or design the AA to detect an unattested recipient ahead of time (e.g., via the `attested` oscript condition) and reroute/queue that portion separately (e.g., credit it to a claimable balance) rather than aborting the entire settlement.

### Proof of Concept
1. Define an asset `attestor_asset` with `spender_attested: true` and attestor address `X` per `validateAssetDefinition` (validation.js:2725-2755) and `checkAttestorList` (validation.js:2850-2864).
2. Deploy an AA that, on trigger, sends a single `payment` message with two outputs of `attestor_asset`: one to `partyA` (e.g., loan repayment) and one to `partyB` (e.g., collateral/change return), built via `sendUnit`/`completePaymentPayload` (aa_composer.js:1043-1139, 1245-1429).
3. Ensure `partyB`'s address has never been attested by `X` (or `X` refuses to attest it).
4. Trigger the AA: `validatePaymentInputsAndOutputs` rejects the payment with `"some output addresses are not attested"` (validation.js:2630-2641) because not all output addresses are attested.
5. `validateAndSaveUnit`'s error propagates to `bounce(err)` (aa_composer.js:1405-1411, 909-945), reverting all state changes; `partyA` never receives their legitimate share, and the AA's funds for that asset remain stuck pending `partyB`'s attestation.

### Citations

**File:** validation.js (L2630-2642)
```javascript
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
```

**File:** validation.js (L2745-2755)
```javascript
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
```

**File:** validation.js (L2850-2864)
```javascript
function checkAttestorList(arrAttestors){
	if (!isNonemptyArray(arrAttestors))
		return "attestors not defined";
	if (arrAttestors.length > constants.MAX_ATTESTORS_PER_ASSET)
		return "too many attestors";
	var prev="";
	for (var i=0; i<arrAttestors.length; i++){
		if (!isValidAddress(arrAttestors[i]))
			return "invalid attestor address: "+JSON.stringify(arrAttestors[i]);
		if (arrAttestors[i] <= prev)
			return "attestors not sorted";
		prev = arrAttestors[i];
	}
	return null;
}
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

**File:** aa_composer.js (L1405-1424)
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
									fixStateVars();
									addResponse(objUnit, function () {
										updateStorageSize(function (err) {
											if (err)
												return revert(err);
											handleSecondaryTriggers(objUnit, arrOutputAddresses);
										});
									});
								});
							});
						});
```

**File:** aa_composer.js (L1759-1798)
```javascript
	function revert(err) {
		console.log('will revert: ' + err);
		if (bSecondary)
			return bounce(err);
		if (!trigger_opts.bAir)
			revertResponsesInCaches(arrResponses);
		
		// copy all logs
		var logs = [];
		arrResponses.forEach(objAAResponse => {
			if (objAAResponse.logs)
				logs = logs.concat(objAAResponse.logs);
		});
		if (logs.length > 0)
			objValidationState.logs = logs;
		
		arrResponses.splice(0, arrResponses.length); // start over
		if (trigger_opts.bAir)
			return bounce(err);
		Object.keys(stateVars).forEach(function (address) { delete stateVars[address]; });
		batch.clear();
		conn.query("ROLLBACK TO SAVEPOINT initial_balances", function () {
			console.log('done revert: ' + err);
			bounce(err);
		});
		/*
		conn.query("ROLLBACK", function () {
			conn.query("BEGIN", function () {
				// initial AA balances were rolled back, we have to add them again
				if (!fPrepare)
					fPrepare = function (cb) { cb(); };
				fPrepare(function () {
					updateInitialAABalances(function () {
						console.log('done revert: ' + err);
						bounce(err);
					});
				});
			});
		});*/
	}
```
