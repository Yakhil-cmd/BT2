## Title
AA payment messages to multiple recipients fail atomically when one recipient loses attestation via a self-triggered `address_definition_change`, freezing all funds for other parties — ([File: validation.js])

### Summary
The Sherlock report describes a `Stream` contract where `cancel()` reverts entirely because the `recipient`'s USDC transfer fails (blacklist), freezing the `payer`'s share too, since there is no isolated try/catch per transfer. In ocore, the equivalent atomicity hazard exists for AAs that pay out a `spender_attested` (or `transfer_condition`-restricted) asset to multiple addresses inside one response unit: if any single output address becomes "unattested" for reasons the recipient fully controls, the whole response unit — including the payer's/other party's own output — fails to validate and the AA response bounces, reverting all state changes with no way to isolate or retry the failing leg.

### Finding Description
When an AA composes a response containing a `payment` message for a `spender_attested` asset with outputs to more than one address (e.g. an escrow/exchange AA settling or refunding two counterparties in one unit), `validatePaymentInputsAndOutputs` checks **all** output addresses together: [1](#0-0) 

`filterAttestedAddresses` treats an address as attested only if a valid attestation exists **after** the address's most recent `address_definition_change`: [2](#0-1) 

This means any address holder can make themselves "unattested" at will and unprivileged, simply by posting an `address_definition_change` for their own address (e.g. key rotation) — no attestor cooperation is required. Once that happens, any subsequent AA-composed payment to that address for the `spender_attested` asset fails with `"some output addresses are not attested"`, or with `"transfer or issue condition not satisfied"` if a `transfer_condition` is used instead: [3](#0-2) 

Because ocore composes the entire AA response as a single unit and validates it atomically, this single failing output causes `validateAndSaveUnit` to fail for the whole unit, which triggers `bounce()`: [4](#0-3) 

`bounce()`/`revert()` restore all state variables and AA balances to their pre-trigger values, discarding whatever computation the AA performed (e.g. crediting the well-behaved party's share), and only returns the *trigger's own* deposited coins (minus bounce fee) back to the trigger address — not the amounts the AA logic intended to pay to other output addresses: [5](#0-4) [6](#0-5) 

There is no per-output try/catch or isolation mechanism in oscript/AA message composition analogous to what the report recommends for Solidity — a single restricted recipient blocks the entire atomic unit.

### Impact Explanation
Any AA that distributes a `spender_attested` (or condition-restricted) asset to multiple parties within one response (escrow release, marketplace settlement, subscription refund, dividend/airdrop-style payout, etc.) can be permanently deadlocked by one counterparty. That counterparty (acting entirely within their rights, e.g. rotating keys) can make their own output fail the attestation/condition check, which reverts the *entire* unit and freezes the funds the AA was going to pay to the other, non-malicious party as well — with no way for that other party to recover their share, since the AA's internal state was rolled back to before the payout attempt. This is a fund-freezing condition reachable purely by an unprivileged AA trigger sender / asset counterparty, matching the Medium-severity impact class of the original report (payer unable to retrieve their fair share, funds stuck permanently).

### Likelihood Explanation
The precondition — the AA definer choosing to build an escrow/exchange/settlement AA around a `spender_attested` or `transfer_condition`-gated asset that pays multiple output addresses in one message — is a common and encouraged design pattern (assets with attestation/whitelisting requirements are a first-class ocore feature meant for exactly this use case). Triggering the freeze requires only an ordinary `address_definition_change`, an action any address owner can perform unilaterally at any time, making exploitation straightforward and requiring no privileged access.

### Recommendation
- For AAs that must pay several parties for a conditioned/attested asset, split the payout into separate atomic units/triggers per recipient (e.g. via secondary AA triggers) rather than a single multi-output payment message, so that one recipient's failure does not block the others.
- Alternatively, extend AA/oscript semantics to allow a payment message to optionally continue (skip the failing output, refunding/holding it in state) rather than failing the entire unit when one output fails an asset-level condition check, mirroring the try/catch isolation recommended in the original report.
- Document this atomicity hazard clearly for asset/AA authors using `spender_attested` or `transfer_condition` so they avoid combining multiple independent counterparties' outputs for such assets in a single response message.

### Proof of Concept
1. Asset `X` is defined with `spender_attested: true` and a list of attestors (`asset_attestors` message) — a normal, unprivileged asset feature: [7](#0-6) .
2. An escrow AA holds deposits of asset `X` from `payer` and, on a "cancel"/"settle" trigger, composes a single `payment` message with two outputs: one to `payer`, one to `recipient`.
3. `recipient`, at any point before triggering settlement, posts an `address_definition_change` for their own address (e.g., ordinary key rotation) — a fully permissionless action.
4. Per `filterAttestedAddresses`, `recipient`'s prior attestation is now invalidated because it predates the definition change: [2](#0-1) .
5. `payer` triggers the AA's cancel/settle function. `validatePaymentInputsAndOutputs` finds `recipient` unattested and rejects the whole payment message: [8](#0-7) .
6. `validateAndSaveUnit` fails, `bounce()` fires, all AA state changes (including the `payer`'s intended payout) are rolled back, and only the trigger's own bounce-fee-adjusted deposit is returned to the trigger address — not the `payer`'s owed share held in AA state: [4](#0-3) [9](#0-8) .
7. `payer` has no way to retrigger a successful settlement as long as `recipient`'s address remains unattested (which `recipient` fully controls), permanently freezing `payer`'s funds inside the AA.

### Citations

**File:** validation.js (L2630-2641)
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

**File:** validation.js (L2725-2733)
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
```

**File:** storage.js (L1959-1974)
```javascript
// filter only those addresses that are attested (doesn't work for light clients)
function filterAttestedAddresses(conn, objAsset, last_ball_mci, arrAddresses, handleAttestedAddresses){
	conn.query(
		"SELECT DISTINCT address FROM attestations CROSS JOIN units USING(unit) \n\
		WHERE attestor_address IN(?) AND address IN(?) AND main_chain_index<=? AND is_stable=1 AND sequence='good' \n\
			AND main_chain_index>IFNULL( \n\
				(SELECT main_chain_index FROM address_definition_changes JOIN units USING(unit) \n\
				WHERE address_definition_changes.address=attestations.address AND main_chain_index<=? AND is_stable=1 AND sequence='good' ORDER BY main_chain_index DESC LIMIT 1), \n\
			0)",
		[objAsset.arrAttestorAddresses, arrAddresses, last_ball_mci, last_ball_mci],
		function(addr_rows){
			var arrAttestedAddresses = addr_rows.map(function(addr_row){ return addr_row.address; });
			handleAttestedAddresses(arrAttestedAddresses);
		}
	);
}
```

**File:** aa_composer.js (L909-944)
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

**File:** aa_composer.js (L1671-1700)
```javascript
	function finish(objResponseUnit) {
		if (bBouncing && bSecondary) {
			if (objResponseUnit)
				throw Error('response_unit with bouncing a secondary AA');
			if (!bAddedResponse && objValidationState.logs) // add the logs from the final bouncing unit
				arrResponses.push({ logs: objValidationState.logs });

			if (typeof error_message === 'string') {
				error_message = { message: error_message };
			}

			let errorObj = { address };
			if (error_message.address) {
				errorObj.next = error_message;
			} else {
				errorObj = { ...errorObj, ...error_message };
			}
			return onDone(null, errorObj);
		}
		fixStateVars();
		saveStateVars();
		addResponse(objResponseUnit, function () {
			updateStorageSize(function (err) {
				if (err)
					return revert(err);
				addUpdatedStateVarsIntoPrimaryResponse();
				onDone(objResponseUnit, bBouncing ? error_message : false);
			});
		});
	}
```

**File:** aa_composer.js (L1759-1783)
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
```
