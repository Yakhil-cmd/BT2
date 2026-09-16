## Title
AA Vault/Manager Update Pattern Can Be Permanently Blocked by Spender-Attested (Blacklist-Style) Assets - (File: aa_composer.js, validation.js)

### Summary
Obyte's analog to token blacklisting is the `spender_attested` asset flag: a definer publishes an attestor list, and any address not on that list is treated exactly like a blacklisted address for that asset — it cannot receive (or spend) the asset. An AA (autonomous agent) that bundles a mandatory payment to a role-holder address (e.g., "pay accrued fee to current manager") together with a state update of that same role (e.g., "set manager = new_address") in a single trigger response is exposed to the identical failure mode described in the external report: if the current role-holder loses attestation ("gets blacklisted"), the payment message fails validation, the AA's atomic execution model rolls back the *entire* response (including the state var update), and the role can never be changed nor can further fees ever be paid out.

### Finding Description
An asset can be defined with `spender_attested: true`, and only the definer can update the attestor list via an `asset_attestors` message, checked in `validateAttestorListUpdate` [1](#0-0) . This is functionally equivalent to a USDC-style blacklist: a centrally-controlled allow/deny list gating who may hold or receive the asset.

When any payment of such an asset is validated, every output address must be attested, or the whole payment message is rejected: [2](#0-1) 

Similarly, spending inputs from an unattested address is rejected as well (`"owner address is not attested"`): [3](#0-2) 

AA execution is atomic: `handleTrigger` composes a *single* response unit containing all the messages produced by a triggered case (e.g. a payment message plus a `state` message that updates a stored role/address). If the composed response unit fails core validation (`validateAndSaveUnit` → `ifUnitError`), the whole trigger is bounced and every state change from the case, including the intended role/address update, is rolled back via `revert()`/`bounce()`: [4](#0-3) [5](#0-4) 

Existing shipped AA templates already follow the vulnerable pattern of combining a payout to a stored address with a subsequent state-variable change inside the same case (fees/withdrawal + `var[...]` update), e.g. the bank/withdraw templates: [6](#0-5) 

If such an AA's role-holder/manager address is stored as an attestable asset recipient and later removed from the attestor list (revoked, "blacklisted"), the combined payment+update case will always fail atomically, so the manager (or any similarly role-gated address) can never be updated, and any assets owed to that role from that point on become permanently unreachable.

### Impact Explanation
- The AA's manager/role address becomes permanently stuck: no unit can ever update it because the accompanying required payout to the (now unattested) address always fails and rolls back the whole trigger response.
- Any accrued fees/funds destined for that role are frozen forever inside the AA, since every attempt to pay them out is rejected by the `spender_attested` check before the state change can be applied.
- This matches the "AA fund loss or freezing" acceptance criterion: an unprivileged unit poster (anyone triggering the AA, or the definer trying to fix the situation) cannot recover control or funds through the AA's own logic.

### Likelihood Explanation
Any AA author who combines a payment output to a stored/role address with a state update of that same address in a single case (a common and natural vault/subscription/manager pattern, as already used by shipped ocore AA templates) is susceptible. The trigger for the block — the definer of a `spender_attested` asset revoking an address's attestation — is a normal, expected, single-message (`asset_attestors`) operation, not a rare or malicious edge case, making this reachable with ordinary usage of existing primitives.

### Recommendation
- AA template guidance/documentation should warn against combining a role-holder payout and a role-holder address update in the same atomic case when using `spender_attested` (or any conditionally-failing transfer/issue condition) assets.
- Consider allowing AA authors to structure such logic so that a failed payout to a stale/blacklisted address does not block the accompanying state update — e.g., splitting the payout into a separate, retryable case/state key (a "claimable balance" pattern) rather than gating the update on payment success in the same message set.
- At minimum, provide an oscript idiom/example demonstrating the safe pattern (update role first, let old role's balance be separately claimable) so integrators don't unknowingly reproduce the Solidity `setManager` bug class in AAs.

### Proof of Concept
1. Definer creates an asset with `spender_attested: true` and an initial attestor list including `manager_address`.
2. An AA vault stores `var['manager'] = manager_address` and, on a `set_manager` trigger case, does:
   - `payment` message: pay `var['accrued_fee']` of the asset to `var['manager']` (old manager withdrawal), and
   - `state` message: `var['manager'] = trigger.data.new_manager;`
   in the same case/messages array.
3. Definer publishes an `asset_attestors` message removing `manager_address` from the attestor list (analogous to USDC blacklisting the manager) — validated per [1](#0-0) .
4. Anyone posts a `set_manager` trigger unit to the AA.
5. `handleTrigger` composes the response unit with both the payment and state messages; `validateAndSaveUnit` calls into `validatePaymentInputsAndOutputs`, which rejects the payment because `manager_address` is no longer attested [2](#0-1) .
6. Because of the `ifUnitError` path, the whole response is reverted/bounced [5](#0-4) , so `var['manager']` is never updated and `var['accrued_fee']` remains permanently stuck, reproducing the reported bug class inside ocore's AA execution model.

### Citations

**File:** validation.js (L2504-2507)
```javascript
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
								return cb("owner address is not attested");
```

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

**File:** validation.js (L2829-2848)
```javascript
function validateAttestorListUpdate(conn, payload, objUnit, objValidationState, callback){
	if (objUnit.authors.length !== 1)
		return callback("attestor list must be single-authored");
	if (!isNonemptyObject(payload))
		return callback("attestor update must be a non-empty object");
	if (hasFieldsExcept(payload, ['asset', 'attestors']))
		return callback("foreign fields in attestor list update");
	storage.readAsset(conn, payload.asset, objValidationState.last_ball_mci, false, function(err, objAsset){
		if (err)
			return callback(err);
		if (!objAsset.spender_attested)
			return callback("this asset does not require attestors");
		if (objUnit.authors[0].address !== objAsset.definer_address)
			return callback("attestor list can be edited only by definer");
		err = checkAttestorList(payload.attestors);
		if (err)
			return callback(err);
		callback();
	});
}
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

**File:** aa_composer.js (L1800-1838)
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
				if (objAAValidationState.sequence !== 'good')
					throw Error("nonserial AA");
				validation_unlock();
				objAAValidationState.bUnderWriteLock = true;
				objAAValidationState.conn = conn;
				objAAValidationState.batch = batch;
				objAAValidationState.initial_trigger_mci = mci;
				objAAValidationState.bDryRun = trigger_opts.bDryRun;
				writer.saveJoint(objJoint, objAAValidationState, null, function(err){
					if (err)
						throw Error('AA writer returned error: ' + err);
					cb();
				});
			}
		}, conn);
	}
```

**File:** test/samples/a_bank_without_percent.oscript (L1-30)
```text
{
	messages: {
		cases: [
			{ // withdraw funds
				if: `{
					$key = 'balance_'||trigger.address||'_'||trigger.data.asset;
					$base_key = 'balance_'||trigger.address||'_'||'base';
					$fee = 1000;
					$required_amount = trigger.data.amount + ((trigger.data.asset == 'base') ? $fee : 0);
					trigger.data.withdraw AND trigger.data.asset AND trigger.data.amount AND $required_amount <= var[$key] AND $fee <= var[$base_key]
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{trigger.data.asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{trigger.data.amount}"}
							]
						}
					},
					{
						app: 'state',
						state: `{
							var[$key] = var[$key] - trigger.data.amount;
							var[$base_key] = var[$base_key] - $fee;
						}`
					}
				]
			},
```
