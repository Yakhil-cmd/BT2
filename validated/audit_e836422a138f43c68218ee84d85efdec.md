### Title
Malicious asset attestor revocation lets an attacker permanently DoS an AA's payment response and freeze legitimate co-bundled asset payouts - (File: `aa_composer.js`, `validation.js`)

### Summary
An attacker can fund an Autonomous Agent (AA) with a self-issued, `spender_attested` asset and later revoke the attestor list for that asset. Because AA responses bundle all `payment` messages (across multiple assets) into a single response unit, a permanently-failing payment of the malicious asset causes the entire response unit — including unrelated, legitimate payments to other users/assets accrued in the same trigger — to bounce forever, mirroring the reported Mantra DEX issue where aggregating rewards into one `BankMsg::Send` lets a malicious tokenfactory denom brick withdrawal of legitimate rewards.

### Finding Description
When an AA composes a response, `sendUnit()` collects every `payment` message the oscript produced (potentially spanning several assets) into one unit and validates/saves it as a whole: [1](#0-0) 

If `validateAndSaveUnit` fails for any reason, the function calls `bounce(err)`, discarding the *entire* unit, i.e. all payment messages contained in it, not just the offending one: [2](#0-1) 

One of the validation checks that can fail is the `spender_attested` requirement on an asset: the payment's output addresses must be on the asset's current attestor list, which is queried fresh (latest stable list) at the time the AA payment is validated: [3](#0-2) [4](#0-3) 

Crucially, the attestor list is **mutable after the asset is created** and can be updated at will, at any time, exclusively by the asset's own `definer_address` (i.e. the attacker who issued the malicious asset): [5](#0-4) 

Exploit flow, directly analogous to the Mantra report:
1. Attacker defines an asset with `spender_attested: true` and includes themself/anyone as an initial attestor so the asset can be funded into a victim AA (e.g. a farm/reward AA that lets pool creators supply arbitrary reward assets, or any generic "distribute what I hold" AA).
2. Attacker deposits this asset into the AA as a "reward"/balance, alongside legitimate assets already tracked for other users.
3. Attacker publishes a new `asset_attestors` unit for their asset that removes all attestors (or removes the addresses the AA will pay to), using their exclusive definer privilege.
4. When any user triggers the AA to claim/withdraw, the AA's response bundles the (now-poisoned) malicious-asset payout together with the user's legitimate payouts into one unit. `validatePaymentInputsAndOutputs`'s `spender_attested` check fails ("some output addresses are not attested"), and `bounce(err)` discards the whole response — the legitimate payouts bundled in the same unit are lost/stuck, and this repeats on every subsequent trigger since the failure condition (attacker-controlled attestor list) never resolves.

This is the same class of bug as the Mantra finding: aggregating a heterogeneous set of asset payouts into a single atomic operation, where one asset's transfer preconditions are controlled by an untrusted, externally-fundable asset issuer, lets that issuer permanently poison the batch.

### Impact Explanation
Any AA design that (a) accepts externally-defined/fundable assets as part of its balance/reward accounting and (b) bundles payouts of multiple assets/users into a single triggered response is vulnerable to permanent denial of service: legitimate users' bytes/asset rewards become permanently un-claimable once bundled alongside a poisoned asset, and because `bounce()` reverts all AA state changes for the trigger via `revert()`/`ROLLBACT TO SAVEPOINT`, there is no partial success — the AA can be left unable to ever again complete that code path. This is a fund-freezing/loss-of-funds impact matching the "Medium/High" criteria (AA fund loss or freezing).

### Likelihood Explanation
Likelihood is moderate-to-high for any publicly-composable AA (DEX, farm, marketplace, escrow) that lets third parties supply the asset used for payouts, since `spender_attested` asset creation and later `asset_attestors` updates are both permissionless, standard, low-cost operations available to any address, and the AA oscript author has no way to prevent a currently-tracked asset from becoming un-payable later — the check is only evaluated at payout time, using the *latest* stable attestor list.

### Recommendation
- AA authors should avoid bundling a single user's or trigger's payouts across multiple heterogeneous, externally-controlled assets into one atomic response; instead, isolate risky/attacker-suppliable assets into separate trigger-driven withdrawal paths so failure of one does not block others.
- Where an AA must hold externally-issued assets, treat `spender_attested` assets specially: verify attestation status at the time of *accepting* the deposit is not sufficient — the AA logic should re-check `asset[...]` conditions or provide an admin/self-serve "abandon poisoned asset" mechanism (e.g., skip/void unpayable balances) instead of aborting the whole response.
- Consider documenting/warning in the oscript AA guidelines that `spender_attested`/`transfer_condition` assets funded by third parties can be weaponized to DoS bundled payment responses, and recommend defensive patterns (per-asset separate response units, try/catch style isolation via secondary triggers) for reward/farm-style AAs.

### Proof of Concept
1. Attacker publishes an `asset` definition with `spender_attested: true`, `is_transferrable: true`, and an initial attestor list containing the AA and/or attacker address (satisfies `validateAssetDefinition`/`validateAttestorListUpdate` preconditions).
2. Attacker sends a trigger to a victim reward-distribution AA, depositing this asset as a funded "reward" for a pool/farm that other users also have legitimate claims against (assets get merged into the AA's balance and internal accounting, per `updateInitialAABalances`/`updateFinalAABalances` in `aa_composer.js`).
3. Attacker submits a follow-up single-authored `asset_attestors` unit (only they, as `definer_address`, are authorized per `validateAttestorListUpdate`) that empties or changes the attestor list so no relevant recipient address is attested.
4. A legitimate user triggers the AA's claim/withdraw logic; the oscript emits one response unit containing both the legitimate payout and the poisoned-asset payout. `validatePaymentInputsAndOutputs`'s `spender_attested` branch fails with "some output addresses are not attested" for the malicious asset's output, `sendUnit()` calls `bounce(err)`, and the whole response — including the user's legitimate reward — is rejected and the AA reverts to pre-trigger state.
5. Since the attacker's attestor list stays empty, every future trigger that would emit this bundled payment permanently bounces, freezing legitimate funds inside the AA.

### Citations

**File:** aa_composer.js (L1247-1288)
```javascript
		for (var i = 0; i < messages.length; i++){
			var message = messages[i];
			if (!isNonemptyObject(message))
				return bounce("message must be nonempty object");
			if (ValidationUtils.hasFieldsExcept(message, ['app', 'payload']))
				return bounce("unknown fields in message");
			if (typeof message.app !== 'string')
				return bounce("app must be a string");
			if (!aa_validation.aaApps.includes(message.app))
				return bounce("unsupported app: " + message.app);
			if (!['string', 'object'].includes(typeof message.payload) || message.payload === null)
				return bounce("payload must be string or object");
			if (message.app !== 'payment')
				continue;
			var payload = message.payload;
			if (!isNonemptyObject(payload))
				return bounce("payload must be nonempty object");
			if (ValidationUtils.hasFieldsExcept(payload, ['asset', 'outputs']))
				return bounce("unknown fields in payment payload");
			if (!Array.isArray(payload.outputs))
				return bounce("outputs must be array"); // empty array is okay
			if (!payload.outputs.every(o => ValidationUtils.isValidAddress(o.address)))
				return bounce("invalid addresses in outputs");
			if (payload.outputs.some(o => ValidationUtils.hasFieldsExcept(o, ['address', 'amount'])))
				return bounce("unknown fields in outputs");
			if ('asset' in payload && !(payload.asset === 'base' || ValidationUtils.isStringOfLength(payload.asset, constants.HASH_LENGTH)))
				return bounce("asset must be a string or omitted");
			// negative or fractional
			if (!payload.outputs.every(function (output) { return (isNonnegativeInteger(output.amount) || output.amount === undefined); }))
				return bounce("negative or fractional amounts");
			// filter out 0-outputs
			payload.outputs = payload.outputs.filter(function (output) { return (output.amount > 0 || output.amount === undefined); });
		}
		// remove messages with no outputs
		messages = messages.filter(function (message) { return (message.app !== 'payment' || message.payload.outputs.length > 0); });
		if (messages.length === 0) {
			error_message = 'no messages after removing 0-outputs';
			console.log(error_message);
			return handleSuccessfulEmptyResponseUnit(null);
		}
		if (mci >= constants.pemCurvesFixMci)
			messages = mergeMessagesAndOutputs(messages);
```

**File:** aa_composer.js (L1405-1411)
```javascript
						executeStateUpdateFormula(objUnit, function (err) {
							if (err)
								return bounce(err);
							validateAndSaveUnit(objUnit, function (err) {
								if (err)
									return bounce(err);
								updateFinalAABalances(arrConsumedOutputs, objUnit, function () {
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

**File:** validation.js (L2829-2847)
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
```

**File:** storage.js (L1917-1946)
```javascript
		function addAttestorsIfNecessary(byAA = false){
			if (!objAsset.spender_attested)
				return handleAsset(null, objAsset);

			// find latest list of attestors
			const before_last_ball_cond = byAA ? "" : `AND main_chain_index<=${+last_ball_mci} AND is_stable=1`;
			conn.query(
				"SELECT unit FROM asset_attestors CROSS JOIN units USING(unit) \n\
				WHERE asset=? " + before_last_ball_cond + " AND sequence='good' ORDER BY "+ (conf.bLight ? "units.rowid" : "level") + " DESC LIMIT 1",
				[asset],
				function (latest_rows) {
					if (latest_rows.length === 0)
						throw Error("no latest attestor list");
					var latest_attestor_list_unit = latest_rows[0].unit;

					// read the list
					conn.query(
						"SELECT attestor_address FROM asset_attestors CROSS JOIN units USING(unit) \n\
						WHERE asset=? AND unit=? " + before_last_ball_cond + " AND sequence='good'",
						[asset, latest_attestor_list_unit],
						function (att_rows) {
							if (att_rows.length === 0)
								throw Error("no attestors?");
							objAsset.arrAttestorAddresses = att_rows.map(function (att_row) { return att_row.attestor_address; });
							handleAsset(null, objAsset);
						}
					);
				}
			);
		}
```
