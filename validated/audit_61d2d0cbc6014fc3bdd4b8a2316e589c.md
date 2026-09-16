## Title
`spender_attested` asset attestor-list changes can permanently freeze AA-held asset funds when a bounce/refund payment is attempted - (File: `aa_composer.js`)

### Summary
The external report describes a case where a smart-contract's cancel/refund path unconditionally sends a restricted token back to a fixed recipient, and reverts (permanently trapping the accounted funds) if that recipient has since become blacklisted by the token's transfer-restriction mechanism. ocore has a structurally identical mechanism: assets can be defined with `spender_attested: true`, requiring every payment **input and output address** to be currently attested by the asset's (definer-controlled) attestor list. An Autonomous Agent (AA) that receives such an asset from a trigger, and later needs to send it back to the trigger's address (either as an explicit refund/business-logic message or via the AA engine's automatic bounce mechanism), performs exactly the kind of "send-to-fixed-recipient" operation that fails if the recipient is no longer attested.

### Finding Description
An asset can require every output address (not only inputs) to be attested at the time of transfer: [1](#0-0) 

Attestation status is derived from the *currently active* attestor list for the asset, which the asset **definer** can fully replace at any time via an `asset_attestors` message (only the definer can update it): [2](#0-1) 

The active attestor list used to determine "is X attested" is always the *latest* one, so if the definer publishes a new attestor list (or drops an attestor), addresses attested only under a prior list stop counting as attested immediately — functionally identical to blacklisting an address: [3](#0-2) [4](#0-3) 

When an AA receives a `spender_attested` asset in `trigger.outputs`, the AA engine's automatic bounce logic loops over *every* asset the trigger sent (not just base bytes) and tries to send it straight back to `trigger.address`: [5](#0-4) 

If composing/validating that bounce payment fails validation — e.g. because `trigger.address` is no longer attested per the (possibly since-changed) attestor list — `sendUnit` invokes `bounce(err)` again. But `bounce()` guards against re-entrant bouncing: [6](#0-5) 

Since `bBouncing` is already `true` on the first failed bounce attempt, the second call to `bounce()` short-circuits straight to `finish(null)`, ending the AA response with **no messages sent at all** and no state reverted for the already-committed initial balances update. The asset amount that was credited to the AA's balance from the trigger unit is never returned and there is no other code path to reclaim it — the AA's own business logic (e.g., an explicit refund message targeting `trigger.address`) hits the identical `validatePaymentInputsAndOutputs` check and bounces the same way, so no combination of subsequent triggers from the same untrusted-again address can recover the funds through the normal payment/bounce mechanism.

This mirrors the reported bug class precisely: a token-level, issuer-controlled "restriction list" (`asset_attestors` playing the role of `TransferRestrictor`'s blacklist) that a legitimate refund/cancel code path unconditionally targets at a fixed recipient, causing the transfer — and therefore the entire settlement/refund — to permanently fail once that recipient falls outside the current allow-list.

### Impact Explanation
Funds (asset units) that a user legitimately sent to an AA can become permanently stuck in that AA's balance, unrecoverable by the user or anyone else, once the asset's attestor list changes such that the user's original sending address is no longer attested. This is an AA fund-freezing condition reachable purely through routine, non-malicious asset administration (attestor rotation) combined with a single ordinary AA trigger — no compromised keys or privileged network position required from the affected user. Given ocore's design intentionally allows `spender_attested` assets to be used inside AAs (validated explicitly in `aa_validation.js`), this is a realistic configuration, not a contrived edge case.

### Likelihood Explanation
Any AA that accepts a `spender_attested` asset as payment (a supported, validated pattern) is exposed. The trigger only needs to be a legitimate user sending such an asset to the AA; the freezing condition is then latent until the asset's definer updates the attestor list (a normal administrative action for such assets, e.g. compliance-gated tokens) before the AA processes a bounce or explicit refund for that address. No attacker action against the AA itself is required — the failure is deterministic given the described attestor-list state.

### Recommendation
- In the AA-engine bounce logic (`aa_composer.js`), do not attempt to bounce assets whose `spender_attested`/output-address restrictions cannot be satisfied; instead, keep such assets accounted in the AA balance in a way that is explicitly recoverable later (e.g., skip that asset in the bounce loop rather than aborting the whole response), or expose the "recipient may become unattested" risk clearly to AA authors.
- AA authors using `spender_attested` assets should be advised (and ideally the validation/documentation should warn) that hardcoding `trigger.address` as an unconditional refund destination for such assets can cause fund freezing if attestation is revoked between receipt and refund.
- Consider allowing partial/best-effort bounce responses so a single un-attested asset does not cause the entire bounce (and thus recovery of unrelated bytes/assets) to be silently dropped via the `bBouncing` re-entrancy guard.

### Proof of Concept
1. Definer creates asset `A` with `spender_attested: true` and an initial attestor list including attestor `T1`; `T1` attests address `U`.
2. `U` sends a payment of asset `A` to AA `X`, whose logic (or the engine's default bounce) is set up to eventually send asset `A` back to `trigger.address` (e.g., a swap/vault AA that refunds on certain conditions).
3. Before `X` processes the refund/bounce, the definer publishes a new `asset_attestors` message removing `T1` (or replacing the list), so `U` is no longer counted as attested per `storage.readAsset`'s "latest attestor list" logic.
4. `X` receives a further trigger (or automatically bounces) and attempts to send asset `A` back to `U`. `validatePaymentInputsAndOutputs` rejects the unit with "some output addresses are not attested" (`validation.js:2637-2638`).
5. `sendUnit` calls `bounce(err)`; since `bBouncing` is already `true` from the first bounce attempt, `finish(null)` is invoked, ending AA execution with no response and no reversal of the already-applied balance credit — asset `A` amount is permanently stuck in AA `X`'s balance.

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

**File:** aa_composer.js (L909-927)
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
```

**File:** aa_composer.js (L928-944)
```javascript
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
