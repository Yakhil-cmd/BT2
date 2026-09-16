### Title
Asset attestor-list update fully replaces (not extends) the attestor set, permanently freezing previously‑attested holders' unspent asset outputs - ([File: storage.js], [File: validation.js])

### Summary
For assets with `spender_attested=true`, the current, "authoritative" attestor list is determined by reading only the single latest `asset_attestors` unit and using **its** attestor set — the pre‑existing attestors from earlier `asset` / `asset_attestors` messages are discarded entirely rather than merged. Because the asset definer is free to post a new `asset_attestors` message that omits addresses present in the previous list, any coin holder who was legitimately attested under the old (now superseded) list becomes permanently unable to spend their existing, unspent outputs of that asset, even though nothing they did was invalid. This mirrors the reported bug class: a list that downstream fund-accounting/authorization logic depends on can be silently shrunk, and the system has no mechanism to reconcile balances/rights that were valid under the old list state.

### Finding Description
`storage.readAsset()` resolves the attestor list for an asset by finding the **most recent** `asset_attestors` unit and reading only the attestors recorded in that single unit: [1](#0-0) 

```
// find latest list of attestors
...
WHERE asset=? ... ORDER BY ... level DESC LIMIT 1
...
objAsset.arrAttestorAddresses = att_rows.map(...)
```

There is no accumulation across successive `asset_attestors` messages — each new message is a full replacement of the effective attestor set. `checkAttestorList()` (the sole validation applied to a new attestor list) only requires the array to be non-empty, sorted, and contain valid addresses; it does not require the new list to be a superset of the previous one, and `validateAttestorListUpdate()` only checks that the message is single-authored by the asset definer: [2](#0-1) 

This resolved `arrAttestorAddresses` is then used to compute which addresses are currently "attested" for the asset via `filterAttestedAddresses` / `loadAssetWithListOfAttestedAuthors`: [3](#0-2) 

That derived `arrAttestedAddresses` gates the ability to spend or receive the asset in every payment that involves it — for issuing: [4](#0-3) 

for spending an existing input (owner must still be attested): [5](#0-4) 

and for receiving an output: [6](#0-5) 

Because the asset definer (an in-scope, unprivileged-relative-to-holders actor — merely the original asset issuer) can at any time post a new `asset_attestors` message that drops one or more previously-listed attestor addresses, any coin holder whose attestation came only from an attestor no longer on the list instantly loses the ability to spend the coins they are already legitimately holding. The coins are not lost to the definer or anyone else — they become permanently frozen/unspendable, exactly analogous to the reported bug where removing an entry from a list that downstream logic depends on for correct accounting causes real economic harm that the protocol has no mechanism to compensate for.

### Impact Explanation
This is a fund-freezing vulnerability reachable by a normal, permission-limited actor already recognized in scope (the asset issuer/definer). A single `asset_attestors` unit, valid per all current checks, can strand other users' already-received, legitimately-attested balances of that asset with no path to recovery (aside from asking the definer to re-attest the address, which the definer, having caused the freeze, is not obligated to do). Given assets can represent real value transferred among many independent holders, this can affect an arbitrary number of victims with a single transaction from the definer.

### Likelihood Explanation
Likelihood is Low/Medium in general use because it requires the asset's definer to author the offending `asset_attestors` message (either through carelessness — e.g., replacing rather than appending to the attestor list when rotating attestors — or intentionally). However, no additional privilege or race condition is needed: the "shrinking" attestor list is fully valid per `checkAttestorList` and `validateAttestorListUpdate`, so it will be accepted and processed by all full nodes exactly as designed, with no additional protocol defenses.

### Recommendation
Require that any new `asset_attestors` update be validated (or that `storage.readAsset` be changed) so previously-attested addresses whose attestation depended on a removed attestor are not retroactively de-attested for *outputs already existing at the time of the update* — e.g., by unioning historical attestor sets for the purpose of judging pre-existing coin ownership, or by explicitly forbidding removal of attestors from `asset_attestors` updates (only allowing additions), similar to the recommendation in the original report to prevent removal from accounting-critical lists. At minimum, document/flag this behavior so asset definers do not inadvertently freeze holder funds when rotating attestors.

### Proof of Concept
1. Definer `D` creates asset `A` with `spender_attested=true` and initial `attestors=[X]`.
2. Attestor `X` attests holder `H`'s address via an `attestation` message.
3. `H` receives a payment of asset `A` (now spendable because `H` is attested by `X`, per `validation.js:2504-2507` and `2630-2642`).
4. Definer `D` posts a new `asset_attestors` message for asset `A` with `attestors=[Y]` (dropping `X`). This passes `checkAttestorList`/`validateAttestorListUpdate` (`validation.js:2829-2864`) since it is a valid, sorted, non-empty, definer-signed list.
5. `storage.readAsset` now resolves `arrAttestorAddresses=[Y]` only (`storage.js:1921-1946`); `H` is no longer in `arrAttestedAddresses` since `H`'s attestation came from `X`, who is no longer in the attestor set.
6. `H` attempts to spend their existing, previously valid balance of asset `A`. The input check at `validation.js:2506-2507` (`objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1`) rejects the payment — `H`'s funds are now permanently frozen unless `Y` (or whoever is currently listed) attests `H`.

### Citations

**File:** storage.js (L1921-1946)
```javascript
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

**File:** storage.js (L1959-1992)
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

// note that light clients cannot check attestations
function loadAssetWithListOfAttestedAuthors(conn, asset, last_ball_mci, arrAuthorAddresses, bAcceptUnconfirmedAA, handleAsset){
	if (arguments.length === 5) {
		handleAsset = bAcceptUnconfirmedAA;
		bAcceptUnconfirmedAA = false;
	}
	readAsset(conn, asset, last_ball_mci, bAcceptUnconfirmedAA, function(err, objAsset){
		if (err)
			return handleAsset(err);
		if (!objAsset.spender_attested)
			return handleAsset(null, objAsset);
		filterAttestedAddresses(conn, objAsset, last_ball_mci, arrAuthorAddresses, function(arrAttestedAddresses){
			objAsset.arrAttestedAddresses = arrAttestedAddresses;
			handleAsset(null, objAsset);
		});
	});
}
```

**File:** validation.js (L2115-2122)
```javascript
		if (objAsset.spender_attested){
			if (conf.bLight && objAsset.is_private) // in light clients, we don't have the attestation data but if the asset is public, we trust witnesses to have checked attestations
				return callback("being light, I can't check attestations for private assets"); // TODO: request history
			if (objAsset.arrAttestedAddresses.length === 0)
				return callback("none of the authors is attested");
			if (bIssue && objAsset.arrAttestedAddresses.indexOf(issuer_address) === -1)
				return callback("issuer is not attested");
		}
```

**File:** validation.js (L2504-2507)
```javascript
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
								return cb("owner address is not attested");
```

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

**File:** validation.js (L2829-2864)
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
