### Title
Asset definer can update `asset_attestors` list to freeze already-received, previously-valid attested payments - ([File: validation.js], [File: storage.js])

### Summary
For assets with `spender_attested=1`, whether a payment is valid depends on the **current, latest** attestor list read at validation time, not on the attestor list that was in effect when the payer/recipient legitimately obtained or composed the transfer. Because the asset definer (a privileged, but not "trusted-with-funds", role) can publish a new `asset_attestors` message at any time, a payment or private-payment chain that was perfectly valid when it was created/received can permanently fail validation later, freezing the holder's funds with no recourse — the same "moving-goalpost" pattern as the Sherlock report's minimum-quote-value bug, where a mutable, definer-controlled parameter is re-checked at execution time instead of being fixed at request/transfer time.

### Finding Description
`spender_attested` assets require that both issuers and current output owners be present in the asset's attestor list at the time a payment message spending/creating their output is validated: [1](#0-0) 

The attestor list used for this check is *not* pinned to any snapshot taken when the payment was composed or when the funds were transferred to the holder. It is recomputed as "the latest stable list of attestors before `last_ball_mci`" every time the asset is loaded: [2](#0-1) 

The list can be changed by the asset definer at will via an `asset_attestors` message, validated only against the requirement that the sender is the asset's definer: [3](#0-2) 

For payments/output addresses, the same re-check happens on the output side too, before the payment is even fully validated: [4](#0-3) 

Because the wallet composer only checks attestation *at compose time* (e.g. `objAsset.spender_attested && objAsset.arrAttestedAddresses.length === 0`), there is a time window between "compose/receive a legitimately attested payment" and "get that payment finally validated/included/spent" during which the definer can publish a new attestor list that removes the holder's address. When that happens, any subsequent attempt by the holder to spend the output they legitimately received (an unprivileged private-payment counterparty or asset holder) fails with `"owner address is not attested"` at input validation, and any attempt to pay out to that holder fails with `"some output addresses are not attested"` — even though attestation was valid at the moment the funds were transferred to them.

This mirrors the reported symmio issue precisely: a mutable, privileged-party-controlled parameter (min quote value / attestor list) is checked using its *current* value at the moment of a later, independent action (close request / spend), rather than the value that applied when the original commitment (open position / fund transfer) was made — leaving the unprivileged counterparty's legitimate, already-committed position permanently stuck.

### Impact Explanation
An asset definer can, intentionally or via a routine attestor-rotation, cause outputs already legitimately held by third parties to become permanently unspendable ("frozen") for as long as the holder's address is excluded from the attestor list — with no way for the holder to remedy it themselves, since they are not the definer and cannot re-add themselves. For `is_private` + `fixed_denominations` assets, this affects private-payment chains held off-chain by recipients (e.g. multi-hop private transfers), i.e., a "private-payment counterparty" who received a coin while properly attested but is later dropped from the list before they get a chance to spend or forward it. This is a fund-freezing issue reachable by an ordinary asset holder/counterparty who did nothing wrong, matching the allowed "AA fund loss or freezing" impact category (generalized here to any asset holder's frozen funds), and can also block acceptance of valid outgoing payments to previously-attested output addresses that lost attestation between compose time and validation time.

### Likelihood Explanation
Likelihood is moderate: it requires an asset with `spender_attested=1` (a supported, documented feature — "must subsequently publish and update the list of trusted attestors") and an attestor-list update by the definer that removes a specific address between the time that address received/composed a payment and the time that payment (or its onward spend) is actually validated/included. For private multi-hop payment chains, this window can be arbitrarily long (funds can sit unswept for an extended period), making the freeze realistic even without malicious intent by the definer — e.g. routine attestor rotation for compliance reasons.

### Recommendation
Decouple the attestation requirement from "current, latest attestor list at validation time" for outputs/holders who were already attested when the funds were transferred to them. For example, snapshot/pin the attestor-eligibility check to the attestor list that was in effect at the time the spent output was created (similar to how definition changes are tracked with `address_definition_changes` and its own MCI-bounded lookups), or provide an explicit grace period / migration mechanism so that funds legitimately received under an old attestor list remain spendable for some bounded time after a list update, rather than being immediately and permanently frozen the moment the definer republishes `asset_attestors`.

### Proof of Concept
1. Definer creates asset `X` with `spender_attested=true`, `is_private=true`, `fixed_denominations=true`, and publishes an initial `asset_attestors` list including address `Alice`.
2. Alice is attested; Bob sends her a private, fixed-denomination coin of asset `X`. Composition succeeds because, at compose/validation time, `Alice` is on the attestor list (`validation.js:2506` check passes, `storage.js:1917-1946` returns the current list including Alice).
3. Definer republishes `asset_attestors` (`validation.js:2829-2848`) with a new list that no longer includes `Alice`. This is accepted because the only requirement is that the definer is the sender.
4. Alice now tries to spend/forward her previously-received coin. `storage.readAsset` (`storage.js:1917-1946`) loads the *new* attestor list (Alice excluded); `validatePaymentInputsAndOutputs` (`validation.js:2504-2507`) rejects the input with `"owner address is not attested"`.
5. Alice's funds are now permanently unspendable unless the definer chooses to re-add her — an unprivileged asset holder's legitimately-acquired funds are frozen purely due to a parameter change made after her position was already established.

### Citations

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
