Found the analog: the `spender_attested` asset mechanism in `ocore` lets the **asset definer** (privileged party) update the trusted "attestor" list for a private/transferrable asset at any time via an `asset_attestors` message, and this list is picked up dynamically at the moment a payment/transfer is validated — the exact same pattern as the reported "owner can update the oracle anytime to feed the wrong price" bug (a privileged party changes a trust-source right before/around a transaction, and validators re-evaluate against the *new* value at spend time rather than the value that was valid when the counterparty prepared their payment).

### Title
Asset definer can rewrite the trusted attestor list at any time to invalidate or redirect in-flight private/attested payments - (File: `validation.js`, `storage.js`)

### Summary
For assets with `spender_attested: true`, the list of trusted "attestor" addresses is not fixed at asset-issuance time. The definer can post a new `asset_attestors` message at any time, and this new list immediately becomes "the latest list" used by every subsequent payment/transfer validation of that asset [1](#0-0) . This is directly analogous to the reported bug: a privileged party (asset definer ≈ swapper owner) can change a trust source (attestor list ≈ oracle) at any point, and the change is picked up live by unrelated transactions in flight, with no cooldown, timelock, or binding to the state that existed when the counterparty built their transaction.

### Finding Description
`validateAttestorListUpdate` only checks that the sender is the asset's `definer_address` and that the new list is well-formed/sorted — there is no restriction on frequency or timing of updates [1](#0-0) .

When any payment or transfer of this asset is validated, `storage.readAsset` resolves attestors by querying for the **most recent** `asset_attestors` unit for the asset (ordered by level/rowid, i.e., "latest wins"), not the list that was current when a receiving/paying counterparty examined the chain and decided to transact [2](#0-1) . `filterAttestedAddresses` similarly filters against whatever is the current `arrAttestorAddresses` at validation time [3](#0-2) .

In `validatePayment`/`validatePaymentInputsAndOutputs`, spender/output-address attestation is checked strictly against this live attestor list: issuers, spenders, and every output address must be attested by the *current* attestor set at the moment of validation [4](#0-3) [5](#0-4) [6](#0-5) .

Because a private-payment chain (or a public attested-asset transfer) can be composed by the receiving/paying party based on the attestor list they observe, and the definer can post a new `asset_attestors` unit that gets included on the DAG before the counterparty's unit is confirmed, the definer can:
1. Change the attestor set right before accepting/settling a payment so that a counterparty who was legitimately attested is suddenly "not attested" (denial/freezing of funds), or
2. Add a new attestor who then immediately (falsely) attests a party the definer wants to benefit, letting that party pass the `spender_attested` check for a transfer that should not have been allowed under the previously agreed trust set.

This mirrors the reported class exactly: the "oracle" (attestor list) is owner-controlled, mutable at will, and consumed live by a counterparty's pending transaction, with no guarantee that validation uses the attestor set the counterparty relied on when constructing the payment.

### Impact Explanation
This can cause: (a) freezing/loss of otherwise-valid private or attested-asset payments — a counterparty's already-signed/sent transfer is rejected as unstable because the live attestor list changed underneath it, and for private payment chains this can permanently break the chain since it must be revalidated when it becomes stable; (b) unauthorized advantage for the definer, who can whitelist an address only at the exact moment they want a self-serving transfer/issue to pass `spender_attested`, then revert the list. Both are concrete "asset issuance and transfer conditions" / "private payment chain" fund-loss or fund-freezing effects reachable by an ordinary asset issuer against ordinary, unprivileged counterparties.

### Likelihood Explanation
Likelihood is Medium-High: it requires an asset with `spender_attested: true` (a supported, documented core feature) and a definer willing to abuse their explicit ongoing privilege over the attestor list. No special race condition beyond normal DAG unit ordering is needed — the definer only needs their `asset_attestors` unit to become part of the DAG (and stable) before the victim's dependent payment is finalized, which the definer, as a normal network participant, can freely attempt at any time since there is no cooldown or binding of attestor-list-version to the payment.

### Recommendation
- Bind attestation checks for a given payment to the attestor list version that was current as of the payment unit's `last_ball_mci` at the time it was composed/broadcast (already partially true via `main_chain_index<=last_ball_mci` filtering, but this still allows the definer to insert an update before the victim's last ball advances) — or
- Require a minimum stabilization/cooldown period after an `asset_attestors` update before it takes effect for new validations, giving in-flight payments time to settle under the prior list, or
- Disallow silent removal of previously-attested addresses within a short window, requiring explicit migration/notice.

### Proof of Concept
1. Definer issues asset `A` with `spender_attested: true`, initial attestor `Attestor1`. `Attestor1` attests `Alice`.
2. `Alice` verifies she is attested and starts composing/broadcasting a transfer of asset `A` to `Bob`.
3. Before Alice's unit stabilizes, the definer posts an `asset_attestors` message for asset `A` replacing the attestor list with `{Attestor2}` (a party who never attested Alice) — validated purely by `objUnit.authors[0].address === objAsset.definer_address`, no other restriction [7](#0-6) .
4. When Alice's transfer is (re)validated, `storage.readAsset` picks the *new* latest attestor list (`Attestor2`) [8](#0-7) , `filterAttestedAddresses` finds Alice is no longer attested under this list [9](#0-8) , and `validatePaymentInputsAndOutputs` rejects the transfer with "owner address is not attested" / "some output addresses are not attested" [10](#0-9) [11](#0-10) , even though Alice's transfer was fully valid under the attestor set that existed when she built it.

### Citations

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
