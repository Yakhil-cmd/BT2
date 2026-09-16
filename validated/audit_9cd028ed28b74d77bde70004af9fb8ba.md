## Title
Asset issuer can retroactively change the trusted attestor list, freezing already-issued spender-attested asset holdings - (File: `validation.js`, `storage.js`)

### Summary
The reported bug ([H-03] in the external report) is a class of vulnerability where a privileged party changes an economic/validity parameter of a token *after* value has already been distributed under the old parameter, causing holders' already-received value to be mis-evaluated. Ocore has a structurally analogous mechanism for `spender_attested` assets: the asset definer can post an `asset_attestors` message at any time to replace the trusted-attestor list, and every later validation of that asset's payments (public or private) uses only the *current/latest* attestor list rather than the list that was valid when the holder's funds were issued or received. This can silently freeze funds for legitimate holders who did nothing wrong.

### Finding Description
An asset with `spender_attested: true` requires that both the payer and payee addresses be attested (by one of the asset's trusted attestors) before a payment/transfer/issue is considered valid, as enforced in `validatePayment` and `validatePaymentInputsAndOutputs`: [1](#0-0) [2](#0-1) [3](#0-2) 

The attestor list itself is **not immutable**: the definer of the asset can post a new `asset_attestors` message at any later time to replace it, checked only for being sorted/well-formed and signed by the definer: [4](#0-3) 

When any subsequent payment involving the asset is validated, `storage.readAsset` always resolves attestors to the **latest** `asset_attestors` unit as of the current `last_ball_mci` — not the list that was in force when a given output was created or when a holder's attestation was obtained: [5](#0-4) 

`filterAttestedAddresses` then checks whether an address is attested by cross-referencing `attestations` against this **current** `arrAttestorAddresses`: [6](#0-5) 

Because validity is always evaluated against the *current* attestor list rather than the list valid at issuance/receipt time, a definer can:
1. Issue/transfer coins to holders while attestor A vouches for them (attestation from A is on-chain and valid at the time).
2. Later post an `asset_attestors` update that drops attestor A from the list (or replaces it entirely).
3. From that point on, every one of those holders' outputs is evaluated against the new list; since their existing attestation was made by the now-removed attestor A, `filterAttestedAddresses` no longer finds them attested, and `validatePaymentInputsAndOutputs` rejects the input/output with "owner address is not attested" for both public and private/fixed-denomination coins.

This mirrors the reported bug class exactly: a mutable reference that downstream code assumes is static is changed mid-flight by a legitimate, unprivileged-relative-to-holders actor (the asset issuer/definer), and previously-accrued value computed/attested under the old reference is evaluated under the new one, to the detriment of holders who did nothing wrong.

### Impact Explanation
Holders of a `spender_attested` asset can have their funds permanently frozen (unable to spend/transfer) the moment the asset definer updates the attestor list, even though those holders received and hold the coins entirely legitimately under the previously published rules. For private (indivisible, fixed-denomination) assets this is worse because token holders cannot themselves re-attest or appeal — spendability is tied to whichever attestor list happens to be current at the time of the *next* attempted spend, not the one active when they acquired the coins. This is a fund-freezing impact reachable purely through the asset issuer posting an ordinary, protocol-legal message.

### Likelihood Explanation
`asset_attestors` updates are a normal, permitted operation for any asset definer with `spender_attested: true` (see the SQL comment "must subsequently publish and update the list of trusted attestors"). No special privilege beyond being the asset's own definer is required, and no mechanism preserves the validity of holders attested under a prior list. Any asset issuer who rotates attestors (e.g., replacing a compromised or defunct attestation service, or maliciously targeting specific holders) will trigger this for any holder whose attestation predates the change.

### Recommendation
When validating spend of an existing output of a `spender_attested` asset, resolve attestor-list validity against the attestor list that was current as of the time the output was created (or as of the holder's own attestation), not the latest list as of `last_ball_mci`. Alternatively, require that an address's attestation remains valid ("grandfathered") for outputs it already owns even after a later attestor-list update, only enforcing the new list for new issuances/transfers going forward.

### Proof of Concept
1. Asset issuer publishes an asset with `spender_attested: true` and an initial attestor list `[A]` (`validateAssetDefinition`, `checkAttestorList`).
2. Attestor A attests Alice's address (`attestation` message).
3. Issuer issues coins to Alice; `validatePayment`/`validatePaymentInputsAndOutputs` pass because Alice is attested by A, per current list `[A]` (`validation.js:2115-2122`).
4. Later, issuer posts `asset_attestors` update replacing the list with `[B]` (`validateAttestorListUpdate`, `validation.js:2829-2848`); this is accepted because only the definer's signature and list well-formedness are checked.
5. Alice now attempts to transfer/spend her existing coins. `storage.readAsset` → `addAttestorsIfNecessary` resolves the attestor list to the latest one, `[B]` (`storage.js:1917-1946`); `filterAttestedAddresses` finds Alice (attested only by A) not attested under `[B]` (`storage.js:1959-1974`).
6. `validatePaymentInputsAndOutputs` rejects Alice's spend with "owner address is not attested" (`validation.js:2504-2507` / `2432-2433`), permanently freezing her previously legitimately-received coins.

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

**File:** validation.js (L2432-2433)
```javascript
						if (objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
							return cb("owner address is not attested");
```

**File:** validation.js (L2504-2507)
```javascript
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
								return cb("owner address is not attested");
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
