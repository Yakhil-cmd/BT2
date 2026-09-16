## Title
Asset attestor revocation permanently freezes previously-received holder funds with no exit path - (File: validation.js)

### Summary
Assets with `spender_attested: true` couple the right to hold/spend outputs of the asset to a live, mutable attestor list controlled by the asset definer/attestors. Attestation is checked at spend-time against the *current* list, not the list in force when the funds were received, and there is no mechanism allowing a previously-attested holder to withdraw or transfer out balances after being removed from the list. This mirrors the reported "staking/unstaking controlled in unison" bug class: the same control (attestation) gates both the opportunity (accumulating asset balance) and the exit (spending it), and revoking it removes both simultaneously, trapping user funds.

### Finding Description
When an asset is created with `spender_attested: true`, every payment (issue, transfer, or spend) requires the relevant address to be in the asset's current attestor-approved list:

- On send/spend, the *input* owner address must be attested: [1](#0-0) 
- On issue, the issuer must be attested: [2](#0-1) 
- On send, *all output* addresses must also be currently attested: [3](#0-2) 

The attestor list itself can be updated at will by the definer/attestors via an `asset_attestors` message, and only the *latest* published list is honored: [4](#0-3) [5](#0-4) 

Attestation status is resolved dynamically at validation time via `filterAttestedAddresses`, which checks the address's live attestation state (and only if it postdates any subsequent address-definition change), not the state at the time the asset units were originally received: [6](#0-5) [7](#0-6) 

There is no code path that lets a holder who legitimately received asset outputs while attested later withdraw/transfer those outputs after the attestor removes them from the list — the same gate ("is this address currently attested?") controls both the ability to have accepted the funds and the ability to ever move them again. This is structurally identical to the reported issue: staking (receiving) and unstaking (spending) are controlled by the same toggle, and disabling it for a user blocks the exit as well as the entry, with no way to recover what was already deposited.

### Impact Explanation
Any holder of a `spender_attested` asset can have their existing balance permanently frozen the moment the attestor/definer publishes an updated attestor list that excludes their address, even though they acquired the funds legitimately while attested. Since attestation checks apply symmetrically to spending (`validation.js:2506`) and to receiving new outputs (`validation.js:2637`), there is no path to move the stranded balance to any address — not even back to the definer, unless `auto_destroy` happens to apply, and even that is definer-controlled, not user-controlled. This constitutes an AA/asset-level fund-freezing condition matching the allowed impact category.

### Likelihood Explanation
Likelihood is Medium: revoking an address from an attestor list is a normal, expected administrative action (e.g., compliance-driven de-attestation) documented in the schema comment "must subsequently publish and update the list of trusted attestors" [8](#0-7) . Any asset definer relying on `spender_attested` for compliance will eventually need to revoke addresses, and the current design offers no grace period, timelock, or unstake-style exception, so freezing is an unavoidable side effect of ordinary attestor-list maintenance rather than a contrived edge case.

### Recommendation
Decouple "eligibility to receive/hold" from "eligibility to exit." Options:
- Snapshot the attestation status at the time an output is created/received, and only enforce spender attestation checks for *new* activity, not for spending outputs already held by an address that was attested when it received them.
- Alternatively, allow any address to unconditionally send/transfer its already-held balance of the asset to the definer or to a fixed set of addresses (an "unstake" equivalent) even after losing attestation, so revocation blocks new accumulation without freezing existing funds.
- At minimum, document/enforce that attestor-list updates cannot retroactively strip spend rights for balances already accumulated before the update's last-ball MCI.

### Proof of Concept
1. Definer creates an asset with `spender_attested: true` and attestor `A` (via `asset` message, validated at [4](#0-3) ).
2. `A` attests address `X`. `X` receives a payment of this asset (issue/transfer succeeds because `X` is currently attested — checks at `validation.js:2115-2121` and `2630-2641` pass).
3. `A` (or the definer) later publishes a new `asset_attestors` list that no longer includes `X`. This is accepted because only the latest list is used going forward (`storage.js:1917-1946`, `validation.js:2033-2041`).
4. `X` now attempts to spend its previously-received asset output (e.g., to sell it or move it to another address). Validation fails at [9](#0-8)  with "owner address is not attested," and any attempted send to any output address is separately blocked at [10](#0-9)  unless the recipient is also currently attested.
5. `X`'s balance is now permanently unspendable — there is no fallback, timelock, or unstake mechanism, only re-attestation, which is entirely at the attestor's discretion.

### Citations

**File:** validation.js (L2033-2041)
```javascript
		case "asset_attestors":
			if (!isStringOfLength(payload.asset, constants.HASH_LENGTH))
				return callback("invalid asset in attestor list update");
			if (!objValidationState.assocHasAssetAttestors)
				objValidationState.assocHasAssetAttestors = {};
			if (objValidationState.assocHasAssetAttestors[payload.asset])
				return callback("can be only one asset attestor list update per asset");
			objValidationState.assocHasAssetAttestors[payload.asset] = true;
			validateAttestorListUpdate(conn, payload, objUnit, objValidationState, callback);
```

**File:** validation.js (L2115-2121)
```javascript
		if (objAsset.spender_attested){
			if (conf.bLight && objAsset.is_private) // in light clients, we don't have the attestation data but if the asset is public, we trust witnesses to have checked attestations
				return callback("being light, I can't check attestations for private assets"); // TODO: request history
			if (objAsset.arrAttestedAddresses.length === 0)
				return callback("none of the authors is attested");
			if (bIssue && objAsset.arrAttestedAddresses.indexOf(issuer_address) === -1)
				return callback("issuer is not attested");
```

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

**File:** storage.js (L1960-1974)
```javascript
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

**File:** storage.js (L1976-1992)
```javascript
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

**File:** initial-db/byteball-sqlite-light.sql (L246-246)
```sql
	spender_attested TINYINT NOT NULL, -- must subsequently publish and update the list of trusted attestors
```
