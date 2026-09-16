### Title
Asset Definer Has Unilateral, Unrestricted Power to Add/Remove Attestors at Any Time, Enabling Instant Freezing or Rug-Pull of `spender_attested` Asset Holders' Funds - (File: `validation.js`)

### Summary
For any asset created with `spender_attested: true`, the asset **definer** retains a permanent, unilateral privilege to rewrite the list of trusted attestors via a plain `asset_attestors` message, with no cap, timelock, cosigning, or opt-out mechanism, exactly analogous to the Blur `ExecutionDelegate` owner being able to call `approveContract()` at any time. Because the attestor list used to authorize a spend is read live at validation time (not fixed at receipt time), the definer can retroactively invalidate legitimate holders' ability to move their funds, or swap in a colluding attestor to grant spend eligibility to an address of the definer's choosing.

### Finding Description
When an asset is defined with `spender_attested: true`, every payment (issue or transfer) of that asset requires the payer/output addresses to be "attested" by one of the asset's currently-registered attestors: [1](#0-0) [2](#0-1) 

The check does not use the attestor list that existed when the holder received the funds — it uses the attestor list **live at validation time** (`objValidationState.last_ball_mci`), fetched from `storage.readAsset`/`filterAttestedAddresses`: [3](#0-2) [4](#0-3) 

The attestor list itself can be changed at any time by a single privileged party — the asset **definer** — via an `asset_attestors` message, gated by nothing more than a single address check: [5](#0-4) 

This is dispatched during normal message validation with no rate limit, timelock, quorum, or multi-party approval requirement: [6](#0-5) 

And the update is persisted unconditionally by `writer.js`, replacing/adding to the effective attestor set consulted by every future spend check: [7](#0-6) 

This mirrors the Blur `ExecutionDelegate.approveContract()` pattern precisely: a single owner-controlled, always-callable function silently changes who is authorized to move already-deposited/held user funds, and users have no reliable, race-free way to protect themselves (there is no "revoke" analog for holders of a `spender_attested` asset — attestation status is entirely under the definer/attestor's control, not the holder's).

### Impact Explanation
Two distinct, concrete harms map directly onto the allowed impact categories (AA/asset fund loss or freezing):
1. **Freezing existing holders' funds:** If the definer removes the attestor that had attested a legitimate holder's address (or simply publishes a new attestor list that omits them), that holder's previously-received, spender_attested asset outputs instantly become unspendable — `filterAttestedAddresses` no longer returns their address, and `validatePaymentInputsAndOutputs`/`validatePayment` reject the transfer with `"owner address is not attested"` / `"none of the authors is attested"`. [8](#0-7) 
2. **Enabling unauthorized transfer eligibility:** The definer can add a colluding/self-controlled attestor address at will, then have that attestor immediately attest any address of the definer's choosing, making that address eligible to receive/hold/spend the asset — bypassing whatever attestation policy (e.g., KYC/whitelisting) users relied upon when acquiring the asset.

Because this power belongs solely to the definer address (single signature, no multisig or timelock enforced by protocol code) and takes effect on the very next stable unit, it is a High/Medium-severity centralization/trust risk consistent with the C4 judge's ultimate ruling (Medium) on the analogous Blur finding: any compromise of the definer's private key, or any malicious/opportunistic behavior by the definer, immediately and irreversibly affects the funds of every current or future holder of that asset.

### Likelihood Explanation
Likelihood is high for any deployed asset that opts into `spender_attested`: the attacker capability required is simply possession of the definer address's private key (no special node access, no race condition needed, no cooperation from other parties). The `asset_attestors` message is a first-class, always-available oscript primitive — no upgrade MCI gate or complexity limit prevents its use at any time after asset creation, and it can be posted in the same unit flow as any other transaction.

### Recommendation
- Require attestor-list changes to be governed by something the current holders can react to safely, e.g., a mandatory timelock/grace period between publishing a new attestor list and its taking effect, so holders have a window to move funds before it applies.
- Alternatively, snapshot/pin the attestor list that was in effect when an output was created, and validate spends against that pinned list rather than the live list, so definer changes cannot retroactively freeze already-received outputs.
- Consider requiring multi-party (e.g., "cosigned by") authorization for `asset_attestors` updates, rather than a bare single-signature check in `validateAttestorListUpdate`.
- Clearly document, at asset-creation and wallet UX levels, that `spender_attested` assets carry this centralization risk so holders can make an informed choice.

### Proof of Concept
1. Definer `D` creates asset `A` with `spender_attested: true` and an initial attestor list `[T1]` via the `asset` message.
2. Attestor `T1` attests holder `H`'s address; `H` receives a transfer output of asset `A` and can currently spend it (validated via `filterAttestedAddresses` against `[T1]`). [4](#0-3) 
3. Definer `D` posts an `asset_attestors` message for asset `A` naming a new list `[T2]` (a definer-controlled or colluding attestor), replacing/adding to the trusted list: [7](#0-6) 
4. `H` attempts to spend the previously received output. `loadAssetWithListOfAttestedAuthors`/`filterAttestedAddresses` now evaluates against `[T2]` (or `[T1,T2]` depending on whether it's additive), and since `T1`'s attestation of `H` is no longer in the trusted set (if `T1` was dropped), the payment is rejected with `"owner address is not attested"`: [1](#0-0) 
   `H`'s funds are frozen with no recourse, purely at the definer's discretion — no unauthorized third party, network fault, or code bug is required, only the single privileged `asset_attestors` capability.

### Citations

**File:** validation.js (L2033-2042)
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
			break;
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

**File:** writer.js (L244-251)
```javascript
						case "asset_attestors":
							var asset_attestors = message.payload;
							for (var j=0; j<asset_attestors.attestors.length; j++){
								conn.addQuery(arrQueries, 
									"INSERT INTO asset_attestors (unit, message_index, asset, attestor_address) VALUES(?,?,?,?)",
									[objUnit.unit, i, asset_attestors.asset, asset_attestors.attestors[j]]);
							}
							break;
```
