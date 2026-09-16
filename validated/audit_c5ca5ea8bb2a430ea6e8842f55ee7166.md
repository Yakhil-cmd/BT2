### Title
Asset attestor list can be unilaterally changed by the definer, permanently freezing funds of previously-attested holders - ([File: validation.js])

### Summary
An asset with `spender_attested: true` requires every spending address to be currently attested by one of the asset's `attestors`. The attestor list is not fixed forever — it can be replaced at any time by the asset's `definer_address` via an `asset_attestors` message. When the list is replaced, ocore recomputes the "currently valid attestor set" from the *latest* `asset_attestors` unit only, discarding the fact that a holder's existing coins were attested and validly transferred to them under the *previous* list. If the new attestor set never (re-)attests these existing holders, their coins become permanently unspendable, mirroring the `loan.callback` issue where a fixed dependency (the callback/attestor) can be swapped by a privileged party without any guarantee that the new dependency will support the operations already relying on it.

### Finding Description
`validateAttestorListUpdate` only checks that the message is single-authored and signed by the current `definer_address` of the asset — it performs no check on whether previously-attested holders remain covered by the new list: [1](#0-0) 

`storage.readAsset`'s `addAttestorsIfNecessary` always resolves `objAsset.arrAttestorAddresses` to the *most recent* `asset_attestors` unit for the asset, with no notion of "attestor list valid when the coin was issued/received": [2](#0-1) 

`filterAttestedAddresses` only checks that an attestation exists from an address currently in `arrAttestorAddresses` and postdates the holder's last definition change — it does not consider whether that attestation predates a subsequent attestor-list replacement that removed the attesting attestor: [3](#0-2) 

Finally, both public/private payment validation and indivisible-asset payment composition/validation hard-require the *current* attestor set to cover the spending/owning address, with no fallback if the list was swapped out from under existing holders: [4](#0-3) [5](#0-4) 

Just like `Cooler.loan.callback`, which is fixed at loan creation but silently becomes incompatible once lender ownership is transferred (with no re-validation that the new lender implements the callback interface), the asset's attestor dependency is swappable by a single privileged actor (the definer, who qualifies as "asset issuer" — one of the reachable actors) with zero guarantee of compatibility for parties who already built state (received/held coins) under the old configuration.

### Impact Explanation
Any address holding units of a `spender_attested` asset can be locked out of spending its own coins as soon as the definer posts a new `asset_attestors` message that does not (yet, or ever) attest them again. Because attestation is a manual, off-chain-triggered action by attestors, there is no protocol-level requirement, delay, or fallback ensuring continuity, so funds can become permanently frozen for legitimate holders — a concrete "AA/asset fund freezing" impact, without requiring any malicious node, network, or off-scope actor. This affects ordinary token holders, not just the definer, i.e., the loss extends to unprivileged counterparties, similar to the "borrower can't repay" outcome in the reported issue.

### Likelihood Explanation
Reachable via a single posted unit: the definer only needs to publish one `asset_attestors` message message (a normal application message type accepted by `validateInlinePayload`/`validateAttestorListUpdate`), which is a routine, permitted, low-cost operation intentionally supported by the protocol for attestor rotation. Any definer who rotates attestors (for legitimate reasons like compromised attestor keys) — without first re-attesting all existing holders — will trigger this condition, making it easy to hit inadvertently and trivial to trigger intentionally.

### Recommendation
When validating spendability of an asset requiring `spender_attested`, do not rely solely on the *latest* attestor list. Options:
- Accept attestations from any attestor that was valid in the attestor list at the time the address received the output (grandfathering), in addition to attestations from the current list, or
- Require a transition/overlap window whenever attestors are updated, during which both old and new attestor attestations remain valid, or
- Emit a protocol warning/require an explicit migration step (e.g., re-attestation deadline) before old attestations are invalidated.

### Proof of Concept
1. Definer creates asset `X` with `spender_attested: true`, `attestors: [A1]`.
2. `A1` attests holder `H`; `H` receives/holds units of `X` (validated fine since `H` ∈ `arrAttestedAddresses` from `A1`'s list) — see check in `validatePaymentInputsAndOutputs`: [5](#0-4) 
3. Definer posts an `asset_attestors` message replacing the attestor list with `[A2]` (allowed solely because `objUnit.authors[0].address === objAsset.definer_address`): [6](#0-5) 
4. `storage.readAsset` now resolves `arrAttestorAddresses = [A2]` for any future validation: [7](#0-6) 
5. `H` attempts to spend the previously-held units of `X`. `filterAttestedAddresses` finds no attestation from `A2` for `H`, so `arrAttestedAddresses` excludes `H`, and `validatePaymentInputsAndOutputs`/`validatePayment` reject the payment with "owner address is not attested" / "none of the authors is attested" — permanently, unless `A2` chooses to attest `H`.

### Citations

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
