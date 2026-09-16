### Title
Holders of a `spender_attested` asset permanently lose spending rights after an address definition change, with no protocol-level recovery path - (File: `storage.js`, `validation.js`)

### Summary
Assets defined with `spender_attested: true` require every spending address to have a currently valid attestation from one of the asset's attestors. The validity of an attestation is tied to the *most recent* definition-change of the holder's address: any legitimate `address_definition_change` (e.g. rotating keys, moving to a new/multi-sig definition) instantly and irrevocably un-attests the address for that asset, and there is no protocol mechanism to reverse this or to disable the `spender_attested` requirement once set. If the attestor(s) are unavailable, unresponsive, or simply never re-attest the new definition, the holder's coins of that asset become permanently frozen — the same "irreversible state transition traps previously-valid funds with no recovery path" pattern described in the Absorber/Shrine report.

### Finding Description
When an asset is created with `spender_attested: true`, every payment input/output address must appear in the asset's currently attested-address list, computed by `storage.filterAttestedAddresses`: [1](#0-0) 

Crucially, the SQL only counts an attestation as valid if it was published **after** the most recent `address_definition_change` for that address:
```
AND main_chain_index>IFNULL(
  (SELECT main_chain_index FROM address_definition_changes JOIN units USING(unit)
   WHERE address_definition_changes.address=attestations.address ...), 0)
```
This means any definition change (a completely normal, legitimate address operation) instantly voids the address's attested status for every `spender_attested` asset it holds.

This check is enforced both for issuing/receiving new outputs and for spending existing ones: [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

The only way to restore spending ability is for the asset's `definer_address` to re-attest the holder's address via a new `asset_attestors`/`attestation` message: [6](#0-5) 

However, the attestor list itself can never be emptied or the `spender_attested` flag disabled — `checkAttestorList` mandates a non-empty list forever, and there is no `asset` message field to turn `spender_attested` off after issuance: [7](#0-6) 

There is also no way to remove/replace an unresponsive attestor unilaterally; only the definer (a single address) can update the list, and doing so still requires ongoing action by an attestor to re-attest every holder who changes their definition. If the definer or attestor keys are lost, compromised, or simply inactive (analogous to the Shrine being irreversibly "killed" and recovery mode becoming permanently un-disableable), any holder who changes their address definition — for entirely legitimate reasons such as rotating a compromised key — permanently loses the ability to move their already-held balance of that asset. This mirrors the audited bug: an otherwise-normal state transition (definition change / system shutdown) collides with a gating condition (attestation / recovery-mode check) that can never again be satisfied, permanently trapping user funds that were valid and spendable before the transition.

### Impact Explanation
Any holder of a `spender_attested` asset (which by design is meant to model regulated/KYC-style tokens, i.e. can carry real economic value) who rotates their address definition — a routine security best practice — can be permanently locked out of their balance if the attestor does not immediately re-attest the new definition. Since `spender_attested` cannot be disabled and the attestor is a single point of failure with no time-bound obligation, this is a durable fund-freezing condition reachable purely by the token holder's own, unprivileged action (definition change) with no way to reverse it at the protocol level.

### Likelihood Explanation
Address definition changes are a normal, frequent user operation (key rotation, switching to multi-sig, recovering from a suspected compromise). Any user holding a `spender_attested` asset who performs this ordinary action is immediately affected; the freeze does not require any malicious actor, only an attestor who does not respond promptly (or ever) with a fresh attestation for the new definition.

### Recommendation
- **Short term:** Do not tie attestation validity to `address_definition_change` timestamps, or provide a grace/carry-over mechanism so previously attested addresses remain attested across definition changes unless the attestor explicitly revokes them.
- **Long term:** Allow the asset definer (or a multi-party governance mechanism) to disable `spender_attested` or replace an unresponsive attestor, and document this "attestation can be silently invalidated by an unrelated address action" invariant clearly for asset designers and wallet implementers so it is accounted for in UX (e.g. warn users before a definition change that it will freeze their `spender_attested` asset balances).

### Proof of Concept
1. Definer issues asset `A` with `spender_attested: true` and attestor list `[Attestor]`.
2. `Attestor` attests holder address `H` (`attestations` message referencing `H`).
3. `H` receives/holds balance of asset `A` — valid and spendable per `filterAttestedAddresses`.
4. `H` legitimately performs an `address_definition_change` (e.g., rotates to a new set of keys) at MCI `X`.
5. Per `storage.js:1960-1974`, the earlier attestation unit's `main_chain_index` is now `<= X`, so it no longer satisfies `main_chain_index > IFNULL(... last definition change mci ...)`; `H` drops out of `arrAttestedAddresses`.
6. `H` attempts to spend asset `A`; `validation.js:2115-2122` / `2432` / `2506` reject the payment with `"owner address is not attested"` / `"issuer is not attested"`.
7. If `Attestor` never issues a fresh `attestations` unit for `H`'s new definition (lost key, inactive, or refuses), `H`'s balance of asset `A` is permanently unspendable, with no protocol path to disable `spender_attested` or force re-attestation.

### Citations

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

**File:** validation.js (L2506-2507)
```javascript
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

**File:** validation.js (L2850-2864)
```javascript
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
