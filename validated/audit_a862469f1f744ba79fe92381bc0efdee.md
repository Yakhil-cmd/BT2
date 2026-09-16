Based on my analysis, ocore's asset "spender attestation" mechanism (used to restrict payments to KYC/whitelisted addresses) is presence-based rather than value/state-based: once a trusted attestor posts an `attestation` for an address, that address is permanently treated as authorized to spend a `spender_attested` asset, with no mechanism for the attestor to revoke that specific attestation. This mirrors the Rancher bug class (a credential issued by an external authority that becomes invalid/stale but the relying system keeps trusting it indefinitely).

### Title
Attestations for `spender_attested` assets cannot be revoked by the attestor, permanently authorizing spending even after the attestor invalidates a subject - (File: storage.js)

### Summary
An asset can be created with `spender_attested: true`, requiring that any address that spends (or is issued) the asset must be "attested" by one of the asset's trusted attestor addresses [1](#0-0) . The check for whether an address is attested is purely presence-based: it looks for any historical `attestation` record from a currently-trusted attestor for that address, with no concept of revocation, expiry, or supersession by a later, contradicting attestation.

### Finding Description
`filterAttestedAddresses` in `storage.js` determines whether an output/author address is authorized to hold or spend a restricted asset by checking if there exists *any* row in the `attestations` table from one of the asset's currently trusted attestors for that address (only bounded by the address's most recent `address_definition_change`, not by attestation recency or content): [2](#0-1) 

This same "exists at least once" semantic is used both when validating payment authors/issuers [1](#0-0)  and outputs [3](#0-2) , as well as by the `attested` definition operator used in address definitions/AA conditions [4](#0-3) .

The only administrative control available is `asset_attestors`, which lets the asset definer change the *list of trusted attestor addresses* going forward [5](#0-4) . There is no mechanism, at the attestor level or the asset-definer level, to revoke or supersede a single already-issued attestation for a specific address while keeping that attestor otherwise trusted. Once attestor A (still trusted) has ever attested address X, address X is permanently treated as attested for that asset, even if:
- The attestor later determines the KYC/compliance basis for that attestation was wrong, fraudulent, or has since been revoked in the real world.
- The address is sanctioned, blacklisted, or otherwise disqualified after the fact.

The only way to cut off address X is to remove attestor A from the trusted list entirely via `asset_attestors`, which would also un-attest every other legitimately-attested address that A vouched for — an all-or-nothing remedy that is not a viable operational response to a single compromised/invalid subject.

### Impact Explanation
For KYC-gated or otherwise compliance-restricted assets (the entire purpose of `spender_attested`), this allows a previously-attested address to keep spending/receiving the restricted asset indefinitely after the real-world basis for the attestation (identity, license, compliance status) has been revoked by the attestor — directly analogous to Rancher continuing to trust a user's session/token after that user was deleted/disabled at the identity provider. This is unauthorized spending of a compliance-restricted asset that the asset issuer explicitly intended to gate.

### Likelihood Explanation
Any account that has ever been legitimately attested by a currently-trusted attestor can exploit this at will — no special privilege beyond having received one (possibly long-past-valid) attestation is required, and the condition is trivially reachable by simply continuing to post `payment` messages for the restricted asset.

### Recommendation
Introduce an explicit revocation mechanism for attestations (e.g., a `revoke` flag/timestamp posted by the same attestor, or requiring the "attested" checks to use only the *latest* attestation from each attestor and to treat that value, e.g., `revoked: true`, as un-attesting the address) instead of purely checking presence-of-any-attestation-ever from a currently-trusted attestor.

### Proof of Concept
1. Asset definer creates asset `A` with `spender_attested: true` and attestor list `[Attestor1]`.
2. `Attestor1` posts an `attestation` message for address `X` (e.g., confirming KYC).
3. `X` is now permitted to hold/spend asset `A` per `filterAttestedAddresses`/`validatePayment`.
4. Time passes; `Attestor1`'s real-world basis for attesting `X` is revoked (KYC failure discovered, `X` sanctioned, etc.). `Attestor1` remains a trusted attestor for asset `A` (asset definer has not, and practically cannot, remove `Attestor1` without also un-attesting all other legitimate holders).
5. `X` continues to freely spend/receive asset `A` in perpetuity, because `filterAttestedAddresses` only checks that an attestation from a trusted attestor exists for `X`, with no way for `Attestor1` to invalidate that specific, now-stale attestation.

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

**File:** definition.js (L904-915)
```javascript
			case 'attested':
				// ['attested', ['BASE32', ['BASE32']]]
				var attested_address = args[0];
				var arrAttestors = args[1];
				if (attested_address === 'this address')
					attested_address = address;
				storage.filterAttestedAddresses(
					conn, {arrAttestorAddresses: arrAttestors}, objValidationState.last_ball_mci, [attested_address], function(arrFilteredAddresses){
						cb2(arrFilteredAddresses.length > 0);
					}
				);
				break;
```
