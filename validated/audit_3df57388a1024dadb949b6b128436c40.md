### Title
Stale/Revoked Attestations Still Satisfy `attested` Address-Definition Condition, Enabling Continued Spending After Revocation - (File: definition.js)

### Summary
The `attested` operator used in Obyte address definitions and asset conditions (e.g. `spender_attested` assets) checks only whether an address was *ever* attested by a listed attestor, not whether that attestation is still current. This mirrors the reported Mattermost bug class: a credential ("magic-link token" / attestation) issued before a status change (deactivation / revocation) continues to grant access because the check only verifies historical issuance, not present validity.

### Finding Description
When an address definition or asset transfer condition contains `['attested', [attested_address, arrAttestors]]`, validation calls: [1](#0-0) 

which delegates to `storage.filterAttestedAddresses(conn, {arrAttestorAddresses: arrAttestors}, objValidationState.last_ball_mci, [attested_address], cb)` and treats the address as attested if `arrFilteredAddresses.length > 0`. This is a pure existence check against the `attestations`/`attested_fields` tables up to `last_ball_mci` — it does not look at the *content* of the attestation (e.g. a `verified: true/false` field) nor does it prefer the most recent attestation.

By contrast, the richer `attestation[[...]]` formula function used in AAs *does* support field-based lookups and an `ifseveral = 'last'` semantic to fetch the latest attested value: [2](#0-1) [3](#0-2) 

But the base `attested` definition primitive used directly in address definitions and asset spend conditions has no such mechanism — it is a one-time, irrevocable "has this attestor ever attested this address" check. This is also true on the `spender_attested` asset path, where attestor list updates are supported (`validateAttestorListUpdate` at [4](#0-3)  lets the definer change *which addresses count as attestors*), but there is no protocol-level way to invalidate a specific attestation instance that was already recorded by an attestor still on the list.

Consequently, an attestor who issues an "verified" attestation and later wants to revoke/deactivate that user (e.g., after KYC failure, fraud, or a support-agent style permission being pulled) cannot do so through the `attested` definition primitive: the original attestation unit remains permanently in the DAG and permanently satisfies the `attested` condition for any spending/definition-authorization logic that relies on it, exactly as a magic-link token issued before deactivation continued to authenticate the Mattermost guest account.

### Impact Explanation
Any address definition or `spender_attested` asset that uses `['attested', ...]` as a spending/authorization gate can be bypassed by a party whose attestation was later revoked by the same attestor(s), because the presence-only check ignores the intent to deactivate. This directly enables unauthorized spending of funds that were meant to be locked to currently-attested/authorized parties (e.g. compliance-gated assets, KYC-gated multisig wallets), which is a concrete "unauthorized spending" outcome under the specified impact criteria.

### Likelihood Explanation
Reachable by any unprivileged address owner who was previously attested and whose attestor later attempts to revoke access — no special privileges, hub/network position, or malicious peer behavior are required; it only requires an ordinary posted attestation unit (by the attestor, following normal usage) and later units authored by the (now supposed to be revoked) address using the same, unmodified definition.

### Recommendation
Extend the `attested` definition/condition semantics (and its validation/evaluation code in `definition.js`) to support field-based or "latest value" attestation checks similar to the `attestation[[...]]` formula function (with `ifseveral = 'last'`), so applications can encode revocable attestation status (e.g., requiring the latest attestation to have `revoked != true`) rather than relying purely on "was ever attested."

### Proof of Concept
1. Attestor `ATT` posts an attestation unit for address `A` (e.g., `{address: 'A', profile: {verified: true}}`).
2. Address `A`'s definition (or an asset's `spender_attested` condition) includes `['attested', ['A', ['ATT']]]`, gating spend authority on this attestation.
3. `A` spends funds; `attested` check at `definition.js:904-915` finds the attestation row and returns true — spend succeeds.
4. Attestor `ATT` later posts a new attestation for `A` with `{verified: false}}` (i.e., revokes access) to signal deactivation.
5. `A` again spends funds using the same definition; `storage.filterAttestedAddresses` still returns a matching row (the *first* attestation, or simply any row) because it does not inspect field content or recency — the `attested` condition is satisfied again, and the "revoked" party retains spending capability, contradicting the intended access-control policy.

### Citations

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

**File:** formula/evaluation.js (L916-928)
```javascript
						var ifseveral = 'last';
						if (params.ifseveral) {
							ifseveral = params.ifseveral.value;
							if (ifseveral !== 'last' && ifseveral !== 'abort')
								return setFatalError('bad ifseveral ' + ifseveral, { arr }, false, cb);
						}

						var type = 'auto';
						if (params.type) {
							type = params.type.value;
							if (type !== 'string' && type !== 'auto')
								return setFatalError('bad att type ' + type, { arr }, false, cb);
						}
```

**File:** formula/evaluation.js (L966-1004)
```javascript
							// first look for attestations in the recent unstable AA units
							conn.query(
								"SELECT " + selected_fields + " \n\
								FROM "+ table +" \n\
								CROSS JOIN units USING(unit) \n\
								CROSS JOIN unit_authors USING(unit) \n\
								CROSS JOIN aa_addresses ON unit_authors.address=aa_addresses.address \n\
								WHERE attestor_address IN(" + arrAttestorAddresses.map(conn.escape).join(', ') + ") \n\
									AND "+ table + ".address = ? " + and_field +" \n\
									AND (main_chain_index > ? OR main_chain_index IS NULL) \n\
								ORDER BY latest_included_mc_index DESC, level DESC, units.unit, message_index LIMIT ?",
								[params.address.value, mci, (ifseveral === 'abort') ? 2 : 1],
								function (rows) {
									if (!bAA)
										rows = []; // discard any results
									count_rows += rows.length;
									if (count_rows > 1 && ifseveral === 'abort')
										return setFatalError("several attestations found for " + params.address.value, { arr }, false, cb);
									if (rows.length > 0 && ifseveral !== 'abort') // if found but ifseveral=abort, we continue
										return returnValue(rows);
									// then check the stable units
									const or_null_mci = conf.bLight ? 'OR main_chain_index IS NULL' : '';
									conn.query(
										"SELECT "+selected_fields+" FROM "+table+" CROSS JOIN units USING(unit) \n\
										WHERE attestor_address IN(" + arrAttestorAddresses.map(conn.escape).join(', ') + ") \n\
											AND address = ? "+and_field+" AND (main_chain_index <= ? " + or_null_mci + ") AND +sequence='good' \n\
										ORDER BY main_chain_index DESC, latest_included_mc_index DESC, level DESC, unit, message_index LIMIT ?",
										[params.address.value, mci, (ifseveral === 'abort') ? 2 : 1],
										function (rows) {
											count_rows += rows.length;
											if (count_rows > 1 && ifseveral === 'abort')
												return setFatalError("several attestations found for " + params.address.value, { arr }, false, cb);
											if (rows.length > 0)
												return returnValue(rows);
											if (params.ifnone) // type is never converted
												return cb(params.ifnone.value); // even if no field
											cb(false);
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
