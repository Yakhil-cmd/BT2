### Title
AA `attestation` formula ignores address-definition changes, letting a new controller of an address inherit a stale attestation - ([File: formula/evaluation.js])

### Summary
The `attestation[[...]]` oscript/formula function used inside Autonomous Agents queries the `attestations`/`attested_fields` tables for the given `address` and `attestors`, but never checks whether the address's controlling definition has changed since the attestation was posted. `storage.js`'s `filterAttestedAddresses()` (used by the plain-oscript `attested` condition and by `spender_attested` asset checks) explicitly guards against this by requiring the attestation's `main_chain_index` to be **after** the last `address_definition_changes` record for that address. The AA formula implementation of `attestation` has no equivalent guard, so it is the analog of the GitLab bug class ("membership/ownership change not reflected, allowing continued/former access").

### Finding Description
`storage.filterAttestedAddresses()` deliberately excludes attestations that predate a later redefinition of the address: [1](#0-0) 

This comparison against `address_definition_changes` exists precisely because in ocore, ownership/control of a fixed address (chash) can be transferred to a different keyset via an `address_definition_change` message while the address string itself stays the same, as validated in: [2](#0-1) [3](#0-2) 

The `attested` definition-language operator that AA/wallet address definitions can use correctly routes through the protected helper: [4](#0-3) 

However, the `attestation[[...]]` formula function evaluated inside AA (oscript) code performs its own raw queries against `attestations`/`attested_fields`/`units`, filtered only by `attestor_address`, `address`, and `main_chain_index`/`sequence` - with **no join or comparison against `address_definition_changes`**: [5](#0-4) 

Because of this, once an attestor (e.g. a KYC/whitelist oracle) has attested some field for address `Y` (posted by whoever controlled `Y` at that time), any later re-definition of `Y` to an entirely different key set (a legitimate, validator-approved operation) does not invalidate the attestation from the AA's point of view. Whoever now controls `Y` can trigger the AA and have the AA's formula evaluate `attestation[[attestors=..., address=trigger.address]].field` to the old, stale value.

### Impact Explanation
AAs commonly use `attestation[[...]]` to gate privileged operations - e.g. releasing funds only to KYC-verified/whitelisted addresses, unlocking bonus payouts, or restricting participation to attested identities. Since the check does not account for definition changes, a party who gains control of an address after it was attested (e.g., by buying/inheriting/otherwise obtaining control through a definition change, or an address whose definition permits multiple/rotating controllers) can pose as the originally-attested identity and pass the AA's authorization gate. This can lead to unauthorized fund release from an AA, bypass of AA-level whitelisting/compliance logic, or supply of privileged AA operations to a party the attestor never vetted — a concrete AA fund-loss / unauthorized-access impact, directly analogous to the GitLab bug where a stale authorization state (TODO delivered under an old permission) let a de-authorized party read confidential content.

### Likelihood Explanation
Any AA author choosing to rely on `attestation[[...]]` for access control is exposed; no special network position, malicious peer, or privileged role is required. Triggering the flaw only requires: (1) an address that was attested once, (2) a legitimate on-chain `address_definition_change` for that address (always permitted by the definition-language, requires no attestor cooperation), and (3) posting a normal trigger unit from the redefined address. All three steps are standard user-level actions reachable by an unprivileged AA trigger sender.

### Recommendation
Modify the `attestation` case in `formula/evaluation.js` to join against `address_definition_changes`/`units` and require that the attestation's `main_chain_index` (or `latest_included_mc_index` for unstable AA-posted attestations) is later than the last stable definition change of the queried `address`, mirroring the logic already implemented in `storage.filterAttestedAddresses()`.

### Proof of Concept
1. Attestor `T` posts `attestation` message: `{address: Y, profile: {kyc: "passed"}}` while address `Y`'s definition is `D1` (controlled by key `K1`, owned by Alice).
2. Alice legitimately posts an `address_definition_change` unit for `Y`, changing its definition from `D1` to `D2` (a totally different keyset, e.g., controlled by key `K2`, now held by Bob) — validated per `validation.js:1719-1745`/`definition.js` and confirmed stable.
3. An AA contains logic such as: `if (attestation[[attestors=T, address=trigger.address]].kyc != 'passed') bounce("not verified"); ... send funds to trigger.address;`
4. Bob (now controlling `Y` via `K2`, never vetted by `T`) sends a trigger unit from address `Y` to the AA.
5. `formula/evaluation.js`'s `attestation` case finds the old attestation row for `address=Y` (no definition-change filter) and returns `kyc='passed'`, so the AA proceeds to send Bob funds/privileges intended only for the originally-attested Alice.

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

**File:** validation.js (L1719-1745)
```javascript
		case "address_definition_change":
			if (!isNonemptyObject(payload))
				return callback("payload must be a non empty object");
			if (hasFieldsExcept(payload, ["definition_chash", "address"]))
				return callback("unknown fields in address_definition_change");
			var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
			var address;
			if (objUnit.authors.length > 1){
				if (!isValidAddress(payload.address))
					return callback("when multi-authored, must indicate address");
				if (arrAuthorAddresses.indexOf(payload.address) === -1)
					return callback("foreign address");
				address = payload.address;
			}
			else{
				if ('address' in payload)
					return callback("when single-authored, must not indicate address");
				address = arrAuthorAddresses[0];
			}
			if (!objValidationState.arrDefinitionChangeFlags)
				objValidationState.arrDefinitionChangeFlags = {};
			if (objValidationState.arrDefinitionChangeFlags[address])
				return callback("can be only one definition change per address");
			objValidationState.arrDefinitionChangeFlags[address] = true;
			if (!isValidAddress(payload.definition_chash))
				return callback("bad new definition_chash");
			return callback();
```

**File:** definition.js (L835-853)
```javascript
			case 'seen definition change':
				// ['seen definition change', ['BASE32', 'BASE32']]
				var changed_address = args[0];
				var new_definition_chash = args[1];
				if (changed_address === 'this address')
					changed_address = address;
				if (new_definition_chash === 'this address')
					new_definition_chash = address;
				var and_definition_chash = (new_definition_chash === 'any') ? '' : 'AND definition_chash='+db.escape(new_definition_chash);
				conn.query(
					"SELECT 1 FROM address_definition_changes CROSS JOIN units USING(unit) \n\
					WHERE address=? "+and_definition_chash+" AND main_chain_index<=? AND sequence='good' AND is_stable=1 \n\
					LIMIT 1",
					[changed_address, objValidationState.last_ball_mci],
					function(rows){
						cb2(rows.length > 0);
					}
				);
				break;
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
