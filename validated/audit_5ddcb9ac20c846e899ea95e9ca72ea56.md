Confirmed: `formula/evaluation.js` has zero matches for `filterAttestedAddresses`/`address_definition_changes`, proving the AA `attestation[[...]]` operator never joins against `address_definition_changes`, unlike `storage.filterAttestedAddresses`. This confirms the analog.

### Title
Stale attestation trust survives address definition change in AA `attestation[[...]]` formula - (File: formula/evaluation.js)

### Summary
The Better Auth CVE's root cause is that a proof-of-control event (email verification) re-activates an account without invalidating credentials/state that were set up under a *different* controller before the proof occurred. Ocore has the structurally identical pattern for address identity: an `attestation` (KYC/whitelist proof) is stored keyed only by `address`, but an address can later change its cryptographic controller via an `address_definition_change` message. The two places that consume attestations diverge in how carefully they treat this: `storage.filterAttestedAddresses` (used by asset `spender_attested` checks and by the `attested` address-definition op) explicitly excludes attestations issued before the address's most recent definition change, but the AA oscript `attestation[[...]]` formula operator does not.

### Finding Description
`storage.filterAttestedAddresses` in `storage.js` correctly binds an attestation's validity to the *current* controller of the address by requiring the attestation's `main_chain_index` to be strictly greater than the mci of the address's latest stable `address_definition_change`: [1](#0-0) 

This same safeguard is applied when the `attested` op is evaluated as part of address-definition authentifier evaluation: [2](#0-1) 

However, the AA formula engine's `attestation[[...]]` operator — used by Autonomous Agents to gate logic/funds on whether a given address has been attested by a trusted attestor — queries the `attestations`/`attested_fields` tables directly by `address` and `attestor_address` only, with **no join or filter against `address_definition_changes`**: [3](#0-2) 

Because an Obyte address is a hash of its *definition*, but the on-chain identity/attestation record is keyed only by the address string, control of an address can change at any time via an `address_definition_change` message (rekeying, definition-template upgrade, key rotation, wallet recovery, or a private-key compromise) without invalidating any prior attestation. `storage.filterAttestedAddresses` accounts for this by re-checking that the attestation postdates the last definition change; `formula/evaluation.js`'s `attestation[[...]]` op does not perform the equivalent check, so an AA relying on it treats an address as still-attested indefinitely, even after its controlling key material has changed — exactly the "proof of control was true once, but the controller changed, and nothing revoked the trust" pattern from the advisory.

### Impact Explanation
Any AA that gates a privileged action (fund release, whitelist-restricted asset transfer/issuance, KYC-restricted payout, governance action) using `attestation[[address=..., attestors=...]]` can be manipulated by whoever currently controls the previously-attested address, regardless of whether that current controller was ever actually vetted by the attestor. Concretely: address `A` is attested by a trusted attestor while under definition `D1`; later, `A`'s controller executes an `address_definition_change` to `D2` (a legitimate key rotation, a sold/transferred address, or a stolen-key takeover); an AA that still honors `attestation[[address=A, ...]]` will grant the new keyholder of `D2` the trust originally extended to `D1`'s owner. This can cause **AA fund loss** (funds released to an unvetted/unauthorized party) or a **funds-freezing/logic-bypass** condition for KYC/whitelist-gated AAs — matching the required "AA fund loss" impact bucket for this program.

### Likelihood Explanation
Reachable by any unprivileged AA trigger sender: the attacker only needs to (a) get (or already have) an address attested by a trusted attestor referenced by a target AA, and (b) issue a standard `address_definition_change` message for that address (a normal, always-available primitive validated in `validation.js`) before triggering the AA. No special privileges, hub/peer compromise, or node collusion is required — the whole exploit is composed of otherwise-legitimate unit posts (`attestation` message, `address_definition_change` message, AA trigger unit).

### Recommendation
Modify the `attestation` case in `formula/evaluation.js` (both the "recent unstable AA units" query and the "stable units" query, lines ~966–1004) to add the same staleness guard used in `storage.filterAttestedAddresses`: require that the attestation's `main_chain_index` (or unstable equivalent ordering) is strictly greater than the `main_chain_index` of the most recent stable `address_definition_change` for that address, joining against the `address_definition_changes` table the same way `storage.js:1959-1974` does. Alternatively, factor the shared logic into `storage.filterAttestedAddresses` and call it from the formula evaluator instead of hand-rolling a separate, incomplete query.

### Proof of Concept
1. Attacker controls address `A` under definition `D1 = ["sig", {pubkey: P1}]`.
2. Attacker (or a colluding/legitimate attestor) posts an `attestation` message for `A` from a trusted `attestor_address` that a target AA references in its `attestation[[attestors=..., address=trigger.address]]` check (e.g., a KYC/whitelist gate for a payout AA).
3. Attacker posts an `address_definition_change` message changing `A`'s definition to `D2 = ["sig", {pubkey: P2}]` — a fully valid, unprivileged operation per `validation.js` `validateInlinePayload` (`"address_definition_change"` case).
4. Attacker (now controlling `A` via `D2`, e.g., after having sold/leaked/rotated away from `D1`, or where `D2` is simply a different attacker-controlled key never vetted by the attestor) sends a trigger unit from `A` to the AA.
5. The AA evaluates `attestation[[attestors=..., address=trigger.address]]`; because `formula/evaluation.js` (lines 966–1004) never checks `address_definition_changes`, the query still finds the old attestation and returns `true`/the attested field, letting the AA release funds or perform the gated action for the new, unvetted controller of `A`.

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
