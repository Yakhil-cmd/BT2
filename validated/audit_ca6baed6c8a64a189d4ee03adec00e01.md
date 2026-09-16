This confirms the finding: `formula/evaluation.js`'s `attestation[[...]]` op queries the `attestations`/`attested_fields` tables directly without excluding attestations that predate a subsequent `address_definition_change` for the attested address, unlike `storage.js`'s `filterAttestedAddresses` (used for asset spender-attestation), which explicitly filters out attestations older than the latest definition change with `main_chain_index>IFNULL((SELECT main_chain_index FROM address_definition_changes ...), 0)`. [1](#0-0) [2](#0-1) 

### Title
Improper Authentication: AA `attestation[[...]]` oscript getter accepts stale attestations issued before an address key/definition change - (File: formula/evaluation.js)

### Summary
The `attestation` operator available to Autonomous Agent (AA) oscript code (evaluated in `formula/evaluation.js`) looks up an address's attestations directly from the `attestations`/`attested_fields` tables filtered only by `attestor_address`, `address`, and `main_chain_index`. It does not exclude attestations that were issued before the attested address's controlling key was changed via an `address_definition_change` message. This is the same bug class as CVE-2022-39238: a party proves a historically-valid credential (the attestor's attestation), but the underlying identity/account has since changed ownership ("been disabled/rotated" in PAM terms), and the system still grants trust based on the stale credential.

### Finding Description
When an address's definition (its controlling keys) is changed on-chain via an `address_definition_change` message, any prior attestation issued to that address (e.g., a KYC attestation, whitelist attestation, or trust flag from an attestor) logically becomes invalid, because the identity now controlled by different keys is not the same party the attestor vouched for.

`storage.js`'s `filterAttestedAddresses` — used for asset `spender_attested` checks and for the `attested` opcode in `definition.js` (address/asset spending-condition evaluation) — correctly guards against this by requiring the attestation's `main_chain_index` to be greater than the `main_chain_index` of the most recent stable `address_definition_change` for that address: [3](#0-2) 

However, the `attestation[[...]]` oscript function in `formula/evaluation.js`, which AAs use to read attestation data (e.g., `attestation[[attestors=X, address=Y]].field`), performs no such check. Its two queries (for unstable/pending AA-visible attestations and for stable attestations) only filter by `attestor_address`, `address`, optional `field`, and `main_chain_index`: [2](#0-1) 

Any AA whose logic gates funds, permissions, or state transitions on `attestation[[...]]` (a common oscript pattern for KYC/whitelist gated AAs) will keep honoring an attestation issued to an address whose keys have since been rotated by the address owner (or, in adversarial scenarios, an address that changed hands/keys after being attested).

### Impact Explanation
An AA author routinely writes trust logic such as:
```
if (!attestation[[attestors=$kyc_attestor, address=trigger.address]])
    bounce("not attested");
```
Because the getter does not check whether the attested address's definition changed after the attestation was issued, an attacker who can gain control of an address that was attested in the past (e.g., an address whose original owner rotated away, or where the definition_chash mechanism allows reusing an address hash under a different keyset before first use) can still pass the AA's attestation check and interact with the AA as if genuinely attested. This can lead to unauthorized fund withdrawal from KYC/whitelist-gated AAs, bypass of AA-level access control, or state corruption of AAs that rely on `attestation[[...]]` for security-critical decisions — a concrete AA fund loss/freezing or unauthorized-spending impact reachable purely by an AA trigger sender using oscript logic already present in the target AA.

### Likelihood Explanation
Exploitation requires: (1) an AA that uses `attestation[[...]]` for access control tied to a specific address (a common, documented oscript pattern), and (2) the ability for the attacker to control an address after its definition (signing keys) has changed subsequent to the attestation, or to otherwise arrange for a stale attestation to remain associated with an address they now control. Address definitions can legitimately be changed via `address_definition_change`, a message any address owner can post, without invalidating attestations recorded for that address in the `attestation[[...]]` getter. The bug is a straightforward missing-filter condition analogous to the already-fixed logic in `storage.filterAttestedAddresses`, making it low-complexity to trigger once a suitable target AA is deployed.

### Recommendation
Add the same `address_definition_changes` freshness filter used in `storage.filterAttestedAddresses` to both attestation-lookup queries in `formula/evaluation.js`'s `attestation` opcode handler, requiring `main_chain_index > IFNULL((SELECT MAX(main_chain_index) FROM address_definition_changes ... WHERE address=?), 0)` (or the AA-response-table equivalent for the unstable-unit query) so that attestations preceding the latest definition change for the attested address are not honored.

### Proof of Concept
1. Attestor A posts `attestation` message for address `X` (e.g., `{address: X, profile: {kyc: "passed"}}`) while `X` is controlled by keypair `K1`.
2. `X`'s owner changes `X`'s definition to require signature from keypair `K2` (unrelated party or attacker who somehow gains rights to sign for `X`) via `address_definition_change`.
3. A trigger unit signed under the new definition (`K2`) is sent to an AA whose oscript logic checks `attestation[[attestors=A, address=trigger.address]]`.
4. Because `formula/evaluation.js`'s attestation queries do not check the `address_definition_changes` table, the historical attestation for `X` is still returned as valid, and the AA proceeds as if the current controller of `X` were attested by `A`, even though the attestation was made against the old identity/keyset.

### Citations

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
