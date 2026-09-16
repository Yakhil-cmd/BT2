### Title
AA `attestation[[...]]` formula trusts attestations issued before the attested address's definition (ownership) was changed - (File: `formula/evaluation.js`)

### Summary
The `attestation[[attestors=..., address=...]]` oscript/formula function, which any Autonomous Agent (AA) can use to gate logic on whether an address has been vouched for by a trusted attestor, looks up rows in the `attestations`/`attested_fields` tables filtered only by `attestor_address`, `address`, and `main_chain_index`. It never checks whether the attested address's definition (i.e. its controlling keyset) was later changed via an `address_definition_change`. Elsewhere in the codebase, the functionally identical trust check for asset `spender_attested` conditions (`storage.filterAttestedAddresses`) explicitly excludes attestations that predate the address's most recent definition change. The formula evaluator omits this safeguard, so an attestation continues to be honored for whoever currently controls the address, not just the party who controlled it (and was actually vetted) at attestation time.

### Finding Description
`evaluate()` in `formula/evaluation.js` handles the `'attestation'` opcode (lines 875-1010). After validating parameters, it runs two SQL queries against the `attestations`/`attested_fields` tables joined only with `units` (and `unit_authors`/`aa_addresses` for the unstable-unit branch): [1](#0-0) 

Neither query joins `address_definition_changes` or otherwise checks that the attestation's `main_chain_index` is later than the last stable definition change of `params.address.value`.

Compare this to the deliberately hardened equivalent used for asset spending conditions, `storage.filterAttestedAddresses`, which requires the attestation to be newer than the address's last definition change: [2](#0-1) 

Because address ownership in Obyte/ocore can change while the address (its hash) stays the same — via an `address_definition_change` message, including redefinition to an arbitrary new definition when `new_definition_chash === 'any'` is allowed (`objValidationState.last_ball_mci >= constants.anyDefinitionChangeUpgradeMci`) — the address's controlling keyset at the time of an AA trigger can be completely different from the keyset that existed when the attestor originally vetted and attested that address. The `attestation[[...]]` formula function has no way to detect this and will still report the address as attested/verified.

This is the same bug class as the Better Auth advisory: a security-relevant assertion made about an identity ("this email is verified" / "this address is attested") is trusted indefinitely without re-checking that the local/on-chain ownership state backing that identity has not changed since the assertion was made.

### Impact Explanation
AAs commonly implement KYC/whitelist/verification-gated logic of the form:
```
if (attestation[[attestors=$trusted_attestor, address=trigger.address]])
    ... release funds / allow privileged action ...
```
Because the formula does not invalidate attestations after a definition change of the attested address, an attacker who can gain control of an address that was attested in the past (e.g., by having the address's definition changed to a keyset they control — whether through collusion, purchase of a previously-attested address/wallet, or exploiting `any`-definition-change flexibility) can satisfy the attestation-gated condition for an identity they were never actually vetted for. Any AA that relies on `attestation[[...]]` to authorize fund transfers, whitelisting, or other privileged actions can be tricked into releasing funds or granting access to an unverified/unauthorized party — a direct AA fund-loss / authentication-bypass condition, reachable purely by an AA trigger sender who controls which address is used as `address` in the formula (typically `trigger.address`).

### Likelihood Explanation
Any AA author who uses the `attestation[[...]]` formula operator for access control is exposed; this is a documented, intended feature of the oscript/AA formula language for exactly this purpose (whitelisting/KYC gating), so it is a realistic pattern in production AAs. Triggering the bug requires only: (1) an address that has a stale attestation on record, and (2) a subsequent `address_definition_change` to a definition the attacker controls — both are standard, unprivileged operations reachable by any unit poster/AA trigger sender.

### Recommendation
Add the same safeguard used in `storage.filterAttestedAddresses` to the `attestation[[...]]` formula evaluator in `formula/evaluation.js`: both SQL queries against `attestations`/`attested_fields` should exclude rows whose `main_chain_index` (or `latest_included_mc_index`/`level` for the unstable branch) is earlier than the last stable `address_definition_changes` entry for the same address, mirroring the `IFNULL(... ORDER BY main_chain_index DESC LIMIT 1 ..., 0)` pattern already used for asset attestation checks.

### Proof of Concept
1. Attestor `T` attests address `A` (controlled by definition `D1`, owned by user `U`) as KYC-verified: an `attestation` unit with `address=A` is posted and becomes stable.
2. Address `A`'s control changes hands — e.g. `U` transfers/sells the address, or an attacker who colludes with `U` posts an `address_definition_change` for `A` from `D1` to `D2`, where `D2` is a definition the attacker fully controls (a plain `['sig', {pubkey: attacker_pubkey}]`, or `'any'` if MCI permits arbitrary redefinition).
3. Attacker, now controlling `A` under `D2`, sends a trigger to a KYC-gated AA using `trigger.address = A`.
4. The AA's oscript evaluates `attestation[[attestors=T, address=trigger.address]]`, which queries `attestations`/`attested_fields` filtered only by `attestor_address`/`address`/`mci` (`formula/evaluation.js:966-993`) — with no check against `address_definition_changes` — and returns `true`, treating the attacker as the originally KYC-verified party.
5. The AA releases funds/privileges to the attacker-controlled address `A`, even though the attacker was never vetted by attestor `T`.

### Citations

**File:** formula/evaluation.js (L966-993)
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
