### Title
`readAsset()` accepts an unstable/unconfirmed attestor-list unit for AA-issued assets, letting an unattested spender race an on-chain attestation into validity before it is final — ([File: storage.js])

### Summary
The reported bug is a classic "check based on state that can be invalidated/forged between decision and inclusion" (TOCTOU) pattern: a privileged approval is granted based on on-chain state that is not required to be final/stable, so an attacker can manufacture the state right before the approval is used. The `TssStakingSlashing` case exploited the fact that the BitDAO's approval used non-final (mempool) state instead of confirmed state.

In ocore, `storage.readAsset()` has an analogous non-final-state acceptance path: when validating a payment for a `spender_attested` asset that was defined by an autonomous agent (AA), the attestor list lookup is allowed to read the **latest attestor-list unit regardless of stability or position relative to `last_ball_mci`**.

### Finding Description
`storage.readAsset(conn, asset, last_ball_mci, bAcceptUnconfirmedAA, handleAsset)` normally requires that both the asset definition and its attestor list be stable and before `last_ball_mci` (the DAG's standard "only trust finalized/agreed state" rule that exists precisely to prevent front-running/race conditions, since ocore units are validated against a commonly-agreed stable snapshot rather than the live mempool): [1](#0-0) 

The stable-only condition is built as:
```
const before_last_ball_cond = byAA ? "" : `AND main_chain_index<=${+last_ball_mci} AND is_stable=1`;
``` [2](#0-1) 

When `byAA` is `true`, `before_last_ball_cond` becomes an **empty string**, so the query that finds "the latest list of attestors" for the asset drops the `main_chain_index<=? AND is_stable=1` restriction entirely and just orders by `level DESC LIMIT 1`:
```
"SELECT unit FROM asset_attestors CROSS JOIN units USING(unit) \n\
WHERE asset=? " + before_last_ball_cond + " AND sequence='good' ORDER BY "+ (conf.bLight ? "units.rowid" : "level") + " DESC LIMIT 1"
``` [3](#0-2) 

`byAA=true` is reached whenever the asset's defining address is itself an AA and the asset was not yet stable/before-last-ball, via:
```
readAADefinition(conn, objAsset.definer_address, last_ball_mci, function (arrDefinition) {
    arrDefinition ? addAttestorsIfNecessary(true) : handleAsset("asset definition must be before last ball (AA)");
});
``` [4](#0-3) 

This function is invoked from `loadAssetWithListOfAttestedAuthors()`, which is called directly from `validatePayment()` — the code path exercised for every ordinary user payment message, using `objValidationState.bAA` as the `bAcceptUnconfirmedAA` flag:
```
storage.loadAssetWithListOfAttestedAuthors(conn, payload.asset, objValidationState.last_ball_mci, arrAuthorAddresses, objValidationState.bAA, function(err, objAsset){
``` [5](#0-4) 

Because the attestor-list unit selected in the `byAA` branch does not need to be stable, `is_stable=1`, or below `last_ball_mci`, an author can broadcast (or an AA-issuer/attestor account can broadcast) a fresh, still-unstable `asset_attestors` message adding an address to the attestor list, then immediately race a `spender_attested` payment spending outputs owned by that address, before the attestor-list unit is confirmed. If the competing/attestor-adding unit ends up losing the DAG race (becomes non-serial/`final-bad`, is pruned, or the branch it's on never stabilizes), the funds transfer that relied on that attestation was accepted based on state that was never finalized — the opposite of ocore's normal "only trust stable, sub-last-ball data" invariant that every other attestation/definition-change check in the codebase enforces (compare `filterAttestedAddresses()`, which strictly requires `main_chain_index<=? AND is_stable=1`). [6](#0-5) 

### Impact Explanation
An attacker who controls (or colludes with) the attestor of a `spender_attested` asset issued by an AA can add themselves (or an accomplice) to the attestor list in an unstable unit and immediately push through a payment of that asset that depends on the attestation being valid — before the DAG has actually finalized that attestor-list change. If the attestor-list unit is later excluded from the main sequence (loses a fork, becomes non-serial), the spend was validated and potentially already propagated/used downstream (e.g., composed into further AA triggers or exchanged) based on a decision that other nodes disagree on, creating a node disagreement on validity and enabling unauthorized transfer of a restricted asset that should have required a properly finalized attestation.

### Likelihood Explanation
Exploitation requires an AA-defined `spender_attested` asset, control (or collusion) over the attestor address, and timing a race between an unstable `asset_attestors` unit and a payment spending from the newly (but not yet stably) attested address. This is a non-trivial but realistic scenario for asset issuers/attestors who are otherwise unprivileged from the protocol's point of view (any address can define an AA-issued asset and act as its own attestor), and it directly parallels the reported bug class: approving an action based on state that isn't guaranteed final.

### Recommendation
Remove the special-case exemption for `byAA` in `addAttestorsIfNecessary()`, or at minimum require that the selected attestor-list unit be `sequence='good'` AND fully included/consistent with the trigger's `parent_units`/DAG position (similar to how other unstable-AA-definition lookups verify inclusion via `graph.determineIfIncludedOrEqual`), rather than merely ordering by `level DESC` with no stability constraint. At minimum, the attestor list used for validation should be required to be on the same DAG branch as, and confirmed no later than, the unit being validated.

### Proof of Concept
1. Address `AA1` (an autonomous agent) defines asset `X` with `spender_attested: true` and initial attestor `ATT`.
2. `ATT` broadcasts `asset_attestors` message adding address `SPENDER` to the attestor list for asset `X`, but does not wait for it to stabilize.
3. Before that unit stabilizes (or while it's still racing for inclusion on the main chain), `SPENDER` broadcasts a payment spending asset `X` outputs.
4. During validation, `validatePayment()` calls `loadAssetWithListOfAttestedAuthors(..., objValidationState.bAA, ...)`; because asset `X` is defined by an AA (`byAA=true` path in `readAsset`), the attestor-list query drops the `is_stable=1 AND main_chain_index<=last_ball_mci` filter and returns the most recent (by `level`) attestor list, including the unstable addition of `SPENDER`, allowing the payment to validate successfully.
5. If the attestor-list-adding unit is later not included in the final serial sequence (e.g., it becomes `temp-bad`/`final-bad` due to a conflicting unit), nodes that saw a different resolution will disagree on whether `SPENDER`'s payment was ever validly attested, while the payment has already been accepted/propagated by nodes that saw the unstable attestor addition.

### Citations

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

**File:** storage.js (L1953-1955)
```javascript
		readAADefinition(conn, objAsset.definer_address, last_ball_mci, function (arrDefinition) {
			arrDefinition ? addAttestorsIfNecessary(true) : handleAsset("asset definition must be before last ball (AA)");
		});
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

**File:** validation.js (L2082-2084)
```javascript
	var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
	// note that light clients cannot check attestations
	storage.loadAssetWithListOfAttestedAuthors(conn, payload.asset, objValidationState.last_ball_mci, arrAuthorAddresses, objValidationState.bAA, function(err, objAsset){
```
