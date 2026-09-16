Found a genuine analog: the `asset_attestors` update mechanism has exactly the same "mutable state referenced by a stale, previously-composed transaction" shape as the Gondi `loanId` bug, and unlike `address_definition_change` (which is protected by `checkNoPendingChangeOfDefinitionChash`/`checkNoPendingDefinition`), there is **no equivalent anti-front-running guard for attestor-list updates**.

### Title
Asset definer can front-run pending spender_attested transfers by revoking the attestor list, causing legitimate payments to be invalidated/frozen - (File: validation.js, storage.js)

### Summary
For a `spender_attested` asset, every payment's validity depends on the *current, latest* attestor list read at validation time via `storage.readAsset`/`loadAssetWithListOfAttestedAuthors`. Unlike `address_definition_change`, an `asset_attestors` update has no "no pending change" guard, so the definer can post a new `asset_attestors` message that removes an address's attestation right after a user has already signed and broadcast (or is about to broadcast) a payment relying on that attestation, causing the payment to become invalid.

### Finding Description
`validatePayment` in `validation.js` resolves the attestor list for `spender_attested` assets using `storage.loadAssetWithListOfAttestedAuthors`, which calls `readAsset`, which in turn always fetches the **latest** attestor-list unit that is stable and good as of `last_ball_mci`: [1](#0-0) 
The freshly-fetched attestor list is then used to check the payer/output addresses: [2](#0-1) [3](#0-2) [4](#0-3) 

The attestor list itself can be freely replaced at any time by the asset definer via an `asset_attestors` message, validated only by `validateAttestorListUpdate`: [5](#0-4) 

Note that this check has **no analog to the address-definition-change safeguards** that ocore already implements for a structurally identical race (`checkNoPendingChangeOfDefinitionChash` / `checkNoPendingDefinition` in `validation.js`, which explicitly reject a unit if there is any pending, not-yet-stable definition/definition-change for the signer's address): [6](#0-5) [7](#0-6) 

Because no such guard exists for `asset_attestors`, a payer whose payment was composed and broadcast while attested can have that attestation revoked by a subsequent, faster-included `asset_attestors` unit from the definer (a single-authored, cheap message). When the payer's payment then gets included, `validatePayment`/`validatePaymentInputsAndOutputs` re-checks attestation against the *now-current* list and rejects the unit ("owner address is not attested" / "some output addresses are not attested" / "issuer is not attested"), exactly mirroring the Gondi `_loans[_loanId]` hash-mismatch pattern where a mutable on-chain reference is changed out from under an already-composed transaction.

### Impact Explanation
This is the AA/asset analog of the Gondi H-10 finding: the asset definer (who is trusted with less power than full custody, since `spender_attested` is meant only to gate *which addresses* may hold/spend the asset, not to arbitrarily block a specific pending transfer) can weaponize `asset_attestors` updates to:
- Selectively censor/DoS a specific counterparty's payment by revoking their attestation the moment their transaction is broadcast, forcing them to pay commissions repeatedly without ever completing the transfer.
- Coordinate with a malicious actor to freeze funds of a spender_attested holder indefinitely, since every resubmitted payment can be front-run again with another list update.
- Because divisible/indivisible transfers using this asset are permanently affected, this results in AA/asset fund freezing for holders of `spender_attested` assets, matching the "AA fund loss or freezing" impact category.

### Likelihood Explanation
`spender_attested` assets are a documented, first-class asset feature (see `assets` schema `spender_attested` column and sample oscripts such as `futures_contract.oscript`, `option_contract.oscript`, `create_an_asset.oscript`). The definer only needs to author a small, cheap, single-message unit (`asset_attestors`) to invalidate a target's pending transfer, and can repeat this indefinitely with low cost right whenever a target's payment appears in the mempool/DAG tips, similar to the low-cost repeated `mergeTranches` front-running in the original report. The main constraint (paralleling the original judge's concerns) is that the attacker must be the asset definer — but this is analogous to the Gondi scenario where the *lender itself* was identified as the most credible attacker with "high motivation," which is exactly the situation here (the definer already controls attestation policy and has motivation to censor specific spenders).

### Recommendation
Add a "no pending attestor-list change" check for `spender_attested` payments analogous to `checkNoPendingChangeOfDefinitionChash`/`checkNoPendingDefinition`: reject an `asset_attestors` update, or reject a payment, if there is an unstable/pending `asset_attestors` unit for the same asset within the same window, or alternatively snapshot the attestor list referenced by the payment (e.g., via an explicit "as of unit" reference) instead of always resolving to the newest list at `last_ball_mci`. At minimum, disallow attestor-list changes from taking effect until they are stable and require some minimum time/MCI delay before a change can invalidate previously-broadcast payments, similar to the recommended mitigation from the original report (don't allow ID/state-changing functions to run close to a pending transaction's finalization).

### Proof of Concept
1. Definer issues asset X with `spender_attested: true` and initial attestor list `[A]`.
2. Attestor issues an `attestation` for address `V` (victim), making `V` attested.
3. `V` composes and broadcasts payment `P` from `V`'s attested address to some recipient, relying on being in `arrAttestedAddresses`.
4. Definer observes `P` in the DAG tips (still unstable) and immediately posts `asset_attestors` message removing `V`'s attestor from the trusted list (`validateAttestorListUpdate` allows this at any time, with no dependency on `P` being resolved first — see `validation.js:2829-2848`).
5. If the definer's unit becomes stable/included before `P` is finalized, when `P` is validated/finalized, `storage.readAsset`/`loadAssetWithListOfAttestedAuthors` resolves the now-updated (empty of `V`) attestor list, and `validatePaymentInputsAndOutputs`/`validatePayment` rejects `P` with "owner address is not attested" (`validation.js:2432-2433`, `2115-2122`).
6. `V`'s funds remain stuck in the `spender_attested` asset; every resubmission can be front-run again the same way, since the check happens against "current latest list", not a list frozen at composition time, and no anti-front-running guard exists for `asset_attestors` (unlike the guard that exists for `address_definition_change`).

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

**File:** validation.js (L1345-1377)
```javascript
	// don't allow contradicting pending keychanges.
	// We don't trust pending keychanges even when they are serial, as another unit may arrive and make them nonserial
	function checkNoPendingChangeOfDefinitionChash(){
		var next = checkNoPendingDefinition;
		//var filter = bNonserial ? "AND sequence='good'" : "";
		conn.query(
			"SELECT unit FROM address_definition_changes JOIN units USING(unit) \n\
			WHERE address=? AND (is_stable=0 OR main_chain_index>? OR main_chain_index IS NULL)", 
			[objAuthor.address, objValidationState.last_ball_mci], 
			function(rows){
				if (rows.length === 0)
					return next();
				if (!bNonserial || objValidationState.arrAddressesWithForkedPath.indexOf(objAuthor.address) === -1)
					return callback("you can't send anything before your last keychange is stable and before last ball");
				// from this point, our unit is nonserial
				async.eachSeries(
					rows,
					function(row, cb){
						graph.determineIfIncludedOrEqual(conn, row.unit, objUnit.parent_units, function(bIncluded){
							if (bIncluded)
								console.log("checkNoPendingChangeOfDefinitionChash: unit "+row.unit+" is included");
							bIncluded ? cb("found") : cb();
						});
					},
					function(err){
						(err === "found") 
							? callback("you can't send anything before your last included keychange is stable and before last ball (self is nonserial)") 
							: next();
					}
				);
			}
		);
	}
```

**File:** validation.js (L1381-1419)
```javascript
	function checkNoPendingDefinition(){
		//var next = checkNoPendingOrRetrievableNonserialIncluded;
		var next = validateDefinition;
		if (bInitialDefinition)
			return next();
		//var filter = bNonserial ? "AND sequence='good'" : "";
	//	var cross = (objValidationState.max_known_mci - objValidationState.last_ball_mci < 1000) ? 'CROSS' : '';
		conn.query( // _left_ join forces use of indexes in units
		//	"SELECT unit FROM units "+cross+" JOIN unit_authors USING(unit) \n\
		//	WHERE address=? AND definition_chash IS NOT NULL AND ( /* is_stable=0 OR */ main_chain_index>? OR main_chain_index IS NULL)", 
		//	[objAuthor.address, objValidationState.last_ball_mci], 
			"SELECT unit FROM unit_authors WHERE address=? AND definition_chash IS NOT NULL AND _mci>?  \n\
			UNION \n\
			SELECT unit FROM unit_authors WHERE address=? AND definition_chash IS NOT NULL AND _mci IS NULL", 
			[objAuthor.address, objValidationState.last_ball_mci, objAuthor.address], 
			function(rows){
				if (rows.length === 0)
					return next();
				if (!bNonserial || objValidationState.arrAddressesWithForkedPath.indexOf(objAuthor.address) === -1)
					return callback("you can't send anything before your last definition is stable and before last ball");
				// from this point, our unit is nonserial
				async.eachSeries(
					rows,
					function(row, cb){
						graph.determineIfIncludedOrEqual(conn, row.unit, objUnit.parent_units, function(bIncluded){
							if (bIncluded)
								console.log("checkNoPendingDefinition: unit "+row.unit+" is included");
							bIncluded ? cb("found") : cb();
						});
					},
					function(err){
						(err === "found") 
							? callback("you can't send anything before your last included definition is stable and before last ball (self is nonserial)") 
							: next();
					}
				);
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
