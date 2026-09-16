## Analysis

The C4 finding centers on a single root cause: **a trusted counterparty can unilaterally swap out a critical verification parameter (the price oracle) after another party has already relied on and committed value under the original parameter**, letting the trusted party retroactively bias the very check that is supposed to protect the other side.

Searching `ocore`'s reachable, unprivileged-triggerable surfaces (asset issuance/transfer conditions, data feeds, AA definitions, address definitions) for an equivalent pattern, the closest structural analog is the `asset_attestors` message, which lets an asset's `definer_address` change the trusted-attestor list ("oracle" for spend authorization) for a `spender_attested` asset at any time, including long after other addresses have already acquired and are holding that asset.

### Title
Asset definer can unilaterally change the trusted attestor list after issuance, freezing existing holders' funds - (File: validation.js)

### Summary
For assets with `spender_attested: true`, spend/transfer validity is gated by whether the payer/payee addresses are attested by the asset's current attestor list. The definer can post an `asset_attestors` message at any time to replace that list, with no check tying the new attestors to the ones in effect when other users already acquired and are holding the asset.

### Finding Description
`validateAttestorListUpdate` only checks that the message is single-authored, well-formed, that the asset actually requires attestors, and that the author is the asset's `definer_address`: [1](#0-0) 

There is no restriction on *when* this can happen and no requirement that it preserve attestation status for addresses that already hold outstanding balances of the asset. This is directly analogous to `NFTPairWithOracle.updateLoanParams()` allowing the lender to swap `params.oracle` post-agreement without checking `params.oracle == cur.oracle`: in both cases a single trusted counterparty (lender / asset definer) can change the reference used by a downstream validity check (loan-seizure price feed / spend attestation) after another party (borrower / token holder) has already committed value based on the original reference.

At spend time, `validatePaymentInputsAndOutputs` re-evaluates attestor status live against whatever attestor list is currently in force, not the one in force when the asset was acquired: [2](#0-1) [3](#0-2) 

`storage.filterAttestedAddresses`/`loadAssetWithListOfAttestedAuthors` likewise always resolve against the attestor set current at `last_ball_mci`, not the historical set: [4](#0-3) 

### Impact Explanation
A malicious or compromised definer can:
1. Issue/transfer a `spender_attested` asset while a broad attestor set exists, causing many addresses to become attested holders.
2. Later post `asset_attestors` naming a completely different, narrow attestor set (e.g., only the definer's own alt address, or attestors who will never attest the existing holders).
3. From that point on, every existing holder's output fails `some output addresses are not attested` in `validatePaymentInputsAndOutputs`, permanently freezing their balances, while the definer (or addresses newly and selectively attested) retains full control and can still transact.

This is a direct "freezing of funds" impact on unprivileged asset holders caused entirely by an action of a single privileged-but-unprivileged-to-them counterparty (the definer), mirroring the report's "lender freely changes the trusted reference after the deal is locked in, to the counterparty's detriment."

### Likelihood Explanation
Likelihood is high for any asset explicitly advertised or perceived as fully-transferable, since nothing in validation, in the wallet-composition flow, or in `storage.readAsset`/`loadAssetWithListOfAttestedAuthors` warns holders that the attestor list is mutable at any time by the definer alone. Any dApp or user holding a `spender_attested` asset is exposed the moment the definer decides to post a new `asset_attestors` message; no cooperation or unusual conditions from the holder are required.

### Recommendation
- Require attestor-list continuity (or a delayed activation with a grace period) so that addresses already attested/holding the asset before an `asset_attestors` update remain attested for spending purposes for existing balances, or
- Require that `asset_attestors` updates be balanced against a documented/queryable "effective attestor set at acquisition time" so wallets/dApps can detect and warn about rug-pull-style attestor changes, and
- At minimum, emit/require this risk to be surfaced in `readAssetInfo`/`loadAssetWithListOfAttestedAuthors` consumers so composing code (e.g. `divisible_asset.js`) can bail out if the attestor set changed since acquisition.

### Proof of Concept
1. Definer `D` creates asset `A` with `spender_attested: true` and initial `attestors: [D2]` (an address `D` also controls or that trusts many participants). [5](#0-4) 
2. Many independent users acquire and hold balances of `A`, verified only against the then-current attestor set via `filterAttestedAddresses`. [6](#0-5) 
3. `D` posts an `asset_attestors` message changing `attestors` to `[D3]`, an address that will never attest the existing holders. [7](#0-6) 
4. Any subsequent attempt by existing holders to spend/transfer their balance of `A` fails `"some output addresses are not attested"` in `validatePaymentInputsAndOutputs`, permanently freezing their holdings, while `D` can attest new addresses of its choosing and continue to use the asset unimpeded. [2](#0-1)

### Citations

**File:** validation.js (L2506-2507)
```javascript
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
								return cb("owner address is not attested");
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

**File:** validation.js (L2725-2750)
```javascript
function validateAssetDefinition(conn, payload, objUnit, objValidationState, callback){
	if (objUnit.authors.length !== 1)
		return callback("asset definition must be single-authored");
	if (!isNonemptyObject(payload))
		return callback("asset definition must be a non-empty object");
	if (hasFieldsExcept(payload, ["cap", "is_private", "is_transferrable", "auto_destroy", "fixed_denominations", "issued_by_definer_only", "cosigned_by_definer", "spender_attested", "issue_condition", "transfer_condition", "attestors", "denominations"]))
		return callback("unknown fields in asset definition");
	if (typeof payload.is_private !== "boolean" || typeof payload.is_transferrable !== "boolean" || typeof payload.auto_destroy !== "boolean" || typeof payload.fixed_denominations !== "boolean" || typeof payload.issued_by_definer_only !== "boolean" || typeof payload.cosigned_by_definer !== "boolean" || typeof payload.spender_attested !== "boolean")
		return callback("some required fields in asset definition are missing");

	if ("cap" in payload && !(isPositiveInteger(payload.cap) && payload.cap <= constants.MAX_CAP))
		return callback("invalid cap");

	if (objValidationState.bAA) {
		if (payload.cosigned_by_definer !== false)
			return callback("cosigned_by_definer must be false because AAs can't cosign");
		if (payload.issued_by_definer_only === true && (payload.is_private !== false || payload.fixed_denominations !== false))
			return callback("assets issued by AA definer cannot be private or fixed denominations");
	}

	// attestors
	var err;
	if ( payload.spender_attested && (err=checkAttestorList(payload.attestors)) )
		return callback(err);
	if (!payload.spender_attested && "attestors" in payload && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
		return callback("attestors should not be defined when spender_attested is false");
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

**File:** storage.js (L1959-1991)
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

// note that light clients cannot check attestations
function loadAssetWithListOfAttestedAuthors(conn, asset, last_ball_mci, arrAuthorAddresses, bAcceptUnconfirmedAA, handleAsset){
	if (arguments.length === 5) {
		handleAsset = bAcceptUnconfirmedAA;
		bAcceptUnconfirmedAA = false;
	}
	readAsset(conn, asset, last_ball_mci, bAcceptUnconfirmedAA, function(err, objAsset){
		if (err)
			return handleAsset(err);
		if (!objAsset.spender_attested)
			return handleAsset(null, objAsset);
		filterAttestedAddresses(conn, objAsset, last_ball_mci, arrAuthorAddresses, function(arrAttestedAddresses){
			objAsset.arrAttestedAddresses = arrAttestedAddresses;
			handleAsset(null, objAsset);
		});
	});
```
