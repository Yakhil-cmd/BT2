### Title
Spender-attested assets permanently lock funds when an address loses attestation, with no definer/admin override - (File: `validation.js`, `storage.js`)

### Summary
Obyte assets can be created with the `spender_attested` flag, which forces every spender's own address to be currently attested by one of the asset's designated attestors before that address is allowed to move (or receive, in some paths) coins of the asset. This is the ocore analog of Ondo's `checkKYC` gate. Just like the CashManager bug, once an address stops being attested (the "unKYC" event), the coins already sitting on that address become permanently unspendable, and — critically — the asset's `definer` (the closest role to `MANAGER_ADMIN`) has no code path to force a transfer, refund, or otherwise release those funds. Only the attestor voluntarily re-attesting the address can restore access, which is outside protocol control.

### Finding Description
When an asset has `spender_attested: true`, `validatePayment` loads the list of currently-attested authors for the asset and rejects the message if the issuer is not attested: [1](#0-0) 

For non-issue transfers, the *owner* (spending) address of every input must also be currently attested, both for public assets: [2](#0-1) 

and for private fixed-denomination assets, where the pre-populated `src_coin` state is used instead of a DB lookup, but the same unconditional check applies: [3](#0-2) 

The attestation lookup itself only counts attestations issued *after* the address's last definition change and requires the address to be currently attested — there is no fallback or override: [4](#0-3) [5](#0-4) 

Crucially, this `spender_attested` check is completely independent of `cosigned_by_definer`. Even when the asset requires the definer to cosign every transfer (`cosigned_by_definer: true`), the definer's cosignature does not bypass the attestation requirement on the owner address — the checks are separate boolean gates evaluated unconditionally: [6](#0-5) 

The only entity that can modify the *attestor list* is the definer, via `validateAttestorListUpdate`, but changing which addresses are authorized as attestors does nothing to make a *specific stuck address* attested again — that still requires the attestor to post a fresh `attestation` message for that address, an action entirely outside the definer's/admin's control: [7](#0-6) 

This mirrors the Ondo Finance bug precisely: an admin-configured compliance gate (`spender_attested`/KYC) is checked unconditionally on every spend, with no code path granting the trusted privileged role (the asset `definer`) the ability to move or free funds once a user's attestation lapses.

### Impact Explanation
Any holder of a `spender_attested` asset whose attestation is revoked, expires, or is never renewed (e.g., attestor service goes offline, business relationship ends, address definition changes trigger the definition-change cutoff in `filterAttestedAddresses`) has their coins permanently frozen. This is a fund-freezing condition with no recovery path even by the trusted asset issuer, matching the "AA/asset fund freezing with no admin remedy" impact class. This directly affects any legitimate user of a compliance-oriented asset built on ocore's `spender_attested` mechanism (e.g., regulated stablecoins/security tokens issued on Obyte), a foreseeable and intended use case of this feature.

### Likelihood Explanation
`spender_attested` is a first-class, documented asset-definition flag reachable by any asset issuer, and losing attestation is a normal expected event (KYC/AML providers routinely revoke or fail to renew attestations). No special conditions or attacker action are required — this triggers under ordinary, expected asset-issuer/attestor operational behavior, making the likelihood high for any asset that adopts this compliance flag.

### Recommendation
Provide the asset `definer` (or a defined admin/attestor-override condition in `transfer_condition`) with an explicit code path to move/reclaim coins from an address that has lost attestation — for example, allowing `transfer_condition`/`issue_condition` to override the blanket `spender_attested` owner-address check when cosigned by the definer, or documenting/enforcing that `spender_attested` assets must always pair with a definer-controlled recovery condition in their `transfer_condition`. At minimum, clearly document this permanent-freeze risk for asset issuers choosing `spender_attested: true` so they can architect recovery conditions into `issue_condition`/`transfer_condition` at asset-definition time.

### Proof of Concept
1. Definer issues an asset with `spender_attested: true` and attestor `X`, per `validateAssetDefinition`: [8](#0-7) .
2. Attestor `X` attests address `A`; `A` receives a payment of the asset (passes `storage.filterAttestedAddresses` check at output-validation time): [9](#0-8) .
3. Attestor `X` stops attesting `A` (no renewal, or `A`'s address definition changes so old attestations no longer count per the `main_chain_index > definition-change` condition in `filterAttestedAddresses`).
4. `A` attempts to spend the asset: `validatePaymentInputsAndOutputs` looks up `objAsset.arrAttestedAddresses` and finds `A` absent, returning `"owner address is not attested"`: [10](#0-9) .
5. Even if the definer cosigns the transaction (satisfying `cosigned_by_definer`), the same unconditional check still rejects the spend — there is no override path in the codebase for the definer to force movement of `A`'s coins.
6. `A`'s balance of the asset is permanently locked unless attestor `X` chooses to re-attest `A`, which is outside the protocol's or definer's control.

### Citations

**File:** validation.js (L2109-2122)
```javascript
			if (objAsset.issued_by_definer_only && issuer_address !== objAsset.definer_address)
				return callback("only definer can issue this asset");
		}
		if (objAsset.cosigned_by_definer && arrAuthorAddresses.indexOf(objAsset.definer_address) === -1)
			return callback("must be cosigned by definer");
		
		if (objAsset.spender_attested){
			if (conf.bLight && objAsset.is_private) // in light clients, we don't have the attestation data but if the asset is public, we trust witnesses to have checked attestations
				return callback("being light, I can't check attestations for private assets"); // TODO: request history
			if (objAsset.arrAttestedAddresses.length === 0)
				return callback("none of the authors is attested");
			if (bIssue && objAsset.arrAttestedAddresses.indexOf(issuer_address) === -1)
				return callback("issuer is not attested");
		}
```

**File:** validation.js (L2425-2433)
```javascript
						var owner_address = src_coin.src_output.address;
						if (arrAuthorAddresses.indexOf(owner_address) === -1)
							return cb("output owner is not among authors");
						if (denomination !== src_coin.denomination)
							return cb("private denomination mismatch");
						if (objAsset.auto_destroy && owner_address === objAsset.definer_address)
							return cb("this output was destroyed by sending to definer address");
						if (objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
							return cb("owner address is not attested");
```

**File:** validation.js (L2499-2507)
```javascript
							var owner_address = src_output.address;
							if (arrAuthorAddresses.indexOf(owner_address) === -1)
								return cb("output owner is not among authors");
							if (denomination !== src_output.denomination)
								return cb("denomination mismatch");
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
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

**File:** validation.js (L2725-2755)
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

	// denominations
	if (payload.fixed_denominations && !isNonemptyArray(payload.denominations))
		return callback("denominations not defined");
	if (!payload.fixed_denominations && "denominations" in payload)
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

**File:** storage.js (L1976-1992)
```javascript
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
}
```
