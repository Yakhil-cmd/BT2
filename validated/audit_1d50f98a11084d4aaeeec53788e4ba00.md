### Title
Asset issuer can immediately regrade `spender_attested` attestor lists mid-flight for AA-issued assets, letting an untimelocked change grief already-triggered AA responses - (File: storage.js)

### Summary
The C4 finding describes a privileged (`onlyOwner`) actor that can push a parameter change with *immediate* effect, while the rest of the protocol (bonding/auction flow) assumes a delay, letting the owner unintentionally front‑run `settleAuction()` and cause loss with no recovery path. The reachable analog in ocore is the `spender_attested` asset mechanism: the asset definer (an "asset issuer", one of the allowed privileged actors) can push a new `asset_attestors` list at any time with no timelock, and for assets defined by an AA, `storage.readAsset()` deliberately reads the *unstable* (not-yet-confirmed) attestor list when called from AA context, instead of requiring it to be stable/in the past like it does for ordinary transactions.

### Finding Description
For ordinary (non-AA) validation, `readAsset()` requires the attestor-list unit to be stable and at or before `last_ball_mci`: [1](#0-0) 

But when `bAcceptUnconfirmedAA` is true (the asset is defined by an AA and the read happens from an AA-execution context), the "before_last_ball_cond" filter is dropped entirely, and the *most recent* attestor-list unit is picked by level, regardless of whether it is stable: [2](#0-1) 

This is invoked from `loadAssetWithListOfAttestedAuthors`, which is used both by normal payment validation (`validation.js`) and by AA payment composition (`divisible_asset.js`, `indivisible_asset.js`): [3](#0-2) [4](#0-3) 

Meanwhile, the general asset-attestor validation path (`validateAttestorListUpdate`) imposes no timelock: the definer address can post a brand-new attestor list in a single unit at any moment: [5](#0-4) [6](#0-5) 

So exactly like the report's contrast between the `onlyOwner`-controlled `auctionDecrement`/`auctionMultiplier` (immediate effect) and the bonded-auction flow (1-day timelock), ocore has: (a) an untimelocked, single-unit attestor-list update by the asset definer, and (b) an AA execution/response flow that — unlike ordinary user transactions — is permitted to consume that update *before it is even stable*, purely based on level ordering of unstable units. A trigger sender composing a payment to/through an AA that spends or forwards this `spender_attested` asset cannot know, at trigger-send time, which attestor list will be "current" once the AA actually executes, because the AA is allowed to pick up an attestor-list change that arrives (or is even still unstable) after the trigger was sent but before/while the trigger stabilizes and the AA runs.

### Impact Explanation
An asset issuer (or anyone colluding with/impersonating the definer role for that spender-attested asset) can post a new `asset_attestors` unit timed to land between when a user sends an AA trigger and when the AA response is computed. Because AA-side reads of the attestor list bypass the stability requirement, the AA can:
- Reject the trigger's associated output check ("some output addresses are not attested") after the user has already paid trigger fees and committed funds to the AA, effectively freezing/losing the trigger sender's funds inside the AA's bounce/fee flow, or
- Accept/decline attestation checks inconsistently with what the trigger sender expected when composing the transaction, causing unintended asset transfers or bounced payments with no way for the trigger sender to reclaim exact pre-trigger state.

This matches the report's core harm: a privileged, untimelocked state change causes unexpected, uncompensated loss for an unprivileged party (the AA trigger sender / asset holder) with no on-chain remedy, and is a griefing/DoS vector the definer can trigger intentionally or accidentally.

### Likelihood Explanation
This requires the asset to be `spender_attested` and defined by an AA (a real, supported ocore feature explicitly guarded by `testnetAssetsDefinedByAAsAreVisibleImmediatelyUpgradeMci` and the AA-definition validation code), and requires the definer to post `asset_attestors` at a time close to trigger execution. Definers are semi-trusted (similar to the acknowledged "owner is assumed trustworthy" caveat in the original report), so likelihood is moderate — it requires a motivated or careless definer, not a fully permissionless attacker, mirroring the original finding's risk profile.

### Recommendation
Require the attestor-list unit used in AA-context (`bAcceptUnconfirmedAA=true`) reads to be at least as stable/confirmed as the trigger's own `last_ball_mci`, i.e., drop the special-case bypass in `readAsset()`'s `addAttestorsIfNecessary(byAA=true)` path, or otherwise pin the attestor list to the state visible at the initial trigger's `last_ball_mci` for the entire life of the AA response chain, so that a definer cannot inject a still-unstable attestor-list change mid-execution.

### Proof of Concept
1. Asset issuer defines asset `X` via an AA with `spender_attested: true`, with attestor `A`.
2. User Bob (holder of asset `X`, attested by `A`) sends an AA trigger paying asset `X` to AA `Z`, which is programmed to forward `X` to another address contingent on being attested.
3. Immediately after Bob's trigger unit is broadcast (before it stabilizes), the asset issuer posts a new `asset_attestors` unit removing attestor `A` / replacing the list.
4. When AA `Z`'s response is composed, `loadAssetWithListOfAttestedAuthors` → `readAsset(..., bAcceptUnconfirmedAA=true)` picks up the issuer's still-unstable attestor-list unit (per `storage.js:1917-1946`), causing the AA's attestation checks to differ from what was true when Bob's trigger was crafted, bouncing/misprocessing Bob's payment and stranding the value Bob already committed to the AA.

### Citations

**File:** storage.js (L1917-1957)
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

		if (objAsset.main_chain_index !== null && objAsset.main_chain_index <= last_ball_mci)
			return addAttestorsIfNecessary();
		// && objAsset.main_chain_index !== null below is for bug compatibility with the old version
		if (!bAcceptUnconfirmedAA || constants.bTestnet && last_ball_mci < testnetAssetsDefinedByAAsAreVisibleImmediatelyUpgradeMci && objAsset.main_chain_index !== null)
			return handleAsset("asset definition must be before last ball");
		readAADefinition(conn, objAsset.definer_address, last_ball_mci, function (arrDefinition) {
			arrDefinition ? addAttestorsIfNecessary(true) : handleAsset("asset definition must be before last ball (AA)");
		});
	});
}
```

**File:** storage.js (L1977-1992)
```javascript
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

**File:** validation.js (L2033-2042)
```javascript
		case "asset_attestors":
			if (!isStringOfLength(payload.asset, constants.HASH_LENGTH))
				return callback("invalid asset in attestor list update");
			if (!objValidationState.assocHasAssetAttestors)
				objValidationState.assocHasAssetAttestors = {};
			if (objValidationState.assocHasAssetAttestors[payload.asset])
				return callback("can be only one asset attestor list update per asset");
			objValidationState.assocHasAssetAttestors[payload.asset] = true;
			validateAttestorListUpdate(conn, payload, objUnit, objValidationState, callback);
			break;
```

**File:** validation.js (L2079-2124)
```javascript
	if (!isStringOfLength(payload.asset, constants.HASH_LENGTH))
		return callback("invalid asset");
	
	var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
	// note that light clients cannot check attestations
	storage.loadAssetWithListOfAttestedAuthors(conn, payload.asset, objValidationState.last_ball_mci, arrAuthorAddresses, objValidationState.bAA, function(err, objAsset){
		if (err)
			return callback(err);
		if (hasFieldsExcept(payload, ["inputs", "outputs", "asset", "denomination"]))
			return callback("unknown fields in payment message");
		if (objAsset.fixed_denominations){
			if (!isPositiveInteger(payload.denomination))
				return callback("no denomination");
		}
		else{
			if ("denomination" in payload)
				return callback("denomination in arbitrary-amounts asset")
		}
		if (!!objAsset.is_private !== !!objValidationState.bPrivate)
			return callback("asset privacy mismatch");
		var bIssue = (payload.inputs[0].type === "issue");
		var issuer_address;
		if (bIssue){
			if (arrAuthorAddresses.length === 1)
				issuer_address = arrAuthorAddresses[0];
			else{
				issuer_address = payload.inputs[0].address;
				if (arrAuthorAddresses.indexOf(issuer_address) === -1)
					return callback("issuer not among authors");
			}
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
		validatePaymentInputsAndOutputs(conn, payload, objAsset, message_index, objUnit, objValidationState, callback);
	});
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
