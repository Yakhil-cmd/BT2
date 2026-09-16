This confirms the analog. In `ocore`, the `spender_attested` asset feature is exactly analogous to a token blacklist/whitelist controlled by a third party (the attestor), and I found the exact validation path that permanently freezes funds when an address's attestation is withdrawn.

### Title
Attestor-revocable `spender_attested` assets permanently freeze holder funds with no recovery path - (File: `validation.js`)

### Summary
An asset defined with `spender_attested: true` restricts who may hold/spend it to addresses currently attested by the asset's designated attestors, per `initial-db/*.sql` schema comment "must subsequently publish and update the list of trusted attestors". [1](#0-0)  The attestor list can be freely rewritten at any time via an `asset_attestors` message, checked only by `validateAttestorListUpdate`, which requires nothing but the asset definer's signature. [2](#0-1)  Because attestation is evaluated using the *current* (last-ball) attestor list rather than the list in effect when funds were received, any address (including an AA) that legitimately received `spender_attested` funds can be retroactively excluded and lose all ability to spend that balance.

### Finding Description
When validating a payment of a `spender_attested` asset, `validatePayment` requires the spending author(s) to be attested at validation time via `storage.loadAssetWithListOfAttestedAuthors`/`filterAttestedAddresses`, otherwise the unit is rejected with "none of the authors is attested" or, for individual inputs, "owner address is not attested". [3](#0-2)  The same check is enforced per-input in `validatePaymentInputsAndOutputs`: [4](#0-3)  and per-output on the receiving side: [5](#0-4) 

`filterAttestedAddresses` computes attestation status dynamically against the current stable state (`SELECT ... WHERE attestor_address IN(?) AND address IN(?) AND main_chain_index<=? AND is_stable=1 ...`), so it reflects only the *latest* published attestor decision, not the state at the time the balance was acquired. [6](#0-5) 

The attestor list itself is mutable at will: `validateAttestorListUpdate` only checks that the asset exists, requires attestors, and that the author is the asset definer — there is no restriction preventing the definer/attestor from removing a previously-attested address (analogous to "blacklisting" a holder) after that holder already received funds. [2](#0-1) 

Once an address is removed from the attestor list, every future attempt to spend its existing balance of that asset will fail unit validation with "owner address is not attested," with no override, no bypass output, and no way to reassign the balance — the funds are permanently stuck at that address. This applies equally to a regular user address and to an Autonomous Agent, since AAs use the identical `storage.loadAssetWithListOfAttestedAuthors` / attestation-checking code path when composing and validating their own payments. [7](#0-6) 

### Impact Explanation
This directly matches the reported bug class ("if the user is added to the blacklist, then his assets will be frozen"): a third party (the asset definer/attestor) can unilaterally and retroactively strip an address's spending rights over an asset it legitimately holds, freezing those funds forever, with the affected party having no recourse in-protocol. If the frozen address is an AA, any protocol funds (deposits, collateral, etc.) denominated in that asset held by the AA become permanently unspendable, which can brick AA logic relying on that balance. This is a High severity fund-freezing issue reachable by any unprivileged asset definer/attestor over any user or AA that accepted their asset.

### Likelihood Explanation
Likelihood is moderate-to-high: any user can define a `spender_attested` asset (`validateAssetDefinition`) [8](#0-7)  and freely update its attestor list at any time via a simple single-message `asset_attestors` unit signed by the definer [2](#0-1) . No cooperation from the target holder is required — the freeze happens purely through attestor-list rewriting, which is a normal, protocol-sanctioned operation.

### Recommendation
Consider evaluating `spender_attested` eligibility against the attestor list that was current when the balance/output was created (i.e., snapshot attestation status at receipt time) rather than re-checking against the latest list at every subsequent spend, or provide a defined mechanism (e.g., an explicit "unfreeze"/burn-and-reissue path) so a holder de-attested after receiving funds is not permanently locked out. At minimum, documentation should make explicit to asset issuers and AA authors that `spender_attested` assets carry an inherent, attestor-controlled freezing risk so authors of AAs avoid holding balances of such assets in ways that can brick their contract logic.

### Proof of Concept
1. Definer creates asset `A` with `spender_attested: true` and attestor `X`. [8](#0-7) 
2. Attestor `X` attests address `U` (e.g., a normal user or an AA address). `U` receives a payment of asset `A`, which validates successfully because `U` is currently attested. [3](#0-2) 
3. Definer later posts `asset_attestors` for asset `A` with a new attestor list that no longer includes `X`, or `X` stops re-attesting `U` while a new attestor is chosen who never attests `U`. This update is valid as long as it's signed by the definer. [2](#0-1) 
4. `U` now attempts to spend its previously-received balance of asset `A`. `filterAttestedAddresses`/`loadAssetWithListOfAttestedAuthors` finds `U` is no longer attested under the current list, and `validatePayment`/`validatePaymentInputsAndOutputs` reject the unit with "owner address is not attested" / "none of the authors is attested". [4](#0-3) [6](#0-5) 
5. `U`'s balance of asset `A` is now permanently unspendable — frozen in the protocol with no recovery mechanism.

### Citations

**File:** initial-db/byteball-mysql.sql (L238-248)
```sql
CREATE TABLE assets (
	unit CHAR(44) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL PRIMARY KEY,
	message_index TINYINT NOT NULL,
	cap BIGINT NULL,
	is_private TINYINT NOT NULL,
	is_transferrable TINYINT NOT NULL,
	auto_destroy TINYINT NOT NULL,
	fixed_denominations TINYINT NOT NULL,
	issued_by_definer_only TINYINT NOT NULL,
	cosigned_by_definer TINYINT NOT NULL,
	spender_attested TINYINT NOT NULL, -- must subsequently publish and update the list of trusted attestors
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

**File:** validation.js (L2504-2507)
```javascript
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

**File:** aa_composer.js (L1323-1330)
```javascript
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
```
