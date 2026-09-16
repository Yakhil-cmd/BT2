## Title
Asset definer can permanently brick the attestor list of a `spender_attested` asset, freezing every holder's funds forever - (File: `validation.js`, `definition.js`)

## Summary
An asset's `spender_attested` flag is set once at issuance and can never be turned off, and only the asset's `definer_address` is allowed to update the attestor list going forward. Since address definitions can be changed to conditions that are permanently unsatisfiable (e.g. `['seen address', X]` for an address `X` that will never post a unit), a malicious or compromised asset definer can self-brick its own `definer_address` right after locking in a hostile/expired attestor list. This is the exact structural analog of the Biconomy `pause()` + `renouncePauser()` bug: a privileged, single-purpose role permanently disables itself while the system is left in a state that can never recover, and — just like in the original report — not even the "owner" (here, the community/witnesses) can undo it.

## Finding Description
When an asset is defined, `validateAssetDefinition` requires `spender_attested` to be a fixed boolean chosen at issuance time, with no message type ever allowing it to be turned back to `false`: [1](#0-0) 

If `spender_attested` is `true`, every future payment of the asset (including by any innocent, unprivileged holder who simply received the asset) is checked against a list of attested addresses: [2](#0-1) [3](#0-2) 

The only entity ever allowed to update this attestor list is the asset's `definer_address`: [4](#0-3) 

Separately, an address's spending definition can be changed via an `address_definition_change` message, and the new definition only needs to be *syntactically* valid at the time of the change — it does not need to be immediately (or ever) satisfiable: [5](#0-4) 

`definition.js` explicitly allows conditions such as `seen address`, which are only true once the referenced address has authored a stable, good unit: [6](#0-5) [7](#0-6) 

Because the definer controls which address `seen address` (or any similarly unreachable combination of conditions) points to, they can choose an address that is guaranteed to never author a unit (e.g. a freshly generated keypair whose private key they discard, or one they simply commit to never using). Once that definition change is confirmed, `definer_address` can never again produce a valid authentifier, exactly like Alice calling `renouncePauser()`.

## Impact Explanation
Combining the two facts:
1. `spender_attested` can never be reverted once set (`validation.js:2725-2733`).
2. The attestor list can only ever be updated by `definer_address` (`validation.js:2829-2848`).

A malicious/compromised definer can:
1. Issue (or already have issued) a `spender_attested` asset that many unprivileged users legitimately hold and transfer.
2. Send an `asset_attestors` update pointing to attestor addresses that will stop attesting anyone (this step is optional if the attestors are already unresponsive/compromised).
3. Send an `address_definition_change` for `definer_address` to a syntactically-valid but permanently unsatisfiable definition (e.g., referencing `seen address` of an address that will never post).

After step 3, no one — not the definer, not the witnesses, not the affected users — can ever submit a valid `asset_attestors` update again, because `unit_authors`/`validateAuthentifiers` can never produce a satisfying signature for that address. Since attestation can then never be granted to any new address, `validatePaymentInputsAndOutputs`'s "owner address is not attested" / "none of the authors is attested" checks will permanently reject every future transfer of that asset for every holder, freezing all funds denominated in that asset irreversibly — the same "cannot be reversed even by the owner" outcome described in the original report.

## Likelihood Explanation
This requires a single privileged party (the asset definer) to act maliciously or be compromised, and requires only two ordinary, protocol-supported messages (`address_definition_change`, optionally `asset_attestors`) that any unit poster is normally allowed to send for their own address. No special network position, consensus manipulation, or third-party cooperation is needed — it's a self-contained, deterministic sequence identical in spirit to the two-call PoC (`pause()` + `renouncePauser()`) in the original report.

## Recommendation
- Disallow an asset's `definer_address` from changing its own definition to one that can never be satisfied is impossible to check in general, so instead:
  - Provide a protocol-level mechanism to permanently or conditionally disable `spender_attested` (or transfer definer rights) via a recovery path not solely gated on `definer_address`'s continued signing ability, or
  - Require that `asset_attestors` updates be authorizable by an alternative/backup mechanism (similar to how `owner` differs from `pauser` in the original report), so a single self-inflicted definition bricking of `definer_address` cannot permanently freeze all holders' funds.
- At minimum, document this risk clearly for asset issuers and holders, since holders of a `spender_attested` asset are fully dependent on the continued liveness and honesty of a single address they do not control.

## Proof of Concept
1. Definer issues asset `A` with `spender_attested: true` and an initial attestor list (`validateAssetDefinition`, `validation.js:2725-2755`); users acquire and hold/transfer asset `A`.
2. Definer (optionally) sends `asset_attestors` pointing attestors to addresses it controls and that will not attest new holders (`validateAttestorListUpdate`, `validation.js:2829-2848`).
3. Definer sends `address_definition_change` changing `definer_address`'s definition to `['seen address', 'ADDRESS_THAT_WILL_NEVER_POST_A_UNIT']` (accepted per `definition.js:345-350` and `validation.js:1719-1745`).
4. From this point on, `definer_address` can never satisfy `validateAuthentifiers` again, so it can never submit another `asset_attestors` update (`validation.js:2841-2842`).
5. Every future `payment` message for asset `A` from any holder fails at `validatePaymentInputsAndOutputs`/`validatePayment` with "owner address is not attested" or "none of the authors is attested" (`validation.js:2115-2122`, `2504-2507`), permanently freezing all holders' balances of asset `A`.

### Citations

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

**File:** validation.js (L2725-2733)
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

**File:** definition.js (L345-350)
```javascript
			case 'seen address':
				if (objValidationState.bNoReferences)
					return cb("no references allowed in address definition");
				if (!isValidAddress(args)) // it is ok if the address was never used yet
					return cb("invalid seen address");
				return cb();
```

**File:** definition.js (L821-833)
```javascript
			case 'seen address':
				// ['seen address', 'BASE32']
				var seen_address = args;
				conn.query(
					"SELECT 1 FROM unit_authors CROSS JOIN units USING(unit) \n\
					WHERE address=? AND main_chain_index<=? AND sequence='good' AND is_stable=1 \n\
					LIMIT 1",
					[seen_address, objValidationState.last_ball_mci],
					function(rows){
						cb2(rows.length > 0);
					}
				);
				break;
```
