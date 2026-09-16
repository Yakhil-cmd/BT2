Confirmed: `validateAttestorListUpdate` (validation.js:2829-2848) only requires the update be posted by the `definer_address` and pass `checkAttestorList` — it imposes no restriction preventing removal of addresses that currently hold outstanding balances of that asset, including the definer's own address used for the `auto_destroy` burn path. [1](#0-0) 

## Analysis

The `spender_attested` asset mechanism in ocore is functionally a whitelist: only addresses on the current `attestors`-approved list may hold/move a `spender_attested` asset's coins. The whitelist (`asset_attestors`) can be updated at will and at any time by the asset definer via an ordinary `asset_attestors` unit message, validated only by `validateAttestorListUpdate`, which checks nothing about existing balances. [1](#0-0) 

That whitelist is enforced symmetrically and unconditionally on **every** payment of the asset — both on the spending owner (input side) and on **every recipient address of every output**, with no special-casing for the burn/return-to-definer exit path (`auto_destroy`): [2](#0-1) [3](#0-2) 

The `auto_destroy` mechanism's only escape valve for holders of a non-transferable/private asset is to send their coins back to `objAsset.definer_address` (this is what "returns"/"destroys" the coins): [4](#0-3) 

But because the `spender_attested` output check (`storage.filterAttestedAddresses` requiring **all** `arrOutputAddresses` to be attested) runs unconditionally whenever `objAsset.spender_attested` is true — regardless of whether the destination is the definer itself — a holder cannot even complete the burn/return step if the definer's own address is not (or is no longer) on the current attestor list. Likewise, if the holder's own address is later removed from the attestor list (e.g., the attestor/definer decides the holder is no longer trusted), the input-side check (`owner address is not attested`) blocks that holder from moving the coins anywhere at all, including to destroy/return them. [5](#0-4) 

This is loaded dynamically at validation time from the *latest stable* attestor list (`storage.readAsset` → `addAttestorsIfNecessary`, which always re-reads the most recent `asset_attestors` unit), not the list in effect when the holder acquired the coins: [6](#0-5) 

So exactly like the Blueberry finding — where removing a token from a governance-controlled whitelist blocked the "safe" `repay` exit path while leaving the "unsafe" `liquidate` path unaffected — here, removing an address (the holder, or even the definer/burn address) from the attestor whitelist permanently blocks the holder's only exit path (returning/destroying the asset to the definer), while the definer retains unilateral, unrestricted power to change the list at any time with no grace period, no exemption for existing balances, and no way for the affected holder to recover or exit.

### Title
Attestor whitelist changes can permanently block a holder's only exit/return path for `spender_attested` assets - (File: validation.js)

### Summary
`spender_attested` assets restrict who may hold and move coins to addresses on an attestor whitelist that the asset definer can update at any time via an `asset_attestors` message. The whitelist check is applied unconditionally to every input owner and every output recipient of every payment, including the only escape path available to holders of non-transferable, `auto_destroy` assets: sending the coins back to the definer address. If the definer removes the holder's address, or removes/never includes their own definer address, from the attestor list, the holder's outstanding balance becomes permanently unmovable — it cannot be transferred, and it cannot even be returned/destroyed via the designated burn path.

### Finding Description
`validatePaymentInputsAndOutputs` enforces the `spender_attested` restriction symmetrically on inputs and outputs with no exception for the definer-return/`auto_destroy` flow:
- Input side: `if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1) return cb("owner address is not attested");` [5](#0-4) 
- Output side: for any `spender_attested` asset, all output addresses (including the definer address used to destroy/return coins) must be attested, or the whole payment is rejected: [3](#0-2) 

The attestor list itself is fully mutable by the definer with no protections for existing holders: `validateAttestorListUpdate` only checks that the caller is the definer and the new list is well-formed — it does not check whether removed addresses currently hold a balance, nor prevent removing the definer's own address from a list it belongs to: [1](#0-0) 

The check is evaluated against the *current* stable attestor list at validation time (not the list at the time coins were acquired), read via `storage.readAsset`: [6](#0-5) 

Since the only sanctioned way to relinquish a non-transferable/`auto_destroy` asset is a payment whose sole output goes to `objAsset.definer_address` [4](#0-3) , and that payment is itself subject to the same output-attestation check, a definer can trap holders' funds by simply editing the attestor list.

### Impact Explanation
An asset holder can lose all practical ability to move or dispose of their `spender_attested` asset balance — not merely restricted from new transfers but unable to exercise the built-in exit/destroy mechanism either — resulting in permanent freezing of funds with no recovery path available to the affected unprivileged holder. This matches the required impact class of AA/asset fund freezing caused by a state (whitelist) change that the affected party cannot control or work around.

### Likelihood Explanation
Likelihood is moderate-to-high in practice for any `spender_attested` asset ecosystem: the definer already has unilateral control over the attestor list as part of normal asset administration (e.g., de-listing a compromised or non-compliant attestor/holder), and nothing in validation prevents an update that also removes the definer's own listing or an existing holder's listing. No special privileges beyond being the asset's definer are required to trigger the freeze, and any holder of the asset is reachable by this issue.

### Recommendation
Exempt the definer-return / `auto_destroy` payment path from the output-side `spender_attested` check (a payment whose only output is to `objAsset.definer_address` should always be allowed regardless of attestor status), and/or evaluate the holder's own input-side attestation using the list in effect when the coins were most recently received rather than only the current list, so that removal from the whitelist cannot strand a holder's existing balance with no exit.

### Proof of Concept
1. Definer creates a `spender_attested`, `is_transferrable: false`, `auto_destroy: true` asset with attestors `[A, D]` where `D` is the definer's own address.
2. Attestor issues attestation for address `H`; `H` receives asset units (input owner `H` is attested — passes the input check, and issuance/first transfer succeeds because `D`/`A` and `H` are attested).
3. Definer posts an `asset_attestors` update removing `D` (or removing `H`) from the attestor list — allowed unconditionally by `validateAttestorListUpdate` since it only checks the caller is the definer and the list format is valid.
4. `H` attempts the standard exit: pay all held units back to `D` (the `auto_destroy`/return mechanism). Validation now fails at the output check (`some output addresses are not attested`, because `D` is no longer attested) or at the input check if `H` was removed (`owner address is not attested`).
5. `H`'s balance is now permanently unmovable — it can neither be transferred (asset is `is_transferrable: false`) nor destroyed/returned (blocked by the attestor check), with no code path allowing recovery.

### Citations

**File:** validation.js (L2504-2510)
```javascript
							if (objAsset && objAsset.auto_destroy && owner_address === objAsset.definer_address)
								return cb("this output was destroyed by sending it to definer address");
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
								return cb("owner address is not attested");
							if (arrInputAddresses.indexOf(owner_address) === -1)
								arrInputAddresses.push(owner_address);
							total_input += src_output.amount;
```

**File:** validation.js (L2616-2629)
```javascript
				if (!objAsset.is_transferrable){ // the condition holds for issues too
					if (arrInputAddresses.length === 1 && arrInputAddresses[0] === objAsset.definer_address
					   || arrOutputAddresses.length === 1 && arrOutputAddresses[0] === objAsset.definer_address
						// sending payment to the definer and the change back to oneself
					   || !(objAsset.fixed_denominations && objAsset.is_private) 
							&& arrInputAddresses.length === 1 && arrOutputAddresses.length === 2 
							&& arrOutputAddresses.indexOf(objAsset.definer_address) >= 0
							&& arrOutputAddresses.indexOf(arrInputAddresses[0]) >= 0
					   ){
						// good
					}
					else
						return callback("the asset is not transferrable");
				}
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
