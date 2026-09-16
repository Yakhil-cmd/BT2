This confirms the mechanism sufficiently. I have what I need to write the final answer.

## Title
AA Pools That Accept Externally-Attested (`spender_attested`) Assets Can Have Deposits Permanently Frozen by the Asset Issuer — Analog of Freeze-Authority DoS - ([File: validation.js](validation.js), [File: aa_composer.js](aa_composer.js))

### Summary
Obyte's asset model provides an on-chain analog of an SPL "freeze authority": an asset can be created with `spender_attested: true`, meaning every future *output* address of that asset must be on an attestor-controlled allow-list. Crucially, this allow-list is **not fixed at asset-creation time** — the asset's definer can republish it at any time via an `asset_attestors` message [1](#0-0) . An AA "pool" that accepts and holds such an asset as a tradable balance (the documented `uniswap_like_market_maker.oscript` pattern is exactly this) has no way to prevent, detect, or work around a subsequent revocation of attestation for its own address or for a depositor's address, resulting in permanently frozen pool funds — the same impact described in the reported freeze-authority DoS.

### Finding Description
When a payment message references an asset, `validatePayment` loads the asset's live attestor state via `storage.loadAssetWithListOfAttestedAuthors` [2](#0-1) , and `validatePaymentInputsAndOutputs` enforces that **every output address** be attested before the unit can be valid:
```
if (!objAsset.spender_attested) return cb();
storage.filterAttestedAddresses(conn, objAsset, objValidationState.last_ball_mci, arrOutputAddresses,
    function(arrAttestedOutputAddresses){
        if (arrAttestedOutputAddresses.length !== arrOutputAddresses.length)
            return cb("some output addresses are not attested");
        cb();
    }
);
``` [3](#0-2) 

The attestor list itself is asset-scoped state that only the asset's `definer_address` may update, at any mci, by publishing a new `asset_attestors` message:
```
if (!objAsset.spender_attested) return callback("this asset does not require attestors");
if (objUnit.authors[0].address !== objAsset.definer_address) return callback("attestor list can be edited only by definer");
``` [4](#0-3) 

`storage.readAsset`/`addAttestorsIfNecessary` always resolves to the *latest* stable attestor-list unit for the asset, not the one in effect at deposit time [5](#0-4) .

An AA that is built to hold and pay out such an asset — exemplified by the repo's own sample AA, which trades an arbitrary asset hash as a liquidity-pool balance without validating any of its issuer-controlled properties (`spender_attested`, `attestors`, `cosigned_by_definer`, `issue_condition`/`transfer_condition`) — is fully exposed:
```
init: `{ $asset = 'n9y3VomFeWFeZZ2PcSEcmyBb/bI7kzZduBJigNetnkY='; ... }`
...
{ // divest MM shares
  messages: [{ app: 'payment', payload: { asset: "{$asset}", outputs: [{address: "{trigger.address}", amount: ...}] } }]
}
``` [6](#0-5) 

Nothing in `aa_composer.js`'s `handleTrigger`/`bounce` logic special-cases this: on a validation failure of the response unit (e.g., "some output addresses are not attested"), the AA can only bounce back what was included in the *current* trigger, based on `bounce_fees`, and cannot deliver the previously-deposited `$asset` balance it is holding, since any output of that asset to any unattested address is unconditionally rejected by validation [7](#0-6) . Because the asset's own protocol rules ("must subsequently publish and update the list of trusted attestors" — as noted in the schema comment) let the issuer add/remove any address from that list at will, and because that same issuer, not the pool, controls this list, a single `asset_attestors` unit from the issuer/attestor is enough to make part or all of the pool's balance of that asset permanently unpayable to some or all counterparties.

### Impact Explanation
Any AA that accepts a `spender_attested` asset as tradable/depositable balance (pools, AMMs, escrow, bonding curves) inherits an externally-controlled freeze switch:
- The asset issuer can revoke attestation for the AA's own address, blocking new deposits.
- The asset issuer can revoke attestation for individual depositor addresses after they've deposited, permanently blocking those depositors from ever withdrawing their share of that asset from the pool (the AA has no override — the underlying protocol validation rejects the payout unconditionally).
- Because the attestor list is mutable at any time (not locked at genesis), holders/pools cannot rely on any point-in-time attestation snapshot; funds already locked into the pool remain subject to this control indefinitely.

This is a direct analog of "Risk of Input Token Mint with Freeze Authority Leading to Permanent DoS" — permanent loss/freezing of already-deposited user funds, caused by relying on an asset whose issuer retains unilateral, dynamically-updatable spending-authorization control.

### Likelihood Explanation
Reaching this requires only two ordinary, unprivileged actions already supported by the protocol: (1) an asset issuer defining a `spender_attested` asset and publishing/updating its `attestors` list (`asset_attestors` message, single-authored, only by the definer — no cross-chain compromise needed) [8](#0-7) , and (2) any user/pool interacting with that asset via normal payment/trigger messages. No malicious node, hub, or peer is needed — the "attacker" role is simply the asset issuer, one of the explicitly in-scope actors. Any AA design that composes tradable balances from arbitrary externally-defined assets (as the repository's own sample AMM does) is reachable this way.

### Recommendation
1. AAs that accept externally-defined assets as pool balances should validate, at deposit time, that the asset has `spender_attested: false`, no `cosigned_by_definer`, and no issuer-controlled `transfer_condition` that could later be leveraged for censorship equivalent to the on-chain checks already used for other fields (`issued_by_definer_only`, `fixed_denominations`, etc., see `validateAssetDefinition`, `validation.js:2725-2827`), rejecting/bouncing deposits of assets carrying issuer-level freeze capability.
2. Document prominently (in AA-authoring guidance / `aa_validation.js`) that `spender_attested` and `asset_attestors` constitute an issuer-revocable, dynamically-updatable freeze mechanism, and that pool/AMM-style AAs must not treat holding such assets as safe custody unless the pool's own address and expected counterparties are guaranteed to remain attested for the life of the pool.
3. Consider providing AA-facing getters (e.g., a `asset[...]` property or bound function) that let an AA check `spender_attested`/current attestor membership for a given address before accepting/paying out a given asset, so pool logic can defensively reject risky assets or affected addresses instead of unconditionally bouncing (and thereby losing the ability to service other, unaffected withdrawals in the same balance).

### Proof of Concept
1. Issuer publishes an asset `A` with `spender_attested: true`, `attestors: [X]` (`validateAssetDefinition`, `checkAttestorList`).
2. Attestor `X` attests the pool AA's address and User `U`'s address.
3. `U` deposits asset `A` into the pool AA (payment validated because both `U`→pool output and pool state satisfy attestation, per `validatePaymentInputsAndOutputs`).
4. Issuer publishes a new `asset_attestors` message for asset `A` removing `U` (and/or the pool address) from the attestor list — a single-author unit, requires only the definer's signature (`validateAttestorListUpdate`).
5. `U` later sends a trigger to divest/withdraw asset `A` from the pool. The AA composes a payment output of asset `A` to `U`'s address; `validatePaymentInputsAndOutputs` rejects it with "some output addresses are not attested" because `U` is no longer in `arrAttestedAddresses`.
6. The AA's `bounce()` can only refund what was included in the current trigger (e.g., pool-share tokens), not the frozen asset `A` balance now stuck in the pool; `U`'s share of asset `A` is permanently unrecoverable through the pool while the issuer can also indefinitely re-block re-attestation attempts.

### Citations

**File:** validation.js (L2082-2122)
```javascript
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

**File:** storage.js (L1917-1945)
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
```

**File:** test/samples/uniswap_like_market_maker.oscript (L1-93)
```text
{
	init: `{
		$asset = 'n9y3VomFeWFeZZ2PcSEcmyBb/bI7kzZduBJigNetnkY=';
		$mm_asset = var['mm_asset'];
	}`,
	messages: {
		cases: [
			{ // define share asset
				if: `{ trigger.data.define AND !$mm_asset }`,
				messages: [
					{
						app: 'asset',
						payload: {
							// without cap
							is_private: false,
							is_transferrable: true,
							auto_destroy: false,
							fixed_denominations: false,
							issued_by_definer_only: true,
							cosigned_by_definer: false,
							spender_attested: false,
						}
					},
					{
						app: 'state',
						state: `{
							var['mm_asset'] = response_unit;
							response['mm_asset'] = response_unit;
						}`
					}
				]
			},
			{ // invest in MM
				if: `{$mm_asset AND trigger.output[[asset=base]] > 1e5 AND trigger.output[[asset=$asset]] > 0}`,
				init: `{
					$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
					$bytes_balance = balance[base] - trigger.output[[asset=base]];
					if ($asset_balance == 0 OR $bytes_balance == 0){ // initial deposit
						$issue_amount = balance[base];
						return;
					}
					$current_ratio = $asset_balance / $bytes_balance;
					$expected_asset_amount = round($current_ratio * trigger.output[[asset=base]]);
					if ($expected_asset_amount != trigger.output[[asset=$asset]])
						bounce('wrong ratio of amounts, expected ' || $expected_asset_amount || ' of asset');
					$investor_share_of_prev_balance = trigger.output[[asset=base]] / $bytes_balance;
					$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding']);
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{$mm_asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{ $issue_amount }"}
							]
						}
					},
					{
						app: 'state',
						state: `{
							var['mm_asset_outstanding'] += $issue_amount;
						}`
					},
				]
			},
			{ // divest MM shares 
				// (user is already paying 10000 bytes bounce fee which is a divest fee)
				// the price slightly moves due to fees received and paid in bytes
				if: `{$mm_asset AND trigger.output[[asset=$mm_asset]]}`,
				init: `{
					$mm_asset_amount = trigger.output[[asset=$mm_asset]];
					$investor_share = $mm_asset_amount / var['mm_asset_outstanding'];
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{$asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{ round($investor_share * balance[$asset]) }"}
							]
						}
					},
					{
						app: 'payment',
						payload: {
							asset: "base",
							outputs: [
								{address: "{trigger.address}", amount: "{ round($investor_share * balance[base]) }"}
							]
						}
					},
```

**File:** aa_composer.js (L909-945)
```javascript
	var bBouncing = false;
	function bounce(error) {
		console.log('bouncing with error', error, new Error().stack);
		objStateUpdate = null;
		error_message = error_message ? (error_message + ', then ' + error) : error;
		if (trigger_opts.bAir) {
			assignObject(stateVars, originalStateVars); // restore state vars
			assignObject(trigger_opts.assocBalances, originalBalances); // restore balances
			if (!bSecondary) {
				for (let a in trigger.outputs)
					if (bounce_fees[a])
						trigger_opts.assocBalances[address][a] = (trigger_opts.assocBalances[address][a] || 0) + bounce_fees[a];
			}
		}
		if (bBouncing)
			return finish(null);
		bBouncing = true;
		if (bSecondary)
			return finish(null);
		if ((trigger.outputs.base || 0) < bounce_fees.base)
			return finish(null);
		var messages = [];
		// iteration order is standardized since ECMAScript 2020
		for (var asset in trigger.outputs) {
			var amount = trigger.outputs[asset];
			var fee = bounce_fees[asset] || 0;
			if (fee > amount)
				return finish(null);
			if (fee === amount)
				continue;
			var bounced_amount = amount - fee;
			messages.push({app: 'payment', payload: {asset: asset, outputs: [{address: trigger.address, amount: bounced_amount}]}});
		}
		if (messages.length === 0)
			return finish(null);
		sendUnit(messages);
	}
```
