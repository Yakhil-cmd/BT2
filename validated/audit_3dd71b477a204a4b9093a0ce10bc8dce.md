### Title
Asset attestor-list update can freeze already-held asset funds without any balance check - (File: validation.js)

### Summary
The `asset_attestors` message lets an asset's definer unilaterally replace the list of trusted attestors for a `spender_attested` asset at any later main-chain point, with no check for whether existing coin/output holders (including AAs) that rely on the *current* attestor list to prove they are attested still hold balances of that asset. This mirrors the Union Finance bug class: removing a component (an attestor, analogous to the removed adapter/token) without verifying whether it still "backs" funds already held by users, causing those funds to be permanently frozen.

### Finding Description
`validateAttestorListUpdate` only checks that the message is single-authored, the asset requires attestors, and the author is the asset definer — it performs no check on the impact of the change on addresses that currently hold, or previously received, coins of the asset: [1](#0-0) 

Spend validity for `spender_attested` assets is always evaluated against the asset's *current* attestor list, not the list that was active when the address received its funds. `loadAssetWithListOfAttestedAuthors`/`filterAttestedAddresses` query `attestor_address IN (?)` using `objAsset.arrAttestorAddresses`, which is read fresh via `storage.readAsset` at the `last_ball_mci` of the spending unit: [2](#0-1) 

This freshly-read (current) attestor list is then enforced as a hard requirement to spend the asset: for indivisible/private assets, each input's owner address must appear in `arrAttestedAddresses`: [3](#0-2) 
and for divisible assets, every output address of a transfer must be attested: [4](#0-3) 

Because the attestor list can be freely replaced by the definer post-issuance (`case "asset_attestors"` inserts a brand-new `asset_attestors` row set, and `readAsset`/`filterAttestedAddresses` always use the newest set as of the spending unit's last ball), any address (including an AA address) that received the asset while attested by attestor A, but is not attested by the new list after A is dropped, permanently loses the ability to spend that balance — the funds are stuck exactly like a removed adapter/token that still silently holds value in the vulnerable Solidity code.

### Impact Explanation
If an AA holds a balance of a `spender_attested` custom asset (a normal, expected usage pattern for AAs interacting with third-party assets), and the asset definer later updates the attestor list (dropping the attestor that had attested the AA's address, or replacing it entirely), the AA's existing balance in that asset becomes permanently unspendable: any `payment` message the AA tries to send in that asset will fail validation because the AA's address is no longer in `arrAttestedAddresses`, even though the funds were legitimately received earlier. This is a concrete case of AA fund freezing with no way to recover, matching the "funds locked indefinitely" impact of the original report.

### Likelihood Explanation
No special privilege beyond being the asset's own definer is required — this is an ordinary, permitted action (`asset_attestors` message, single-authored by definer) that any asset issuer can perform at any time after issuance, and it is expected/normal for definers to periodically rotate attestors. There is no check anywhere in `validateAttestorListUpdate` or in the payment/asset code for the presence of outstanding balances tied to attestors being removed, so the freeze can happen unintentionally during routine attestor rotation, not just via malicious intent.

### Recommendation
Before allowing an attestor-list update (or add a mandatory transition rule), consider one of:
- Track attestation status at the time funds were received (or at time of a "seen" snapshot) rather than re-checking against the live/current attestor list on every future spend, so previously attested holders remain able to move funds they already own.
- Require/allow addresses to "re-qualify" via a fresh attestation from any attestor that was valid at time of receipt in addition to the current list, so a definer's list change cannot retroactively invalidate already-received balances.
- At minimum, document and strongly discourage attestor-list changes that would strand outstanding balances, and provide tooling/data feeds so definers can check current holder attestation status (`arrAttestedAddresses`) before publishing an `asset_attestors` update.

### Proof of Concept
1. Definer issues asset `X` with `spender_attested: true`, `attestors: [A]`.
2. Address `H` (a plain wallet or an AA) is attested by `A` and later receives a payment of asset `X`, which is validated successfully because `H` is in `arrAttestedAddresses` at that time (per `filterAttestedAddresses`, `validation.js:2630-2641` or `2430-2433`).
3. Definer posts an `asset_attestors` message for asset `X` setting `attestors: [B]` (removing `A`). `validateAttestorListUpdate` (`validation.js:2829-2848`) accepts this unconditionally as long as it's signed by the definer.
4. `H` (still holding its balance of `X`) is never attested by `B`. Any subsequent attempt by `H` to spend `X` fails validation (`"some output addresses are not attested"` / `"owner address is not attested"`), because `storage.readAsset`/`filterAttestedAddresses` always use the current attestor list, not the list valid when `H` received the funds.
5. `H`'s balance of asset `X` is now permanently unspendable, with no adapter/token-holding-check ever having been performed by the protocol before the attestor removal — directly analogous to the reported Union Finance issue.

### Citations

**File:** validation.js (L2430-2433)
```javascript
						if (objAsset.auto_destroy && owner_address === objAsset.definer_address)
							return cb("this output was destroyed by sending to definer address");
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

**File:** storage.js (L1959-1992)
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
}
```
