## Title
Unstable/unconfirmed attestor list accepted for AA-defined `spender_attested` assets bypasses the "before last ball / stable" authorization check - (File: storage.js)

### Summary
`readAsset()` in `storage.js` selects the attestor list for a `spender_attested` asset with a filter that depends on whether the asset was defined by an unconfirmed AA (`byAA`). When `byAA` is true, the `before_last_ball_cond` clause that normally restricts the attestor-list lookup to `main_chain_index<=last_ball_mci AND is_stable=1` is dropped entirely, so the query only requires `sequence='good'` with no stability/finality requirement.

### Finding Description
`readAsset()` computes the attestor list that gates spending of a `spender_attested` asset: [1](#0-0) 

The `before_last_ball_cond` is the authorization gate that is supposed to ensure the attestor list used for spend/issue checks is a finalized, agreed-upon piece of DAG history (`is_stable=1 AND main_chain_index<=last_ball_mci`), analogous to a feature/permission flag that must be enabled and confirmed before it can be trusted: [2](#0-1) 

When the asset is defined by an AA and accessed through the `bAcceptUnconfirmedAA` path (`addAttestorsIfNecessary(true)`), this stability/finality gate is unconditionally removed (`before_last_ball_cond = ""`), meaning:
- The query can select an `asset_attestors` unit that is not yet stable, not before the current last ball, or even one on a losing/temporary sequence branch (only `sequence='good'` is required, which for not-yet-stable units is only a `temp-good`/tentative state, not final).
- Different nodes evaluating the same trigger/response at different points in DAG propagation, or with different views of not-yet-stable units, can select **different** attestor-list units as the "latest" one (`ORDER BY ... DESC LIMIT 1`), because the set of visible unstable units differs across nodes.

This function is used by both `readAsset` and `loadAssetWithListOfAttestedAuthors`, which are called from the AA trigger-execution path (`aa_composer.js`) whenever an AA composes a payment message for a `spender_attested` asset it defined itself: [3](#0-2)  — `storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, ...)` is invoked with `bAcceptUnconfirmedAA=true` while building the AA's own payment/issue messages.

The `filterAttestedAddresses()`/`arrAttestedAddresses` result derived from this potentially-unstable attestor list is then used to decide whether the trigger sender (or issuer) is considered "attested" and therefore authorized to spend or receive the asset: [4](#0-3) 

Because the AA-controlled asset's attestor list can be chosen from unconfirmed/unstable content, the set of permitted spenders is not guaranteed to be the same on every node, and is not guaranteed to be immutable once chosen (an unstable unit can later be reordered/voided, changing the "latest" attestor list). This is the same class of bug as the GitLab report: a feature-gating check (attestor-list authorization) that is correctly enforced in the general/stable path is bypassed on an alternate access path (`byAA`), letting an entity see/act on data governed by that gate before the proper authorization state (stability/finality) is established.

### Impact Explanation
An AA that defines a `spender_attested` asset (fully permitted for any unprivileged AA author or bounce-triggered composition) can have its attestor list resolved from not-yet-stable DAG content. Because unstable content can differ between nodes (temporarily) and can be reordered before finality, two honest nodes executing the exact same AA trigger can compute **different** attestor lists, and thus reach different conclusions about whether a given address is authorized to receive/spend the asset. This creates:
- Node disagreement on AA response/state-var determinism for the same trigger (a consensus-safety concern for deterministic AA execution), and
- A path for the AA-defined asset's attestation gate to be satisfied using an attestor list that is not final and could still be discarded, potentially allowing coins to be issued/transferred to addresses that would not qualify once the asset's authorization state is properly finalized.

### Likelihood Explanation
Reachable by any address that triggers an AA which defines (or has previously defined) a `spender_attested`, `issued_by_definer_only`-optional asset and subsequently attempts to pay/issue that asset in a bounce/response message — a standard, unprivileged AA usage pattern requiring no special permissions, matching the "AA trigger sender" reachable surface named in scope.

### Recommendation
Do not drop the stability/finality condition for the `byAA` branch. Either:
1. Require the attestor-list unit to be stable and use a consistent finality bound (e.g., the AA's own execution `mci`) even when the asset itself was defined by an unconfirmed AA, or
2. If unstable attestor lists must be supported for freshly AA-defined assets, deterministically pin the attestor list at the same point the asset itself was accepted (e.g., snapshot it once at asset-definition acceptance and cache it) rather than re-querying "latest" without a stability bound on every read.

### Proof of Concept
1. An AA defines an asset `A` with `spender_attested: true` and `attestors: [addr_X]` in a `messages.app == "asset"` response (this uses `bAcceptUnconfirmedAA` at read time since the asset's own defining unit may still be unstable).
2. Shortly after, in a following trigger, the AA (or the trigger sender) causes an `asset_attestors` update unit to be posted that changes the attestor list to `[addr_Y]`.
3. Before this `asset_attestors` unit stabilizes, two nodes have diverging views of DAG unstable content (e.g., due to normal propagation delay) and both evaluate an AA trigger that spends/issues asset `A`.
4. `readAsset()` → `addAttestorsIfNecessary(true)` runs the attestor query without any `is_stable`/`main_chain_index<=last_ball_mci` filter, so one node may pick the unit for `[addr_Y]` as "latest" (already visible to it) while the other still resolves to `[addr_X]`.
5. The two nodes compute different `arrAttestedAddresses`, and thus different validity/authorization outcomes for the same AA response — a concrete disagreement on AA execution result for identical inputs.

*(Note: I was not able to fully trace every downstream consumer of `arrAttestorAddresses`/`arrAttestedAddresses` for this exact reachability chain within the available search iterations; the analysis is based on the code paths found in `storage.js` and `aa_composer.js`. A full confirmation would benefit from tracing `aa_composer.js`'s complete trigger-handling flow and any additional callers of `readAsset`/`loadAssetWithListOfAttestedAuthors` with `bAcceptUnconfirmedAA=true`.)*

### Citations

**File:** storage.js (L1911-1957)
```javascript
	readAssetInfo(conn, asset, function (objAsset) {
		if (!objAsset)
			return handleAsset("asset " + asset + " not found");
		if (objAsset.sequence !== "good")
			return handleAsset("asset definition is not serial");
		
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

**File:** aa_composer.js (L1298-1330)
```javascript
		async.eachSeries(
			messages,
			function (message, cb) {
				if (message.app !== 'payment') {
					try {
						if (message.app === 'definition')
							message.payload.address = objectHash.getChash160(message.payload.definition);
						completeMessage(message);
					}
					catch (e) { // may error if there are empty objects or arrays inside
						return cb("some hashes failed: " + e.toString());
					}
					return cb();
				}
				var payload = message.payload;
				if (payload.asset === 'base')
					delete payload.asset;
				var asset = payload.asset || null;
				if (asset === null) {
					if (objBasePaymentMessage)
						return cb("already have base payment");
					objBasePaymentMessage = message;
					// we'll add output addresses later, after possibly removing a send-all output
					return cb(); // skip it for now, we can estimate the fees only after all other messages are in place
				}
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
```
