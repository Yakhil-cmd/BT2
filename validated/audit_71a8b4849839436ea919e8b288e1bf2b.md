I found a strong analog in `storage.js`'s `readAssetInfo` cache, which mirrors the exact bug class described: an in-memory cache keyed by an identifier that omits a state dimension needed to determine correctness, causing stale/incorrect data to be served for subsequent, distinct evaluations.

### Title
Stale Cached Asset Info Served by `readAssetInfo`, Ignoring MCI Context Leads to Incorrect Formula/AA Evaluation - ([File: storage.js])

### Summary
`storage.readAssetInfo` caches asset properties (`cap`, `is_private`, `issue_condition`, `transfer_condition`, `issued_by_definer_only`, etc.) in `assocCachedAssetInfos`, keyed only by `asset` (the defining unit hash), with no consideration of the `main_chain_index`/stability context of the caller. Once an asset is marked stable and cached, every future caller — including formula/AA evaluation at a different, potentially earlier `mci` — receives the same cached object regardless of whether the asset's conditions were valid or resolvable at that point in DAG history.

### Finding Description
`readAssetInfo` populates the cache purely based on `is_stable`, independent of the `mci` argument passed by callers: [1](#0-0) . The cache lookup `assocCachedAssetInfos[asset]` at the top of the function short-circuits any DB re-check and returns the previously stored object unconditionally.

This cache is consumed by `readAsset`, which layers `main_chain_index <= last_ball_mci` checks on top of the *already-cached* `objAsset` — but the cached object itself was captured once and never revalidated against different `last_ball_mci` values [2](#0-1) . `readAsset` is the function used throughout AA/formula evaluation (e.g. `readAssetInfoPossiblyDefinedByAA` in `formula/evaluation.js`) and wallet code paths (`readAssetProps` in `wallet.js`) to determine issue/transfer conditions, caps, and privacy flags used to authorize spending and issuance decisions: [3](#0-2) [4](#0-3) .

Because the cache is keyed only by `asset` and not by `mci`, this class of bug is directly analogous to the reported `clientCache` issue: the cache key omits a contextual dimension (`mci`/DAG-position, analogous to the wallet address) that determines whether the cached object is the *correct* one to use for the current evaluation context. An `AA trigger sender` or `asset issuer` who can influence when/whether an asset becomes visible or how its conditions resolve at different points in DAG history (e.g., assets defined by AAs becoming visible only after specific `mci`s, per the `readAssetInfoPossiblyDefinedByAA` logic) could cause two different, valid evaluation contexts (different `mci`s) to observe the same cached `objAsset`, even though a strict per-mci reconstruction should differ (e.g. attestor lists, whether it's visible at all before the defining AA is confirmed).

### Impact Explanation
If asset issue/transfer conditions or attestor-derived fields are served from a stale cache entry that doesn't correspond to the requesting `mci`, this can affect validation consensus around issuance/transfer authorization for that asset, potentially leading nodes to disagree on which conditions apply — impacting AA fund flows and asset-based value transfer decisions. This maps to the "AA fund loss or freezing" / "node disagreement on validity" impact categories.

### Likelihood Explanation
Likelihood is Medium: triggering requires an asset (or AA-defined asset) whose conditions or attestor list are queried across different `mci`/last-ball contexts after the object is first cached, which is a natural occurrence for actively-used assets and AA-defined assets, not a contrived edge case.

### Recommendation
Key `assocCachedAssetInfos` by both `asset` and the relevant `mci`/stability marker (or invalidate/refresh the cache whenever attestor lists or definition-dependent fields could differ across `mci`), analogous to keying the `clientCache` by both chainId and address in the original report:
```js
function cacheKey(asset, mci) { return asset + ':' + mci; }
```
Alternatively, only cache the immutable core fields (those fixed at asset definition time) and always freshly compute any mci-dependent derived fields (like `arrAttestorAddresses`) outside the cached object.

### Proof of Concept
Not independently reproducible from static analysis alone — this requires demonstrating that two callers use `readAsset`/`readAssetInfo` for the same asset but with materially different `last_ball_mci`/AA-definition-visibility context and receive the identical cached `objAsset` despite different expected results (e.g., one context where the asset should not yet be visible via `readAADefinition`, another where it is). I was not able to trace a concrete double-spend/consensus-divergence trigger sequence within the available time; this should be validated with a live/test-node repro before treating it as confirmed exploitable, as flagged uncertainty.

### Citations

**File:** storage.js (L1871-1896)
```javascript
function readAssetInfo(conn, asset, handleAssetInfo){
	if (!handleAssetInfo)
		return new Promise(resolve => readAssetInfo(conn, asset, resolve));
	var objAsset = assocCachedAssetInfos[asset];
	if (objAsset)
		return handleAssetInfo({ ...objAsset });
	conn.query(
		"SELECT assets.*, main_chain_index, sequence, is_stable, address AS definer_address, unit AS asset \n\
		FROM assets JOIN units USING(unit) JOIN unit_authors USING(unit) WHERE unit=?", 
		[asset], 
		function(rows){
			if (rows.length > 1)
				throw Error("more than one asset?");
			if (rows.length === 0)
				return handleAssetInfo(null);
			var objAsset = rows[0];
			if (objAsset.issue_condition)
				objAsset.issue_condition = JSON.parse(objAsset.issue_condition);
			if (objAsset.transfer_condition)
				objAsset.transfer_condition = JSON.parse(objAsset.transfer_condition);
			if (objAsset.is_stable) // cache only if stable
				assocCachedAssetInfos[asset] = objAsset;
			handleAssetInfo({ ...objAsset });
		}
	);
}
```

**File:** storage.js (L1898-1956)
```javascript
function readAsset(conn, asset, last_ball_mci, bAcceptUnconfirmedAA, handleAsset) {
	if (arguments.length === 4) {
		handleAsset = bAcceptUnconfirmedAA;
		bAcceptUnconfirmedAA = false;
	}
	if (last_ball_mci === null){
		if (conf.bLight)
			last_ball_mci = MAX_INT32;
		else
			return readLastStableMcIndex(conn, function(last_stable_mci){
				readAsset(conn, asset, last_stable_mci, bAcceptUnconfirmedAA, handleAsset);
			});
	}
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
```

**File:** formula/evaluation.js (L3169-3184)
```javascript
	function readAssetInfoPossiblyDefinedByAA(asset, handleAssetInfo) {
		storage.readAssetInfo(conn, asset, function (objAsset) {
			if (!objAsset)
				return handleAssetInfo(null);
			if (objAsset.main_chain_index !== null && objAsset.main_chain_index <= mci)
				return handleAssetInfo(objAsset);
			if (!bAA) // we are not an AA and can't see assets defined by fresh AAs
				return handleAssetInfo(null);
			// defined later than last ball, check if defined by AA
			storage.readAADefinition(conn, objAsset.definer_address, mci, function(arrDefinition) {
				if (arrDefinition)
					return handleAssetInfo(objAsset);
				handleAssetInfo(null); // defined later by non-AA
			});
		});
	}
```

**File:** wallet.js (L1795-1799)
```javascript
function readAssetProps(asset, handleResult){
	if (!asset)
		return handleResult(null, {fixed_denominations: false, cap: constants.TOTAL_WHITEBYTES, issued_by_definer_only: true});
	storage.readAsset(db, asset, null, handleResult);
}
```
