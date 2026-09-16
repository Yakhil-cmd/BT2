### Title
Unchecked empty-result-set dereference in `readAsset()` causes uncaught exception / node crash when validating a payment in a `spender_attested` asset with no confirmed attestor list - ([File: storage.js])

### Summary
`storage.readAsset()` in `storage.js` looks up the current attestor list for a `spender_attested` asset before allowing any payment/oscript access to that asset. If the query for the "latest attestor list" or the attestor addresses returns zero rows, the code `throw`s an `Error` instead of passing an error through the callback chain used everywhere else in this function. Because this happens inside an asynchronous `conn.query` callback, the thrown exception is not caught by any surrounding `try/catch` and propagates as an uncaught exception, crashing the node process. This is directly analogous to CVE-2019-14875: an unchecked "allocation"/lookup result (`latest_rows`/`att_rows` being empty) is unconditionally dereferenced/acted upon, and the resulting failure is not handled gracefully — it aborts the whole process instead of returning a validation error.

### Finding Description [1](#0-0) 

`readAsset()` is the standard path used to validate and read metadata for any asset referenced by a payment message or by oscript's `asset[...]` selector. When `objAsset.spender_attested` is true, `addAttestorsIfNecessary()` queries the `asset_attestors` table for the most recent attestor-list unit: [2](#0-1) 

```
if (latest_rows.length === 0)
    throw Error("no latest attestor list");
...
if (att_rows.length === 0)
    throw Error("no attestors?");
```

Every other failure path in this function (`"asset " + asset + " not found"`, `"asset definition is not serial"`, `"asset definition must be before last ball"`, etc.) correctly reports the error through the `handleAsset(error, ...)` callback, letting the caller (`validation.js`, oscript `asset[]` evaluation, `wallet.js`, `private_payment.js`) reject the offending unit normally. The two `throw Error(...)` statements break this pattern: they assume that a `spender_attested` asset must always have at least one confirmed `asset_attestors` unit, but nothing in asset-definition validation enforces that an attestor list ever be posted before the asset is used. An issuer can define an asset with `spender_attested: true` and never post (or never get confirmed) any `asset_attestors` message. Any subsequent payment referencing that asset, or any oscript `asset[asset_hash]` evaluation for it, drives execution into `addAttestorsIfNecessary()`, which finds zero rows and throws inside the `conn.query` callback — an uncaught exception with no `try/catch` in the call chain, crashing the node.

### Impact Explanation
This is reachable by an ordinary, unprivileged asset issuer: (1) post an `asset` definition message with `spender_attested: true` and no genuine attestor list; (2) post (or have anyone post) a payment using that asset, or trigger an AA whose oscript formula evaluates `asset[<that asset>]...`. Every full node (and every AA-executing node) that validates that unit reaches the unchecked `throw` and crashes. Because this occurs during ordinary unit/AA validation — not a malicious-peer or p2p-only path — it can be used to reliably crash any node (and, if propagated by the attacker to the whole network as a normal unit, potentially many/most full nodes at once), preventing that unit (and anything depending on it) from ever being confirmed. This satisfies the required "network unable to confirm new units" / node-crash impact bar.

### Likelihood Explanation
High. No special privileges, no cooperating malicious peer, and no timing race are required — only two ordinary application-level messages (`asset` definition + a payment/AA trigger referencing that asset) that any user can construct and broadcast through the normal wallet/AA composer APIs. The vulnerable code path is exercised in the default, most common execution flow for any asset flagged `spender_attested`.

### Recommendation
Replace both `throw Error(...)` calls in `addAttestorsIfNecessary()` (storage.js, lines ~1929 and ~1939) with normal error propagation via `handleAsset("no attestor list defined for this asset")`/similar, matching the pattern used by the rest of `readAsset()`. Additionally, either enforce at asset-definition-validation time that a `spender_attested` asset cannot be spent/read until at least one `asset_attestors` unit is confirmed (returning a validation error rather than crashing), or explicitly handle the "no attestors yet" state as a legitimate business condition (e.g., treat the asset as currently non-transferable) instead of an invariant violation.

### Proof of Concept
1. Attacker (asset issuer) posts a unit defining a new asset with `is_private:false`, and `spender_attested: true`, without ever posting a confirmed `asset_attestors` message for it.
2. Attacker (or any user) posts a payment unit that spends/creates an output in that asset, or an AA is triggered whose oscript formula evaluates `asset['<asset_hash>'].is_issued` (or any field triggering `readAsset`).
3. Every node validating that payment/trigger calls `storage.readAsset()` → `addAttestorsIfNecessary()` → `conn.query(...)` returns `latest_rows.length === 0` → `throw Error("no latest attestor list")` inside the async callback, with no enclosing `try/catch`, crashing the node process before it can render a normal `ifUnitError`/`ifJointError` verdict.

### Citations

**File:** storage.js (L1898-1957)
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
}
```
