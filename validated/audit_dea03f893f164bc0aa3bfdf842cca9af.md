### Title
Unrestricted asset metadata `name`/`suffix` strings are stored and rendered in the wallet UI without length or content sanitization - (File: `wallet.js`)

### Summary
`ocore`'s asset-metadata mechanism lets any address (registry) publish a `data`-app message that assigns a human-readable `name` to an asset. `validateInlinePayload()` in `validation.js` only checks that a `data` payload is a non-empty object, imposing no length limit, character whitelist, or newline check on any string field it contains [1](#0-0) . This is materially weaker than the sibling `data_feed` validation just above it, which explicitly bounds feed name/value length and forbids newlines [2](#0-1) . The AA-side validator for `data` messages has the identical gap [3](#0-2) .

`wallet.js`'s `fetchAssetMetadata()` consumes this attacker-controlled `payload.name` from the referenced unit and stores it verbatim into the `asset_metadata` table, only checking that it is truthy: `if (!payload.name) return handleMetadata(...)` [4](#0-3) . The resulting `name` (optionally combined with an equally unchecked `suffix`) is then exposed through `readAssetMetadata()` as the display name for the asset to any front end/GUI consuming this wallet library [5](#0-4) , and `assocAssetMetadata[asset].name` is used again when metadata is refreshed [6](#0-5) .

### Finding Description
This mirrors the Sablier bug class: an untrusted, attacker-supplied string (there: ERC20 `symbol()`, here: asset registry's `data` message `name`/`suffix`) is accepted with no bound on length or character set and is propagated into a value that the wallet displays to end users as the asset's name. Any address can post a `data` message tagged with an `asset` id and an arbitrary `name` string; nothing in `validateInlinePayload` (`case "data":`) or `aa_validation.js`'s `validatePayload` for `app === 'data'` enforces limits on string length, disallows control characters, HTML/script-like sequences, or newlines — unlike the parallel `data_feed` path which does exactly this (`MAX_DATA_FEED_NAME_LENGTH`, `MAX_DATA_FEED_VALUE_LENGTH`, and rejection of `\n`) [7](#0-6) . Because the asset metadata name is meant purely for UI display (unlike a data feed value used in oscript conditions), the absence of any of these checks is a UI-facing sanitation gap analogous to the Sablier SVG symbol injection: any wallet/GUI that renders `assocAssetMetadata[asset].name` into HTML/DOM without its own escaping is exposed to injected markup or script from a malicious "registry"/asset issuer.

### Impact Explanation
If a GUI/front-end built on `ocore`'s wallet module renders the asset name from `readAssetMetadata`/`assocAssetMetadata` directly (e.g., in a balances list, transaction history, or textcoin claim view) without independently HTML-escaping it, an attacker acting as an asset "registry" can inject arbitrary length strings, including HTML/JS payloads, into that displayed name. This can be leveraged for UI spoofing (fake confirmation/signing dialogs) similar to the cited Sablier report, potentially tricking a user into approving a malicious transaction — a concrete impact reachable purely from posting units, with no privileged network position required.

### Likelihood Explanation
Any address can act as an "asset metadata registry" by posting a `data` unit that references any `asset` id and includes a `name`, since `fetchAssetMetadata`/`readJoint` only checks that `objJoint.unit.authors[0].address` equals the `registry_address` supplied by the (attacker-controlled) hub response, not that the registry is a trusted or pre-approved actor. The lack of length/content checks means this is trivially reachable by any unprivileged unit poster, making likelihood high wherever a GUI trusts and renders this field unescaped.

### Recommendation
In `validation.js`'s `validateInlinePayload` `case "data":` and the corresponding `aa_validation.js` `data` branch, add explicit constraints mirroring the `data_feed` checks: bound the length of any string fields (or at least a dedicated bound for asset-metadata `name`/`suffix` values used by `wallet.js`), and reject control characters/newlines. Additionally, in `wallet.js`'s `fetchAssetMetadata`, validate `payload.name` and `suffix` against a strict allow-list (e.g., alphanumerics, limited punctuation) and a sane maximum length before persisting to `asset_metadata`, so downstream consumers receive a value safe to render without relying on every front end to remember to escape it.

### Proof of Concept
1. Attacker controls an address `R` acting as an asset-metadata registry.
2. Attacker posts a `data` message unit with payload `{asset: "<target_asset_unit>", name: "<img src=x onerror=alert(document.cookie)>"}` — this passes validation because `case "data"` only requires a non-empty object [1](#0-0) .
3. A victim wallet queries `hub/get_asset_metadata`, receives `registry_address = R` and `metadata_unit` pointing at the malicious unit; `fetchAssetMetadata` accepts it since only `metadata_unit` and `registry_address` format are checked, and `payload.name` is truthy [8](#0-7) .
4. The malicious `name` is stored in `asset_metadata` and returned via `readAssetMetadata`; any GUI that renders this field as-is in an HTML context executes the injected payload.

### Citations

**File:** validation.js (L1925-1951)
```javascript
		case "data_feed":
			if (objValidationState.bHasDataFeed)
				return callback("can be only one data feed");
			objValidationState.bHasDataFeed = true;
			if (!isNonemptyObject(payload))
				return callback("data feed payload must be non-empty object");
			if (Object.keys(payload).length * objUnit.authors.length > constants.MAX_DATA_FEEDS_PER_MESSAGE)
				return callback("too many data feeds in message");
			for (var feed_name in payload){
				if (feed_name.length > constants.MAX_DATA_FEED_NAME_LENGTH)
					return callback("feed name "+feed_name+" too long");
				if (feed_name.indexOf('\n') >=0 )
					return callback("feed name "+feed_name+" contains \\n");
				var value = payload[feed_name];
				if (typeof value === 'string'){
					if (value.length > constants.MAX_DATA_FEED_VALUE_LENGTH)
						return callback("data feed value too long: " + value);
					if (value.indexOf('\n') >=0 )
						return callback("value "+value+" of feed name "+feed_name+" contains \\n");
				}
				else if (typeof value === 'number'){
					if (!isInteger(value))
						return callback("fractional numbers not allowed in data feeds");
				}
				else
					return callback("data feed "+feed_name+" must be string or number");
			}
```

**File:** validation.js (L1961-1964)
```javascript
		case "data":
			if (typeof payload !== "object" || payload === null)
				return callback(objMessage.app+" payload must be object");
			return callback();
```

**File:** aa_validation.js (L83-90)
```javascript
			switch (message.app) {
				case 'profile':
				case 'data':
				case 'temp_data':
					if (!isNonemptyObject(payload))
						return cb2('payload of app=' + message.app + ' must be non-empty object or formula: ' + JSON.stringify(payload));
					cb2();
					break;
```

**File:** wallet.js (L1360-1382)
```javascript
function readAssetMetadata(arrAssets, handleMetadata, metadataUpdatedCb){
	if (!handleMetadata && !metadataUpdatedCb)
		return new Promise(resolve => readAssetMetadata(arrAssets, () => { }, (bUpdated, metadata) => resolve(metadata)));
	var sql = "SELECT asset, metadata_unit, name, suffix, decimals, registry_address, " + db.getUnixTimestamp("creation_date") + " AS timestamp FROM asset_metadata";
	if (arrAssets && arrAssets.length)
		sql += " WHERE asset IN ("+arrAssets.map(db.escape).join(', ')+")";
	db.query(sql, function(rows){
		var assocAssetMetadata = {};
		for (var i=0; i<rows.length; i++){
			var row = rows[i];
			// if expired, we'll download the asset's metadata again
			var is_expired = isUpdatableRegistry(row.registry_address) && row.timestamp < Date.now() / 1000 - ASSET_METADATA_EXPIRY_PERIOD;
			if (is_expired)
				console.log(row.name + " metadata has expired, will update it");
			var asset = row.asset || "base";
			assocAssetMetadata[asset] = {
				is_expired: is_expired,
				metadata_unit: row.metadata_unit,
				decimals: row.decimals,
				name: row.suffix ? row.name+'.'+row.suffix : row.name
			};
		}
		handleMetadata(assocAssetMetadata);
```

**File:** wallet.js (L1399-1412)
```javascript
					var name = objMetadata.suffix ? objMetadata.name + '.' + objMetadata.suffix : objMetadata.name;
					if (assocAssetMetadata[asset]
						&& assocAssetMetadata[asset].metadata_unit === objMetadata.metadata_unit
						&& assocAssetMetadata[asset].decimals === objMetadata.decimals
						&& assocAssetMetadata[asset].name === name
					) {
						console.log('metadata of ' + asset + ' (' + name + ') unchanged');
						return cb();
					}
					assocAssetMetadata[asset] = {
						metadata_unit: objMetadata.metadata_unit,
						decimals: objMetadata.decimals,
						name: name
					};
```

**File:** wallet.js (L1451-1483)
```javascript
			storage.readJoint(db, metadata_unit, {
				ifNotFound: function(){
					handleMetadata("metadata unit "+metadata_unit+" not found");
				},
				ifFound: function(objJoint){
					if (objJoint.unit.authors[0].address !== registry_address)
						return handleMetadata("registry address doesn't match: expected " + registry_address + ", got " + objJoint.unit.authors[0].address);
					objJoint.unit.messages.forEach(function(message){
						if (message.app !== 'data')
							return;
						var payload = message.payload;
						if (payload.asset !== asset)
							return;
						if (!payload.name)
							return handleMetadata("no name in asset metadata "+metadata_unit);
						var decimals = (payload.decimals !== undefined) ? parseInt(payload.decimals) : undefined;
						if (decimals !== undefined && !ValidationUtils.isNonnegativeInteger(decimals))
							return handleMetadata("bad decimals in asset metadata "+metadata_unit);
						var verb = isUpdatableRegistry(registry_address) ? "REPLACE" : "INSERT " + db.getIgnore();
						db.query(
							verb + " INTO asset_metadata (asset, metadata_unit, registry_address, suffix, name, decimals) \n\
							VALUES (?,?,?, ?,?,?)",
							[asset, metadata_unit, registry_address, suffix, payload.name, decimals],
							function(){
								var objMetadata = {
									metadata_unit: metadata_unit,
									suffix: suffix,
									decimals: decimals,
									name: payload.name
								};
								handleMetadata(null, objMetadata);
							}
						);
```
