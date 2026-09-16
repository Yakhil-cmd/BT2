Confirmed: the `data` app validation in `validation.js` (`case "data":`) only checks that `payload` is a non-null object — it imposes no length limit and no character/control-code restriction on any field, unlike the sibling `data_feed` case a few lines above which explicitly rejects `\n` and enforces `MAX_DATA_FEED_NAME_LENGTH`/`MAX_DATA_FEED_VALUE_LENGTH`. This `data` message type is exactly what asset registries use to publish `name` metadata (`wallet.js` `fetchAssetMetadata`, reading `message.app === 'data'`, `payload.name`), which is then stored verbatim into `asset_metadata.name` and surfaced in the wallet UI (transaction history, asset pickers) via `readAssetMetadata`.

### Title
Unsanitized asset registry `data` payload allows control-character/spoofing injection into wallet-displayed asset names - (File: validation.js)

### Summary
Any address acting as an asset "registry" can post a `data` message (`app: "data"`) containing an arbitrary, unbounded, unsanitized `name` string for an asset. `wallet.js`'s `fetchAssetMetadata` blindly stores this string into `asset_metadata.name` and displays it verbatim wherever asset names are shown to the user (balances, transaction history, payment confirmation dialogs).

### Finding Description
`validation.js` handles the generic `"data"` app with: [1](#0-0) 
This is the only validation performed on arbitrary `data` messages, in contrast to `data_feed` handling a few lines above which explicitly strips/rejects newlines and enforces length caps: [2](#0-1) 

The wallet's `fetchAssetMetadata` reads the `name` field straight out of such a `data` message from the registry address and persists it without any sanitization, length limit, or character filtering: [3](#0-2) 

That stored `name` is later surfaced to the user through `readAssetMetadata`, which is used across the wallet UI (asset selectors, transaction history rows, "moved"/"sent" labels) to render a human-readable asset label: [4](#0-3) 

Because `name` (and `suffix`) can contain arbitrary bytes — including terminal/ANSI control sequences, right-to-left override characters, zero-width characters, or characters designed to visually truncate/overwrite a rendered label — a malicious or compromised registry (an "asset issuer"-adjacent, unprivileged network participant reachable purely by posting a `data` unit) can spoof the on-screen asset name. This mirrors the CVE-2019-6110 bug class: an untrusted peer's output is displayed to the user as-is, letting the attacker manipulate what the client renders and thereby hide or disguise the true nature of what's happening (there, hidden file transfers; here, a disguised/spoofed asset identity).

### Impact Explanation
A user who relies on the rendered asset name to decide whether to accept a payment, approve a private-payment counterparty request, or send funds to what they believe is a specific asset can be deceived: the spoofed name can visually impersonate a well-known, valuable asset (via control characters that overwrite/hide the real suffix, or homoglyphs/invisible characters) while actually referring to an attacker-issued worthless asset with a colliding-looking display string. This can lead to a user issuing a real payment (unauthorized/fund-loss-type outcome from the victim's perspective) believing they are dealing with a different, legitimate asset. The registry mechanism is unprivileged — any address can act as `registry_address` for assets it wasn't even necessarily authorized for from the wallet's point of view, since only `objJoint.unit.authors[0].address !== registry_address` is checked, not any global registry allowlist enforced by base layer consensus.

### Likelihood Explanation
Likelihood is limited by user interaction: the attacker must get the victim's wallet to fetch/display metadata for an asset tied to an attacker-controlled or attacker-influenced registry address (e.g., by sending the victim an asset unit or via a shared/private payment flow), then rely on the victim visually confusing the displayed name. This requires some social-engineering component (like the original CVE's reliance on the user watching progress output), which is why the severity aligns with Medium rather than higher.

### Recommendation
Apply the same sanitization already used for `data_feed` values to the `name`/`suffix` fields accepted from asset-metadata `data` messages: enforce a maximum length, strip/reject control characters (`\n`, `\r`, other C0/C1 control codes), reject bidi-control and zero-width Unicode characters, and consider normalizing/escaping the string before rendering in the UI (`readAssetMetadata`/`fetchAssetMetadata` in `wallet.js`).

### Proof of Concept
1. Attacker controls (or is) `registry_address` for some asset `A`.
2. Attacker posts a `data` unit with payload `{ asset: A, name: "USDT\u0008\u0008\u0008\u0008REAL", decimals: 2 }` (or with ANSI/zero-width/RTL-override characters) authored by `registry_address`.
3. Validation only requires the payload be a non-null object (`validation.js:1961-1964`); no length or character checks reject it.
4. A victim wallet, resolving asset `A`'s metadata via `fetchAssetMetadata` (`wallet.js:1451-1481`), stores the crafted `name` verbatim in `asset_metadata`.
5. `readAssetMetadata` (`wallet.js:1360-1382`) returns this string, and the wallet UI renders it as the asset's display name in balances/transaction history, spoofing the victim into believing they hold/are transacting a different, legitimate asset.

### Citations

**File:** validation.js (L1930-1951)
```javascript
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

**File:** wallet.js (L1451-1481)
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
```
