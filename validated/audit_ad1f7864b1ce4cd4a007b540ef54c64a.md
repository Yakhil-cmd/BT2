### Title
Unvalidated, unnormalized asset `name`/`suffix` in asset metadata allows homograph spoofing of trusted asset tickers - (File: wallet.js)

### Summary
Any address (asset issuer) can publish a plain `data` message that maps an arbitrary asset unit to a human-readable `name`, which the wallet stores in `asset_metadata` and later displays to end users as the asset's ticker in balances and transaction history. `ocore` never checks the `name` string for confusable/homograph Unicode characters, character-set restrictions, or normalization before accepting and displaying it — mirroring the root cause of CVE-2020-6412 (Chrome's Omnibox failing to validate/normalize untrusted IDN input before display, enabling domain spoofing).

### Finding Description
In `fetchAssetMetadata` in `wallet.js`, the wallet reads an asset-metadata `data` message and accepts `payload.name` with only an emptiness check: [1](#0-0) 
No validation is performed on the byte length, character set, or visual confusability of `payload.name` (or the `suffix`, which is derived from the issuer's own `bots.name`). The value is written verbatim into `asset_metadata.name` and used to build the display string: [2](#0-1) 
This same unchecked string is later surfaced to the user in `readAssetMetadata`/`readTransactionHistory`, which compose the displayed ticker as `name` or `name + '.' + suffix`: [3](#0-2) 
An attacker who controls any address can define a new asset (via the normal `asset` app, validated generically in `validateAssetDefinition`) and post a `data` message declaring `payload.name` equal to, or a Unicode-confusable lookalike of, a well-known/trusted asset name (e.g., a ticker using Cyrillic/Greek homoglyphs that render identically to a legitimate asset's Latin name). Because there is no normalization/confusable check anywhere in the message-processing pipeline (`validation.js`'s generic `data`-app handling imposes no charset constraints, and `wallet.js` does not sanitize it either), the wallet UI will display the attacker's asset under a name visually indistinguishable from the trusted one.

### Impact Explanation
A user relying on the wallet-displayed asset name to identify which asset they are receiving/sending in a private payment or trade could be tricked into accepting the attacker's worthless spoofed asset while believing it is the legitimate, valuable one (or vice versa, sending the real asset expecting to receive the real one back). This is a concrete asset/ticker-spoofing attack that can cause a counterparty to suffer unauthorized loss of value in a trade — the same "user is shown the wrong trust indicator due to unvalidated untrusted input" root cause as the Chrome IDN homograph bug, but here the trust indicator is a token name instead of a domain name.

### Likelihood Explanation
The attack requires only that the attacker (a) issue a new asset — an action any address can perform without special privilege, and (b) publish a single `data` message with a crafted Unicode name — both are ordinary user-composed messages requiring no elevated network position, no colluding hub, and no client bug beyond the display path. The main barrier is that a victim must be tricked into a trade with this spoofed asset (typical of social-engineering/token-name-spoofing scenarios seen on other DLT platforms), so exploitation is straightforward but requires the attacker to also lure a counterparty into a private trade.

### Recommendation
Before storing or displaying `asset_metadata.name`/`suffix`, normalize the string (NFC) and reject or visually flag names containing mixed scripts, invisible/combining characters, or characters confusable with the restricted ticker character set of well-known assets (e.g., restrict metadata names to a whitelist such as `[A-Za-z0-9_.-]` similarly to how domain names are restricted, or run a confusable-detection algorithm akin to Unicode TR39 before display), and warn the user when an asset name collides/looks similar to an existing locally cached asset name from a different registry/issuer.

### Proof of Concept
1. Attacker issues a new asset `X` (`app: "asset"`) from address `A`.
2. Attacker's registry address `A` (recorded, e.g., in the `bots` table, or as `registry_address`) posts a `data` message: `{ app: "data", payload: { asset: "X", name: "ԌBYTE" } }`, where `"ԌBYTE"` uses a Cyrillic `Ԍ` (U+0524) visually identical to Latin `G`, mimicking the well-known "GBYTE" ticker.
3. `fetchAssetMetadata` in `wallet.js` accepts and stores this name because it only checks `!payload.name` (wallet.js:1464-1465), performing no confusable/normalization check.
4. Victim's wallet later displays balances/incoming payments of asset `X` labeled "ԌBYTE" (wallet.js:1379/1399), visually indistinguishable from the genuine "GBYTE", leading the victim to accept it in a trade believing it is the genuine base asset.

### Citations

**File:** wallet.js (L1374-1380)
```javascript
			var asset = row.asset || "base";
			assocAssetMetadata[asset] = {
				is_expired: is_expired,
				metadata_unit: row.metadata_unit,
				decimals: row.decimals,
				name: row.suffix ? row.name+'.'+row.suffix : row.name
			};
```

**File:** wallet.js (L1458-1465)
```javascript
					objJoint.unit.messages.forEach(function(message){
						if (message.app !== 'data')
							return;
						var payload = message.payload;
						if (payload.asset !== asset)
							return;
						if (!payload.name)
							return handleMetadata("no name in asset metadata "+metadata_unit);
```

**File:** wallet.js (L1469-1480)
```javascript
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
```
