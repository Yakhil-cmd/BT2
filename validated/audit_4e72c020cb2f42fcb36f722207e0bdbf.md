### Title
Unrestricted asset display-name registration enables confusable-character spoofing of asset identity - (File: wallet.js)

### Summary
The Chrome CVE describes an Omnibox spoofing bug where a crafted domain name containing a confusable (visually-similar) character can trick a user into believing they are looking at a different, trusted identifier. The closest reachable analog in ocore is the asset naming/registry mechanism: any address can act as an unprivileged "registry" and publish a `data` message that assigns a human-readable `name`/`suffix` to an asset, and this name is stored and later displayed in the wallet UI as the asset's identity with no confusable-character/homoglyph or canonicalization checks.

### Finding Description
Asset display names are populated purely from unit content authored by an arbitrary address, and consumed by `fetchAssetMetadata`/`readAssetMetadata` in `wallet.js` for display purposes: [1](#0-0) 

The registry-supplied `payload.name` string is only checked for existence (`if (!payload.name) ...`), with no restriction on its character set, no confusable-character/homoglyph filtering, and no normalization (e.g., NFKC) before being stored and displayed: [2](#0-1) 

The resulting name is combined into a display string (`name+'.'+suffix`) and surfaced to the user as the asset's identity: [3](#0-2) 

The underlying `asset_metadata` schema only enforces uniqueness of `(name, registry_address)`, not uniqueness or canonical form of the visual string itself, so two different registry addresses can register visually-identical-looking `name` values (e.g. using Cyrillic/Greek homoglyphs of Latin letters) for two different, unrelated assets: [4](#0-3) 

This is structurally analogous to the CVE's Omnibox spoofing: the identifier a user relies on to recognize a trusted entity (a domain name in Chrome, an asset's display name in the wallet) can be crafted by an unprivileged, arbitrary party using confusable Unicode characters to visually impersonate a different, legitimate identifier, with no defense-in-depth check performed by the code that ingests and displays that string.

### Impact Explanation
A malicious actor can register asset metadata for an attacker-controlled asset using a `name`/`suffix` that is visually indistinguishable from a well-known, legitimate asset's name. When a victim's wallet resolves and displays this metadata (via `readAssetMetadata`/`fetchAssetMetadata`), the UI shows the spoofed name as the asset identity. A victim who is asked to send/receive "TrustedToken" may be shown the confusable string and be deceived into sending real value expecting to interact with the legitimate asset, or into accepting payment in the worthless spoofed asset believing it is the legitimate one — leading to concrete unauthorized loss of funds through user deception, comparable to a spoofed payment address/asset misidentification.

### Likelihood Explanation
Likelihood is moderate: any address can publish a `data` unit assigning metadata to any asset hash it wants to describe (the registry field is just the author address of the unit, not restricted to the asset's own definer), and the wallet code performs no content sanitization on the `name` string beyond a non-empty check. The main friction is that a victim would need to be induced (e.g., via social engineering or a fake pairing/registry service) to trust and resolve metadata from the attacker's registry address, and would need to overlook the accompanying raw asset ID.

### Recommendation
- Apply Unicode confusable-character detection/normalization (e.g., IDNA-like skeleton comparison, NFKC normalization, or restricting the character set to safe ASCII subsets) to `name`/`suffix` fields before they are stored in `asset_metadata` or displayed to the user.
- When displaying an asset name, always show it alongside its immutable, non-spoofable asset hash so users cannot rely on the name alone to distinguish assets.
- Warn or refuse to auto-trust metadata coming from registry addresses that were not manually configured/whitelisted by the user, rather than accepting the first metadata received from any peer/hub.

### Proof of Concept
1. Attacker crafts and posts a unit with a `data` message: `{asset: <attacker_asset_hash>, name: "TrustedTokeո", decimals: 2}` where the final `n`-like character is a Unicode confusable (e.g., Armenian ո U+0578) that renders visually identical to "n" in common wallet fonts.
2. Attacker's device serves this asset's `hub/get_asset_metadata` response (or the unit propagates normally) so `fetchAssetMetadata` in `wallet.js` retrieves and stores it in `asset_metadata` with no validation of the visual similarity to the real "TrustedToken" asset's name. [5](#0-4) 
3. Victim's wallet later calls `readAssetMetadata`, which formats and returns `name+'.'+suffix` for UI display without any indication that the string is a homoglyph of a different asset. [3](#0-2) 
4. Victim, relying on the displayed name to identify the asset in a payment request, sends real funds under the belief they are interacting with the legitimate "TrustedToken" asset, resulting in loss of value to the attacker's spoofed asset.

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

**File:** wallet.js (L1455-1483)
```javascript
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

**File:** initial-db/byteball-mysql.sql (L683-695)
```sql
CREATE TABLE asset_metadata (
	asset CHAR(44) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL PRIMARY KEY,
	metadata_unit CHAR(44) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL,
	registry_address CHAR(32) NULL,
	suffix VARCHAR(20) NULL, -- added only if the same name is registered by different registries for different assets, equal to registry name
	name VARCHAR(20) NULL,
	decimals TINYINT NULL,
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	UNIQUE byNameRegistry(name, registry_address),
	FOREIGN KEY (asset) REFERENCES assets(unit),
	FOREIGN KEY (metadata_unit) REFERENCES units(unit)
	-- FOREIGN KEY (registry_address) REFERENCES addresses(address) -- addresses is not always filled on light
) ENGINE=InnoDB  DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
```
