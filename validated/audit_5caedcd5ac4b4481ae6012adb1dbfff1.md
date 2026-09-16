### Title
Asset ticker/name spoofing via unvalidated Unicode `name` field in asset metadata registration - ([File: wallet.js])

### Summary
CVE-2017-5383 concerns browsers failing to convert visually deceptive Unicode strings (homoglyphs of hyphens/quotes) to punycode, letting attackers spoof legitimate domain names in the address bar. The same bug class — accepting arbitrary Unicode identifiers that a user cannot visually distinguish from a legitimate one, with no normalization/confusable check — is reachable in `ocore` through the asset-metadata-registry mechanism, where an asset name (a user-facing "ticker") is taken verbatim from an untrusted unit's payload and stored/displayed with no charset or confusable-character restriction.

### Finding Description
Any address can act as an asset-metadata "registry" simply by posting a `data`-app unit referencing an `asset` id together with a `name` field. In `fetchAssetMetadata` in `wallet.js`, the only validation performed on the attacker-controlled `payload.name` is a truthiness check: [1](#0-0) 

There is no check on:
- character set (any Unicode codepoints are accepted, including confusable homoglyphs, e.g. Cyrillic "с"/"а"/"е" vs Latin "c"/"a"/"e", zero-width characters, combining marks, RTL override characters, etc.)
- length (the DB column `name VARCHAR(20)` will silently truncate, but the in-memory/display value used before insertion is unbounded)
- normalization (no NFKC/NFC normalization, no confusable-skeleton comparison)

This name is stored in `asset_metadata` and surfaced to the user as `name` (optionally combined with a `suffix` when the *exact byte-for-byte* name collides with another registry's name): [2](#0-1) 

The `suffix` disambiguation mechanism itself is exact-string based (`UNIQUE byNameRegistry(name, registry_address)` / conflict detection compares full strings) as seen in the schema comment: [3](#0-2) 

Because the collision/suffix logic is a byte-equality check, an attacker who registers a name using homoglyphs that render identically to a well-known asset's ticker (e.g. "USDT" using a Cyrillic "Т") produces a *different* string from the legitimate name. This bypasses the suffix-disambiguation safety net entirely — the spoofed asset is displayed to the user with no distinguishing suffix, exactly mirroring the CVE-2017-5383 class of bug where the anti-spoofing measure (punycode conversion) fails to trigger for confusable-but-not-identical strings.

### Impact Explanation
A malicious asset issuer/registry can register a fake asset whose displayed name is visually indistinguishable from a legitimate, valuable asset (e.g. a stablecoin). Wallet users trusting the displayed asset name when sending or receiving payments can be tricked into sending funds against, or accepting as payment, the attacker's worthless spoofed asset instead of the intended one, resulting in unauthorized/misdirected fund transfers. Since asset name resolution feeds directly into payment composition/selection surfaces used to decide which `asset` id to spend from or pay to, this can lead to concrete fund loss for the victim without any code flaw needing to be exploited beyond social/visual deception — the exact impact class the punycode-display protection in browsers was designed to prevent for domains.

### Likelihood Explanation
Registering asset metadata requires no special privilege — any address can author a `data` message referencing any `asset` unit and an arbitrary `name`, exactly the "unprivileged asset issuer" actor described in scope. The only friction is that wallets must fetch and trust the registry's metadata unit, which is standard behavior (`fetchAssetMetadata` is invoked automatically by wallets when displaying assets). No cryptographic or consensus bypass is needed, only choice of Unicode codepoints, making this straightforward to execute.

### Recommendation
- Restrict `name`/`suffix` payloads to a defined safe character set (e.g., ASCII alphanumerics plus a small punctuation whitelist) in `fetchAssetMetadata` (`wallet.js`) before accepting/storing them.
- Apply Unicode normalization (NFKC) and a confusable-skeleton comparison (e.g., Unicode TR39 skeleton algorithm) when checking for name collisions, instead of the current exact-string `UNIQUE(name, registry_address)` check, so that homoglyph variants of an existing name are treated as colliding and forced to carry a distinguishing suffix.
- Enforce an explicit length limit at the application layer prior to DB insertion instead of relying on silent column truncation.

### Proof of Concept
1. Registry address `R2` (attacker-controlled) posts a `data` unit with `{ asset: "<attacker_asset_id>", name: "USDТ" }` where "Т" is Cyrillic U+0422, visually identical to Latin "T".
2. A victim wallet queries `hub/get_asset_metadata` for `<attacker_asset_id>`, receives `metadata_unit`, `registry_address = R2`, and fetches the joint via `fetchAssetMetadata` (`wallet.js:1427-1489`).
3. Since `payload.name` is only checked with `if (!payload.name)` (`wallet.js:1464-1465`), the Cyrillic string passes validation and is stored/inserted into `asset_metadata` unmodified.
4. Because "USDТ" (Cyrillic) ≠ "USDT" (Latin) as a string, the `UNIQUE(name, registry_address)` collision check never fires, so no disambiguating `suffix` is attached — the wallet displays the asset simply as "USDT", indistinguishable from the real stablecoin.
5. A victim, trusting the displayed name, sends funds intending to interact with the real USDT asset but is shown/selects the attacker's spoofed asset in the UI, resulting in funds being sent under a false identification of the asset.

### Citations

**File:** wallet.js (L1396-1412)
```javascript
						console.log(err);
						return cb();
					}
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

**File:** wallet.js (L1458-1473)
```javascript
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
```

**File:** initial-db/byteball-myrocks.sql (L652-663)
```sql
CREATE TABLE asset_metadata (
	asset CHAR(44) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL PRIMARY KEY,
	metadata_unit CHAR(44) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL,
	registry_address CHAR(32) BINARY NULL,
	suffix VARCHAR(20) BINARY NULL, -- added only if the same name is registered by different registries for different assets, equal to registry name
	name VARCHAR(20) BINARY NULL,
	decimals TINYINT NULL,
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	UNIQUE byNameRegistry(name, registry_address),
	KEY (metadata_unit)
	-- FOREIGN KEY (registry_address) -- addresses is not always filled on light
) ENGINE=RocksDB  DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
```
