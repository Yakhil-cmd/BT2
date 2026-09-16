## Title
Unicode Homoglyph/Confusable-Character Spoofing of Asset Metadata `name` Enables Fake-Asset Impersonation - (File: wallet.js)

### Summary
CVE-2018-20070 describes Chrome's URL Formatter failing to reject confusable Unicode characters in domain names, letting an attacker spoof the Omnibox display and impersonate a trusted site. `ocore` has an analogous trust-critical display string — the asset `name` stored in `asset_metadata` and shown to wallet users as the asset's ticker/label — that is accepted from an untrusted, attacker-controlled `data` message without any restriction on which Unicode characters are allowed. An asset issuer/registry operator can therefore register a `name` that is visually indistinguishable from a well-known asset's name using confusable Unicode glyphs (Cyrillic/Greek look-alikes, zero-width characters, etc.), spoofing the trusted asset in the UI a user relies on when selecting an asset to send/receive.

### Finding Description
`fetchAssetMetadata()` in [1](#0-0)  reads a `data` message's `payload.name` published by an arbitrary registry address and stores it verbatim into `asset_metadata.name`:
```
if (!payload.name)
    return handleMetadata("no name in asset metadata "+metadata_unit);
...
db.query(verb + " INTO asset_metadata (asset, metadata_unit, registry_address, suffix, name, decimals) ...",
    [asset, metadata_unit, registry_address, suffix, payload.name, decimals], ...);
```
The only check is a falsy/empty-string check — there is no validation of character set, script mixing, presence of zero-width/joiner characters, bidi-control characters, or normalization (NFC/NFKC) to detect confusable glyphs (`punycode`/`confusable` handling is entirely absent from the codebase, confirmed by search).

This `name` (optionally with a `suffix` used only to disambiguate exact string collisions per [2](#0-1)  `UNIQUE byNameRegistry(name, registry_address)`) is what `readAssetMetadata()` returns to the wallet UI as the human-facing asset label, per [3](#0-2) :
```
assocAssetMetadata[asset] = {
    ...
    name: row.suffix ? row.name+'.'+row.suffix : row.name
};
```
Because the uniqueness constraint operates on exact byte-string equality, a homoglyph string that is not byte-identical to a legitimate, already-registered name will not collide and will not get a disambiguating `suffix`, so it renders as if it were an original, unrelated (and thus seemingly legitimate) name — exactly analogous to how Chrome's Omnibox failed to flag confusable-character domains as suspicious.

Any address can act as a metadata "registry" (there is no permissioning check on `registry_address` beyond matching the publishing unit's author), so this is reachable by an unprivileged unit/asset issuer.

### Impact Explanation
A user relying on the asset name shown by the wallet (e.g., when picking an asset to pay with/into, or verifying which asset they received) can be tricked into treating a malicious, worthless, or otherwise unrelated asset as the well-known one it visually impersonates. This can lead to victims sending genuine funds under the belief they are transacting in the legitimate/trusted asset, or accepting the spoofed asset as if it had the value/reputation of the impersonated one — a concrete loss-of-funds/spoofing scenario for wallet users and counterparties, paralleling the omnibox-spoofing-enabled phishing impact of the original CVE.

### Likelihood Explanation
Trivial to exploit: any actor can issue a new asset and publish a `data` message with `app: 'asset_metadata'`-style payload (`asset`, `name`, `decimals`) from any address acting as "registry," embedding Unicode homoglyphs in `name`. No special privileges, cryptographic tricks, or race conditions are needed — only crafting a confusable string, well within reach of a single unprivileged unit poster/asset issuer.

### Recommendation
- Restrict `asset_metadata.name` (and `suffix`) to a constrained character set (e.g., ASCII alphanumerics plus a small allow-list of punctuation), or
- Apply Unicode confusable-character detection/normalization (NFKC + a confusables skeleton check, similar to IDN/UTS #39 "skeleton" algorithm) before accepting or displaying a name, rejecting names whose skeleton collides with an already-registered name from a different registry, and
- Visually flag mixed-script or non-ASCII asset names in the wallet UI.

### Proof of Concept
1. Attacker issues a new asset `X` and picks their own address as `registry_address`.
2. Attacker publishes a `data` unit with payload `{ asset: X, name: "GBYTE" /* using Cyrillic С instead of Latin, or with zero-width joiners */, decimals: 9 }` matching the pattern read in [4](#0-3) .
3. Any wallet calling `readAssetMetadata`/`fetchAssetMetadata` stores and displays this `name` unmodified, per [5](#0-4) , with no visual distinction from the real `GBYTE` asset since the string does not collide byte-for-byte and thus gets no disambiguating suffix.
4. Victim, viewing "GBYTE" (visually) in an asset picker/history, sends real GBYTE payment expecting to interact with the genuine asset ecosystem, or accepts the fake asset believing it's the reputable one — resulting in fund loss/misdirected payment.

### Citations

**File:** wallet.js (L1373-1380)
```javascript
				console.log(row.name + " metadata has expired, will update it");
			var asset = row.asset || "base";
			assocAssetMetadata[asset] = {
				is_expired: is_expired,
				metadata_unit: row.metadata_unit,
				decimals: row.decimals,
				name: row.suffix ? row.name+'.'+row.suffix : row.name
			};
```

**File:** wallet.js (L1458-1483)
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
