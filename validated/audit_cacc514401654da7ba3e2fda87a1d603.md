### Title
Asset name spoofing via untrusted registry_address in wallet asset-metadata lookup enables stablecoin/token impersonation - ([File: wallet.js])

### Summary
The `asset_metadata` mechanism lets any address post a signed `data` message naming an existing asset (e.g. calling it "USDT" or "GBYTE"). The wallet client trusts the `name` string returned via `hub/get_asset_metadata` to label an asset in the UI, using `registry_address` only to disambiguate collisions with a `suffix` — not to authenticate that the name actually belongs to a well-known/trusted issuer. This mirrors the reported Canto bug class: trusting a free-form, attacker-choosable string (a token "name"/"symbol") instead of a fixed, unique identifier (the asset unit hash) to determine how a token is treated/displayed, allowing impersonation of a legitimate stable/well-known asset.

### Finding Description
`asset_metadata` is populated purely from a signed unit authored by whatever address chooses to publish it — there is no protocol-level whitelist of "trusted registries": [1](#0-0) 

`fetchAssetMetadata` only checks that the metadata unit is validly signed by the claimed `registry_address` (`objJoint.unit.authors[0].address !== registry_address`), and that the `payload.asset` field matches the target asset. It does **not** check that `registry_address` is any kind of trusted/whitelisted authority — any address can become a self-declared "registry" for any asset it likes and assign it an arbitrary `name`: [2](#0-1) 

The `asset_metadata` table's `UNIQUE(name, registry_address)` constraint and the `suffix` column exist specifically because the same human-readable `name` can be claimed by multiple different registries for different assets: [3](#0-2) 

The `suffix` is only appended when a naming collision is detected against already-known metadata for the *specific* combination the wallet has already fetched (`row.suffix ? row.name+'.'+row.suffix : row.name` in `readAssetMetadata`): [4](#0-3) 

Because the association between a `name` and its "official" `registry_address` is not enforced by any consensus/protocol rule (any address, including an attacker's own newly created address, is a valid `registry_address`), an attacker can:
1. Issue a new asset (any user can freely define/issue an asset via an `asset` app message).
2. Post a signed `data` message from their own address declaring `{asset: <attacker_asset>, name: "USDT"}` (or "GBYTE", or the name of any well-known token).
3. Because the (name, registry_address) pair is unique to *that* combination and no other registry has yet claimed "USDT" for this specific pairing, the wallet will display the attacker's asset with the plain name "USDT" with no disambiguating suffix — exactly reproducing the same non-unique-string trust problem cited in the Canto report (`compareStrings(symbol, "cUSDT")`), except here the "symbol" is the freely-chosen `name` field in `asset_metadata`.

This is analogous in root cause to the reported bug: a non-unique, attacker-controllable string (the asset "name"/symbol) is used as the basis for asset identification/display instead of the unique asset unit hash, and the mitigation recommended in the original report (fixed address/hash whitelisting instead of string comparison) is exactly what is missing here — `registry_address` is accepted from any signer instead of being checked against a fixed, known-trusted set of registries.

### Impact Explanation
A user relying on the wallet's displayed asset name (e.g., seeing "USDT" in their balance/transaction history/payment request) can be deceived into believing they are dealing with the legitimate stablecoin/token, when in fact the underlying asset is a completely different unit hash controlled by an attacker. This can lead to:
- Users paying/accepting the wrong (worthless) asset believing it to be a recognized stable/valuable token — a concrete instance of unauthorized/misdirected fund transfer via deception, analogous to how the Canto oracle would treat an attacker's cUSDT-lookalike as if it were the real stablecoin.
- Any downstream tooling (exchanges integration, AA frontends, bots) that displays or matches assets by `name` rather than by unit hash inherits the same impersonation risk.

Given the external precedent was judged Medium severity due to mitigating factors (governance-gated legitimate tokens), the same reasoning applies here: this is a design weakness rather than a full protocol break, and it depends on downstream consumers trusting `name` over the asset unit hash.

### Likelihood Explanation
Likelihood is straightforward: issuing an asset and posting a self-authored `data` metadata message are both unprivileged operations available to any wallet user; no governance approval or special permission is required to become a `registry_address` for a given `name`. The only friction is that a collision with an *already-fetched* legitimate mapping would introduce a suffix, but a first-seen or differently-ordered fetch, or a name that hasn't yet been claimed by the legitimate registry in the victim's local cache, allows the impersonation to display unqualified.

### Recommendation
- Do not treat `registry_address` as authoritative for display purposes unless it is a fixed, hardcoded/whitelisted set of known-trusted registries (analogous to using fixed address whitelisting instead of comparing a non-unique string, per the original recommendation).
- Always display the unique asset identifier (unit hash) alongside or in place of the free-form `name`, and never let a `name` collision be silently resolved to "no suffix" for a *new* asset unless the registry is on a curated trust list.
- Consider requiring `suffix` (registry identification) unconditionally for any asset not registered by a well-known/whitelisted registry, so a self-declared registry can never present an unqualified name that could be confused with an established token.

### Proof of Concept
1. Attacker issues a new asset `A` (`app: 'asset'`), fully unprivileged.
2. Attacker signs and broadcasts a unit from their own address `R_attacker` with `app: 'data', payload: { asset: A, name: "USDT", decimals: 6 }`.
3. A wallet querying `hub/get_asset_metadata` for asset `A` receives `registry_address = R_attacker`, `name = "USDT"`, with no `suffix` (since this specific `(name, registry_address)` pair is new to that wallet, per `wallet.js:1451-1484` and the `UNIQUE(name, registry_address)` schema in `asset_metadata`).
4. The wallet then displays/treats asset `A` as "USDT" indistinguishably from the legitimate USDT asset unless the victim wallet has independently cached the legitimate registry's claim on the same name, at which point the *legitimate* asset — not the attacker's — would receive the disambiguating suffix (or vice versa depending on fetch order), since disambiguation depends on local cache state rather than any authoritative binding between name and registry.

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

**File:** wallet.js (L1451-1484)
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
					});
```

**File:** initial-db/byteball-sqlite.sql (L701-712)
```sql
CREATE TABLE asset_metadata (
	asset CHAR(44) NOT NULL PRIMARY KEY,
	metadata_unit CHAR(44) NOT NULL,
	registry_address CHAR(32) NULL,
	suffix VARCHAR(20) NULL, -- added only if the same name is registered by different registries for different assets, equal to registry name
	name VARCHAR(20) NULL,
	decimals TINYINT NULL,
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	UNIQUE (name, registry_address),
	FOREIGN KEY (asset) REFERENCES assets(unit),
	FOREIGN KEY (metadata_unit) REFERENCES units(unit)
--	FOREIGN KEY (registry_address) REFERENCES addresses(address) -- addresses is not always filled on light
```
