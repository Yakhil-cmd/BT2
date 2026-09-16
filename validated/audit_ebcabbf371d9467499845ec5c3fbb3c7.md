Based on my investigation, I found a concrete analog to the kinto-attachment bug class (mutable content protected by insufficient authorization) in the `peer_addresses` cache used for multi-signature / shared-address wallet contracts.

### Title
Prosaic/arbiter contract counterparty can overwrite another party's cached address definition in `peer_addresses` without ownership verification - (File: wallet.js)

### Summary
The `prosaic_contract_response` and `arbiter_contract_response` handlers in `wallet.js` cache a counterparty's address `definition` into the `peer_addresses` table, keyed only by `address` (its `PRIMARY KEY (address)` in the schema). When the row already exists, the code silently `UPDATE`s it without checking that the request actually originates from the `device_address` that legitimately owns/controls that address, mirroring the kinto-attachment pattern where a mutable resource can be replaced by a party whose privileges were validated for a different, narrower purpose (accepting/declining a contract) rather than for writing that specific resource.

### Finding Description
In `wallet.js`, handling of `prosaic_contract_response` and `arbiter_contract_response` messages (device-to-device correspondence, reachable by any paired device that negotiates a contract) performs: [1](#0-0) [2](#0-1) 

The `INSERT ... ON CONFLICT (IGNORE)` followed by an unconditional `UPDATE peer_addresses SET signing_paths=?, definition=? WHERE address=?` means that whenever a row for that `address` already exists (inserted earlier by any other correspondent device), the incoming response overwrites `signing_paths` and `definition` for that address without checking `device_address=from_address`. The schema confirms `peer_addresses` has a single-column primary key on `address` only, not `(address, device_address)`: [3](#0-2) 

The only checks performed before this write are: the response corresponds to a known contract (`objContract`), `from_address === objContract.peer_device_address`, and `author.address === objContract.peer_address` with `author.definition` hashing to `author.address`: [4](#0-3) 

These checks validate that the sender is the counterparty for *that specific contract* and that the definition is self-consistent (hashes to the claimed address) — but they do not verify that the sender is the device that legitimately owns/authored `address` in general. Any device that can get a user to negotiate (even a rejected/declined) prosaic or arbiter contract using a `peer_address` equal to some other, already-cached address can force-overwrite that address's cached `definition`/`signing_paths` entry.

This is functionally analogous to the kinto-attachment flaw: authorization was validated for one action (respond to a contract you're party to) but was insufficient for the actual write being performed (overwrite a shared cache keyed by `address`, irrespective of who created the pre-existing entry).

### Impact Explanation
`peer_addresses.definition` is consumed as an authoritative source of an address's spending definition/signing paths in multiple flows: `findAddress()` uses `peer_addresses` to route signing requests to `device_address` [5](#0-4) 
and `getSigner().readDefinition` reads straight from `peer_addresses` (unioned with `my_addresses`/`shared_addresses`) to populate the `definition` embedded in a composed unit's author when constructing/co-signing multi-party spends: [6](#0-5) 
and `readFullSigningPaths`/`readAdditionalSigningAddresses` use it to determine which additional signing devices/paths must cosign a shared-address payment: [7](#0-6) [8](#0-7) 

By overwriting this cache with an attacker-chosen `definition`/`signing_paths` for a victim's address (still required to self-hash correctly, so it must be some *valid* definition, just not the real member's actual definition/signing setup), an attacker can corrupt which signing paths/devices the local wallet believes are needed to complete a shared/multisig transaction involving that address, and which device it will route signing requests to (`ifRemote(candidate_addresses[0], [])`). This can be leveraged to misdirect signing requests for shared-address funds to an attacker-controlled device or to disrupt an honest cosigner's ability to route/complete a transaction — a form of AA/shared-fund freezing or facilitation of a bad-actor's spend flow for the affected shared address, satisfying "AA fund loss or freezing" / "unauthorized" write to material used to construct spends. On-chain final validation (`Definition.validateAuthentifiers`) will still ultimately reject signatures that don't check out against the address's true committed chash, which limits the impact to a wallet-state/DoS-style corruption rather than a direct fund theft.

### Likelihood Explanation
Reachable by any paired device that can initiate or respond to a prosaic/arbiter contract offer — no special privilege is required beyond being a correspondent, satisfying the "paired device" attacker model. The trigger only requires supplying a `body.authors[0]` whose `address` collides with a `peer_address` already cached from an unrelated, previous multisig/contract negotiation and a definition that hashes to that address, both of which are entirely attacker-controlled inputs in the message body.

### Recommendation
Scope the `UPDATE peer_addresses ...` (and the initial `INSERT`) with `AND device_address=?` bound to `from_address`, or change the table's key to `(address, device_address)` so a new correspondent's claim cannot silently clobber an existing entry created by a different device. Additionally consider requiring that overwrites of an existing `peer_addresses` row only occur if the previous entry was created by the same `device_address`, otherwise reject or merge with explicit user confirmation.

### Proof of Concept
1. Device A and Device B previously multisig/share an address `X` with Device A, causing `peer_addresses` to have a row `(address=X, device_address=A, definition=D_A)` via a prior shared-address flow.
2. A malicious Device M pairs with the victim's wallet and sends a `prosaic_contract_offer` naming `peer_address = X` (X does not have to be M's own address; M just claims it as the "acceptor" in the negotiation).
3. Victim wallet (unaware X isn't M's real address) proceeds and eventually processes a `prosaic_contract_response` from M with `body.authors = [{ address: X, definition: D_M }]`, where `D_M` is some valid definition chosen by M that hashes to `X`.
4. Because `author.address === objContract.peer_address` (`X`) and the definition self-hashes correctly, the checks at wallet.js:525-532 pass.
5. Since a `peer_addresses` row for `X` already exists (inserted for Device A), the `INSERT ... IGNORE` fails and the code falls through to `UPDATE peer_addresses SET signing_paths=?, definition=? WHERE address=X`, overwriting Device A's legitimate cached definition/signing paths with M's attacker-supplied values — with no check that M is `device_address=A`.
6. Subsequent local operations (`findAddress`, `readFullSigningPaths`, `getSigner().readDefinition`) for shared payments involving `X` now use the corrupted cache, misrouting signing requests or corrupting the wallet's understanding of the multisig, disrupting completion of the shared-address payment.

### Citations

**File:** wallet.js (L515-532)
```javascript
					if (from_address !== objContract.peer_device_address)
						return callbacks.ifError("response is from wrong device");
					if (objContract.is_incoming)
						return callbacks.ifError("this contract is incoming, you cannot accept your own offer");
					var processResponse = function(objSignedMessage) {
						if (body.authors && body.authors.length && objSignedMessage) {
							if (body.authors.length !== 1)
								return callbacks.ifError("wrong number of authors received");
							var author = body.authors[0];
							try {
								if (author.definition && (author.address !== objectHash.getChash160(author.definition)))
									return callbacks.ifError("incorrect definition received");
							}
							catch (e) {
								return callbacks.ifError("invalid definition: " + e);
							}
							if (!ValidationUtils.isValidAddress(author.address) || author.address !== objContract.peer_address)
								return callbacks.ifError("incorrect author address");
```

**File:** wallet.js (L538-544)
```javascript
									db.query("INSERT "+db.getIgnore()+" INTO peer_addresses (address, device_address, signing_paths, definition) VALUES (?, ?, ?, ?)",
										[author.address, from_address, JSON.stringify(Object.keys(objSignedMessage.authors[0].authentifiers)), JSON.stringify(author.definition)],
										function(res) {
											if (res.affectedRows == 0)
												db.query("UPDATE peer_addresses SET signing_paths=?, definition=? WHERE address=?", [JSON.stringify(Object.keys(objSignedMessage.authors[0].authentifiers)), JSON.stringify(author.definition), author.address]);
										}
									);
```

**File:** wallet.js (L899-905)
```javascript
									db.query("INSERT "+db.getIgnore()+" INTO peer_addresses (address, device_address, signing_paths, definition) VALUES (?, ?, ?, ?)",
										[author.address, from_address, JSON.stringify(Object.keys(objSignedMessage.authors[0].authentifiers)), JSON.stringify(author.definition)],
										function(res) {
											if (res.affectedRows == 0)
												db.query("UPDATE peer_addresses SET signing_paths=?, definition=? WHERE address=?", [JSON.stringify(Object.keys(objSignedMessage.authors[0].authentifiers)), JSON.stringify(author.definition), author.address]);
										}
									);
```

**File:** wallet.js (L1289-1310)
```javascript
					db.query(
						"SELECT device_address, signing_paths FROM peer_addresses WHERE address=?", 
						[address],
						function(pa_rows) {
							if (pa_rows.length > 1)
								throw Error("more than 1 peer address found for address "+address);
							var candidate_addresses = [];
							for (var i = 0; i < pa_rows.length; i++) {
								var row = pa_rows[i];
								JSON.parse(row.signing_paths).forEach(function(signing_path_candidate){
									if (signing_path_candidate === signing_path)
										candidate_addresses.push(row.device_address);
								});
							}
							if (candidate_addresses.length > 1)
								throw Error("more than 1 candidate device address found for peer address "+address+" and signing path "+signing_path);
							if (candidate_addresses.length == 1)
								return callbacks.ifRemote(candidate_addresses[0], []);
							if (fallbackInfo)
								return callbacks.ifRemote(fallbackInfo.device_address, fallbackInfo.other_device_addresses);
							return callbacks.ifUnknownAddress();
						}
```

**File:** wallet.js (L1769-1785)
```javascript
					sql = "SELECT signing_paths FROM peer_addresses WHERE address=?";
					arrParams = [member_address];
					if (arrSigningDeviceAddresses && arrSigningDeviceAddresses.length > 0){
						sql += " AND device_address IN(?)";
						arrParams.push(arrSigningDeviceAddresses);
					}
					conn.query(sql, arrParams, function(rows){
						if (!rows.length) {
							assocSigningPaths[path_prefix] = 'key';
							return onDone();
						}
						JSON.parse(rows[0].signing_paths).forEach(function(signing_path){
							assocSigningPaths[path_prefix + signing_path.substr(1)] = 'key';
						});
						return onDone();
					});
				}
```

**File:** wallet.js (L1869-1898)
```javascript
function readAdditionalSigningAddresses(arrPayingAddresses, arrSigningAddresses, arrSigningDeviceAddresses, handleAdditionalSigningAddresses){
	var arrFromAddresses = arrPayingAddresses.concat(arrSigningAddresses);
	var sql = "SELECT DISTINCT address FROM shared_address_signing_paths \n\
		WHERE shared_address IN(?) \n\
			AND ( \n\
				EXISTS (SELECT 1 FROM my_addresses WHERE my_addresses.address=shared_address_signing_paths.address) \n\
				OR \n\
				EXISTS (SELECT 1 FROM shared_addresses WHERE shared_addresses.shared_address=shared_address_signing_paths.address) \n\
				OR \n\
				EXISTS (SELECT 1 FROM peer_addresses WHERE peer_addresses.address=shared_address_signing_paths.address AND peer_addresses.definition IS NOT NULL) \n\
			) \n\
			AND ( \n\
				NOT EXISTS (SELECT 1 FROM addresses WHERE addresses.address=shared_address_signing_paths.address) \n\
				OR ( \n\
					SELECT definition IS NULL \n\
					FROM address_definition_changes CROSS JOIN units USING(unit) LEFT JOIN definitions USING(definition_chash) \n\
					WHERE address_definition_changes.address=shared_address_signing_paths.address AND is_stable=1 AND sequence='good' \n\
					ORDER BY level DESC LIMIT 1 \n\
				) = 1 \n\
			)";
	var arrParams = [arrFromAddresses];
	if (arrSigningAddresses.length > 0){
		sql += " AND address NOT IN(?)";
		arrParams.push(arrSigningAddresses);
	}
	if (arrSigningDeviceAddresses && arrSigningDeviceAddresses.length > 0){
		sql += " AND device_address IN(?)";
		arrParams.push(arrSigningDeviceAddresses);
	}
	db.query(
```

**File:** wallet.js (L2001-2014)
```javascript
		readDefinition: function (conn, address, handleDefinition) {
			conn.query(
				"SELECT definition FROM my_addresses WHERE address=? \n\
				UNION \n\
				SELECT definition FROM shared_addresses WHERE shared_address=? \n\
				UNION \n\
				SELECT definition FROM peer_addresses WHERE address=?",
				[address, address, address],
				function (rows) {
					if (rows.length !== 1)
						throw Error("definition not found for address " + address);
					handleDefinition(null, JSON.parse(rows[0].definition));
				}
			);
```

**File:** initial-db/byteball-mysql.sql (L755-763)
```sql
CREATE TABLE peer_addresses (
	address CHAR(32) NOT NULL,
	signing_paths VARCHAR(255) NULL,
	device_address CHAR(33) NOT NULL,
	definition LONGTEXT NULL,
	creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (address),
	FOREIGN KEY (device_address) REFERENCES correspondent_devices(device_address)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
```
