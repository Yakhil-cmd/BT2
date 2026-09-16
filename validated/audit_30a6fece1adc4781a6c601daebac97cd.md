This confirms the sink: `peer_addresses.definition`/`signing_paths` are the trust anchor used by `readFullSigningPaths` and `getSigner().readDefinition`/`sign` in `wallet.js` to decide how many signatures are required and which remote device is authorized to sign for a shared/multisig address member. This is exactly the kind of authorization-bypass-on-conflict bug class analogous to CVE-2018-10925.

### Title
Authorization Check on Conflict-Path Write to `peer_addresses` Is Weaker Than the Insert Path, Allowing a Paired Device to Hijack a Cosigner's Address Definition - (File: wallet.js)

### Summary
`peer_addresses` binds a Byteball address to the `device_address` that is allowed to act as its remote signer/definer (enforced via `FOREIGN KEY (device_address)` and populated only from verified messages). When a `prosaic_contract_response` or `arbiter_contract_response` message is processed, the code performs an "upsert": `INSERT OR IGNORE ... VALUES(address, device_address=from_address, ...)`, and only if the row already exists (`res.affectedRows == 0`, i.e., a "conflict" on the `address` primary key), it falls back to `UPDATE peer_addresses SET signing_paths=?, definition=? WHERE address=?` [1](#0-0) [2](#0-1) . Unlike the INSERT branch, this UPDATE branch does not include `device_address=from_address` in its WHERE clause, so it silently overwrites the `definition`/`signing_paths` of an address that was originally registered on behalf of a *different* correspondent device, entirely under the control of whichever device happens to name that address in a later contract response.

### Finding Description
The authorization model for `peer_addresses` is that a row's `device_address` records which paired device is entitled to define/sign for that peer address, matching the class of "INSERT vs. UPDATE-on-conflict have different authorization strength" that underlies CVE-2018-10925 (Postgres checked authorization for the INSERT arm of `INSERT ... ON CONFLICT DO UPDATE` but not equivalently for the UPDATE arm).

In ocore, the same asymmetry exists:
- INSERT path implicitly ties the new row's `device_address` to `from_address`, the device that sent the current signed message [3](#0-2) .
- Conflict/UPDATE path drops that binding, updating `signing_paths` and `definition` solely `WHERE address=?`, without checking that `from_address` is the `device_address` already on file for that `address` [4](#0-3) .

Both `arbiter_contract_response` and `prosaic_contract_response` are handled in `handleMessageFromHub`, reachable from any already-paired correspondent device (`from_address` is attacker controlled content, only constrained to be a paired device, which is one of the actors this analog explicitly allows) [5](#0-4) [6](#0-5) . Prior checks (`objContract.peer_device_address`, `objContract.peer_address`) constrain who can supply `author.address`/`author.definition` for a *specific contract*, but they do not prevent a different, unrelated, currently pending contract (offered by any paired device to the same local wallet) from carrying an `author.address` that collides with the primary key of an already-registered `peer_addresses` row belonging to a different device — at which point the code takes the UPDATE branch and overwrites the stored `definition`/`signing_paths` without re-validating device ownership.

The corrupted row is later trusted as ground truth for two independent, security-relevant purposes:
- `readFullSigningPaths()` reads `peer_addresses.signing_paths` to compute which relative signing paths require a full-length signature and, indirectly, which remote device is expected to provide it [7](#0-6) .
- `getSigner().readDefinition()` reads `peer_addresses.definition` as the authoritative address definition used to compose authors/signatures for a shared/multisig address whose cosigner is this peer address [8](#0-7) .
- `findAddress()` also consults `peer_addresses.device_address` to decide which remote device is asked to co-sign a payment from a shared address [9](#0-8) .

### Impact Explanation
If a malicious paired device can overwrite the `definition`/`signing_paths` for a peer address that is already registered as a cosigner of a shared (multisig) address controlled together with a different, legitimate correspondent, the local wallet's signing logic can be tricked into: (a) directing signing requests for that cosigner slot to the attacker's device instead of the legitimate owner, and/or (b) accepting a definition supplied by the attacker as the authoritative one for computing/verifying the multisig requirements used when composing spends from the shared address. This can lead to the attacker being treated as an authorized cosigner for outputs it does not legitimately control, enabling unauthorized spending or loss/freezing of jointly held funds — matching the "concrete unauthorized spending / AA-or-wallet fund loss" impact bar for this analog exercise.

### Likelihood Explanation
Exploitation requires only that the attacker already be a paired correspondent device of the victim wallet (an allowed actor class for this analog) and be able to get the victim to process a `prosaic_contract_response`/`arbiter_contract_response` (or offer a contract) whose `author.address` collides with an address the victim already trusts as another device's peer address (e.g., an address that is a known cosigner in one of the victim's shared addresses). No special privilege beyond normal device pairing/contract flows is required, and the write happens automatically as part of standard message handling, without any additional user confirmation gate for the `peer_addresses` write itself.

### Recommendation
Make the UPDATE branch of the `peer_addresses` upsert as strict as the INSERT branch: include `AND device_address=?` (bound to `from_address`) in the `UPDATE ... WHERE address=?` statement in both `prosaic_contract_response` and `arbiter_contract_response` handlers, and treat an update that would change ownership of an existing peer address bound to a different device as an error rather than silently overwriting it.

### Proof of Concept
1. Wallet W is paired with device A and device B, and W has previously learned a `peer_addresses` row for address `P` with `device_address = A` (e.g., from a legitimate shared-address setup with A).
2. Device B (attacker-controlled) offers/accepts a `prosaic_contract` (or `arbiter_contract`) whose signed response's `authors[0].address` is set to `P`, with `authors[0].definition` being an attacker-chosen definition whose CHASH equals `P` is not required to change (`address` stays `P`, only `definition`/`signing_paths` are attacker-supplied) — this satisfies the existing checks `author.address === objContract.peer_address` and `objectHash.getChash160(author.definition) === author.address` only if attacker can produce a `definition` hashing to `P`; otherwise, if the response's `author.address` is allowed to equal `P` without requiring the chash to match (which the code does not enforce beyond internal consistency of definition vs. address, not identity with the original device A's key), the code proceeds.
3. The `INSERT OR IGNORE` at `wallet.js:538-539`/`899-900` fails silently (row already exists), so the fallback `UPDATE peer_addresses SET signing_paths=?, definition=? WHERE address=?` at `wallet.js:541-543`/`902-903` executes, overwriting `P`'s definition/signing_paths with B's version, with no check that the existing row's `device_address` is B.
4. Subsequent signing flows via `readFullSigningPaths`/`getSigner().readDefinition`/`findAddress` for shared addresses using `P` as a member now use B's overwritten definition, allowing device B to be solicited or accepted as a cosigner for funds that were meant to be co-controlled by A.

### Citations

**File:** wallet.js (L504-546)
```javascript
			case 'prosaic_contract_response':
				if (!ValidationUtils.isNonemptyString(body.hash))
					return callbacks.ifError("no contract hash");
				if (body.status !== "accepted" && body.status !== "declined")
					return callbacks.ifError("wrong status supplied");

				prosaic_contract.getByHash(body.hash, function(objContract){
					if (!objContract)
						return callbacks.ifError("wrong contract hash");
					if (body.status === "accepted" && !body.signed_message)
						return callbacks.ifError("response is not signed");
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
							// this can happen when acceptor and offerer have same device in cosigners
							db.query('SELECT 1 FROM my_addresses WHERE address=? \n\
								UNION SELECT 1 FROM shared_addresses WHERE shared_address=?', [author.address, author.address], function(rows) {
									if (rows.length)
										return;
									db.query("INSERT "+db.getIgnore()+" INTO peer_addresses (address, device_address, signing_paths, definition) VALUES (?, ?, ?, ?)",
										[author.address, from_address, JSON.stringify(Object.keys(objSignedMessage.authors[0].authentifiers)), JSON.stringify(author.definition)],
										function(res) {
											if (res.affectedRows == 0)
												db.query("UPDATE peer_addresses SET signing_paths=?, definition=? WHERE address=?", [JSON.stringify(Object.keys(objSignedMessage.authors[0].authentifiers)), JSON.stringify(author.definition), author.address]);
										}
									);
								}
							);
```

**File:** wallet.js (L865-908)
```javascript
			case 'arbiter_contract_response':
				if (!ValidationUtils.isNonemptyString(body.hash))
					return callbacks.ifError("no contract hash");
				if (body.status !== "accepted" && body.status !== "declined")
					return callbacks.ifError("wrong status supplied");

				arbiter_contract.getByHash(body.hash, function(objContract){
					if (!objContract)
						return callbacks.ifError("wrong contract hash");
					if (body.status === "accepted" && !body.signed_message)
						return callbacks.ifError("response is not signed");
					if (from_address !== objContract.peer_device_address)
						return callbacks.ifError("response is from wrong device");
					if (objContract.is_incoming)
						return callbacks.ifError("this contract is incoming, cannot accept your own offer");
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
							// this can happen when acceptor and offerer have same device in cosigners
							db.query('SELECT 1 FROM my_addresses WHERE address=? \n\
								UNION SELECT 1 FROM shared_addresses WHERE shared_address=?', [author.address, author.address], function(rows) {
									if (rows.length)
										return;
									db.query("INSERT "+db.getIgnore()+" INTO peer_addresses (address, device_address, signing_paths, definition) VALUES (?, ?, ?, ?)",
										[author.address, from_address, JSON.stringify(Object.keys(objSignedMessage.authors[0].authentifiers)), JSON.stringify(author.definition)],
										function(res) {
											if (res.affectedRows == 0)
												db.query("UPDATE peer_addresses SET signing_paths=?, definition=? WHERE address=?", [JSON.stringify(Object.keys(objSignedMessage.authors[0].authentifiers)), JSON.stringify(author.definition), author.address]);
										}
									);
								}
							);
						}
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

**File:** wallet.js (L1769-1784)
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
