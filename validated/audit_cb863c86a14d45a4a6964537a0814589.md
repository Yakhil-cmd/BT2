Confirmed: the analog exists in the `signed_message.js` credential-verification path used by `is_valid_signed_package()` in AA oscript evaluation.

### Title
AA `is_valid_signed_package()` accepts a signed package tied to an address's original (genesis) definition even after the address owner has revoked/rotated it via `address_definition_change` - (File: `signed_message.js`)

### Summary
`validateSignedMessage()` has two verification modes: a network-aware mode (`last_ball_unit` present) that resolves the address's *current* definition as of a given MCI (correctly reflecting any `address_definition_change`), and a non-network-aware mode that only checks `chash160(definition) === address`. Because an address hash is computed once from its genesis definition and never changes, the non-network-aware branch will forever accept a signed package built with the original/compromised keyset, regardless of any later revocation of that keyset, exactly mirroring the Casdoor flaw where a signature/JWT is validated cryptographically but its revocation status is never checked.

### Finding Description
`validateOrReadDefinition()` in [1](#0-0)  handles the case where the signed package has no `last_ball_unit` (`bNetworkAware=false`). In that branch it only verifies `objectHash.getChash160(objAuthor.definition) !== objAuthor.address`, i.e. that the supplied definition hashes to the address — which is always true for the address's original genesis definition, by construction, and is not tied to the address's DB-tracked current definition. It never consults `storage.readDefinitionByAddress` (nor `address_definition_changes`) to determine whether this specific definition is still the one currently in force for that address.

By contrast, the network-aware branch [2](#0-1)  does call `storage.readDefinitionByAddress(conn, objAuthor.address, last_ball_mci, ...)`, which correctly reflects any subsequent `address_definition_change` (key rotation/revocation) recorded in `address_definition_changes`, as validated in [3](#0-2) .

This dual-mode function is exposed to AA oscript through `is_valid_signed_package`, reachable by any AA trigger sender who controls trigger data used to build `$pkg`: [4](#0-3) . The `last_ball_unit` check at line 1684 is conditional (`if (typeof signedPackage.last_ball_unit === 'string')`); if the attacker simply omits `last_ball_unit` from the package, `signed_message.validateSignedMessage` is called in non-network-aware mode, bypassing the current-definition/revocation check entirely: [5](#0-4) .

### Impact Explanation
If an AA author uses `is_valid_signed_package($pkg, $address)` as an authorization/attestation gate (e.g., verifying that a particular address approved a withdrawal, an oracle attestation, a multisig cosignature, or KYC/attestation-style approval encoded off-chain), an attacker who once possessed the address's original private key(s) can keep forging valid `is_valid_signed_package` results forever by omitting `last_ball_unit`, even after the legitimate owner has rotated away from that compromised keyset via `address_definition_change`. This can lead to AA fund loss or unauthorized state transitions gated on an address's "current" authorization, because the AA's presumed revocation (key rotation) provides no actual protection against this specific verification primitive.

### Likelihood Explanation
Exploitation requires only sending a standard AA trigger with attacker-controlled JSON data — no special privileges, no network position, and no reliance on peer/hub trust. The precondition (attacker previously held valid signing material for the address, later revoked by the legitimate owner) is a realistic threat model (e.g., recovering from key compromise), and the omission of `last_ball_unit` is trivial for the attacker to control since `$pkg` is typically built from trigger data in the AA's oscript.

### Recommendation
When `is_valid_signed_package` (or `validateSignedMessage` generally) is used to assert current authorization of an address, either:
- require `last_ball_unit` to be present and reject non-network-aware packages in this evaluation context, or
- in the non-network-aware branch of `signed_message.js`, additionally check `storage.readDefinitionByAddress` (or `address_definition_changes`) for the address at some verifiable MCI to ensure the presented definition is still the currently active one, not merely a definition that once hashed to the address.

### Proof of Concept
1. Address `A` is created with keyset `K1` (genesis definition `D1`, `chash160(D1) === A`).
2. Owner detects `K1` compromise and issues `address_definition_change` to `D2`/`K2`, recorded in `address_definition_changes` (validated per [3](#0-2) ).
3. Attacker (who has `K1`) builds `$pkg = { signed_message: "authorize X", authors: [{ address: A, definition: D1, authentifiers: {...signed with K1...} }] }` — deliberately omitting `last_ball_unit`.
4. Attacker sends this as trigger data to a victim AA that calls `is_valid_signed_package($pkg, A)`.
5. `formula/evaluation.js` skips the `last_ball_unit` branch (absent) and calls `signed_message.validateSignedMessage` in non-network-aware mode, which only checks `chash160(D1) === A` (always true) and validates `K1`'s signature — succeeding despite `A` having revoked `D1`/`K1`.
6. The AA treats the package as a valid, current authorization from `A`, enabling unauthorized fund release or state change gated on this check.

### Citations

**File:** signed_message.js (L219-238)
```javascript
				storage.readDefinitionByAddress(conn, objAuthor.address, last_ball_mci, {
					ifDefinitionNotFound: function (definition_chash) { // first use of the definition_chash (in particular, of the address, when definition_chash=address)
						if (!bHasDefinition) {
							if (!conf.bLight || bRetrying)
								return handleResult("definition expected but not provided");
							var network = require('./network.js');
							return network.requestHistoryFor([], [objAuthor.address], function () {
								validateOrReadDefinition(objAuthor, cb, true);
							});
						}
						if (objectHash.getChash160(objAuthor.definition) !== definition_chash)
							return handleResult("wrong definition: "+objectHash.getChash160(objAuthor.definition) +"!=="+ definition_chash);
						cb(objAuthor.definition, last_ball_mci, last_ball_timestamp);
					},
					ifFound: function (arrAddressDefinition) {
						if (bHasDefinition)
							return handleResult("should not include definition");
						cb(arrAddressDefinition, last_ball_mci, last_ball_timestamp);
					}
				});
```

**File:** signed_message.js (L241-252)
```javascript
		else {
			if (!bHasDefinition)
				return handleResult("no definition");
			try {
				if (objectHash.getChash160(objAuthor.definition) !== objAuthor.address)
					return handleResult("wrong definition: " + objectHash.getChash160(objAuthor.definition) + "!==" + objAuthor.address);
			} catch (e) {
				return handleResult("failed to calc address definition hash: " + e);
			}
			// no last_ball_unit of its own; before the fix, always behave as before (-1) to keep old units re-evaluating the same way
			cb(objAuthor.definition, (mci >= constants.pemCurvesFixMci) ? mci : -1, 0);
		}
```

**File:** validation.js (L1719-1746)
```javascript
		case "address_definition_change":
			if (!isNonemptyObject(payload))
				return callback("payload must be a non empty object");
			if (hasFieldsExcept(payload, ["definition_chash", "address"]))
				return callback("unknown fields in address_definition_change");
			var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
			var address;
			if (objUnit.authors.length > 1){
				if (!isValidAddress(payload.address))
					return callback("when multi-authored, must indicate address");
				if (arrAuthorAddresses.indexOf(payload.address) === -1)
					return callback("foreign address");
				address = payload.address;
			}
			else{
				if ('address' in payload)
					return callback("when single-authored, must not indicate address");
				address = arrAuthorAddresses[0];
			}
			if (!objValidationState.arrDefinitionChangeFlags)
				objValidationState.arrDefinitionChangeFlags = {};
			if (objValidationState.arrDefinitionChangeFlags[address])
				return callback("can be only one definition change per address");
			objValidationState.arrDefinitionChangeFlags[address] = true;
			if (!isValidAddress(payload.definition_chash))
				return callback("bad new definition_chash");
			return callback();

```

**File:** formula/evaluation.js (L1653-1702)
```javascript
			case 'is_valid_signed_package':
				if (!objValidationState.count_signed_packages)
					objValidationState.count_signed_packages = 0;
				if (objValidationState.count_signed_packages >= constants.MAX_SIGNED_PACKAGES_PER_AA_EVAL && bPostPemCurvesFix)
					return setFatalError("too many signed packages in evaluation", { arr }, false, cb);
				objValidationState.count_signed_packages++;
				var signed_package_expr = arr[1];
				var address_expr = arr[2];
				evaluate(address_expr, function (evaluated_address) {
					if (fatal_error)
						return cb(false);
					if (!ValidationUtils.isValidAddress(evaluated_address))
						return setFatalError("bad address in is_valid_signed_package: " + evaluated_address, { arr }, false, cb);
					evaluate(signed_package_expr, async function (signedPackage) {
						if (fatal_error)
							return cb(false);
						if (!(signedPackage instanceof wrappedObject))
							return cb(false);
						signedPackage = signedPackage.obj;
						if (ValidationUtils.hasFieldsExcept(signedPackage, ['signed_message', 'last_ball_unit', 'authors', 'version']))
							return cb(false);
						if (signedPackage.version) {
							if (typeof signedPackage.version !== 'string')
								return cb(false);
							if (signedPackage.version === constants.versionWithoutTimestamp)
								return cb(false);
							const fVersion = parseFloat(signedPackage.version);
							const maxVersion = 4; // depends on mci in the future updates
							if (fVersion > maxVersion)
								return cb(false);
						}
						if (typeof signedPackage.last_ball_unit === 'string') {
							const [row] = await conn.query("SELECT main_chain_index, is_on_main_chain FROM units WHERE unit=?", [signedPackage.last_ball_unit]);
							if (!row || row.main_chain_index > mci || row.main_chain_index === null) // not existing or not stable last ball unit
								return cb(false);
							if (!row.is_on_main_chain && mci >= constants.pemCurvesFixMci) // last ball must be on the MC
								return cb(false);
							if (mci >= constants.pemCurvesFixMci && row.main_chain_index < constants.pemCurvesFixMci) // last ball unit is before the fix
								return setFatalError("last ball unit is before the PEM curves fix", { arr }, false, cb);
						}
						signed_message.validateSignedMessage(conn, signedPackage, evaluated_address, mci, function (err, last_ball_mci) {
							if (err)
								return cb(false);
							if (last_ball_mci === null || last_ball_mci > mci)
								return cb(false);
							cb(true);
						});
					});
				});
				break;
```
