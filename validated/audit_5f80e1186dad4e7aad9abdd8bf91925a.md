## Title
Stale/superseded address definitions are accepted by `is_valid_signed_package`, allowing revoked signing keys to satisfy AA authorization checks - (File: signed_message.js)

### Summary
`is_valid_signed_package` (oscript/AA formula operator) and other network-aware users of `validateSignedMessage()` verify a `signed_message` against the address definition that was active at the *attacker-chosen* `last_ball_unit`, rather than the address's *current* definition. Because there is no requirement that this reference point be recent, a party can present a signed package proving control of an address using a definition that has since been superseded (e.g. after a key rotation/definition change performed because the old key was compromised), and the check will still succeed — the oscript/AA equivalent of a deactivated credential still being able to "authenticate."

### Finding Description
`signed_message.validateSignedMessage()` supports a "network-aware" mode (`bNetworkAware`, triggered by the presence of `last_ball_unit` in the signed package). In this mode the definition used to check the authentifiers is fetched from the historical DAG state at the MCI of the caller-supplied `last_ball_unit`, not from the address's up-to-date definition: [1](#0-0) 

Specifically, `storage.readDefinitionByAddress(conn, objAuthor.address, last_ball_mci, ...)` returns whatever definition was in force at that (attacker-chosen) historical MCI: [2](#0-1) 

`readDefinitionChashByAddress` simply picks the latest `address_definition_changes` row with `main_chain_index<=max_mci`, so any MCI predating a key-rotation event still returns the old, now-superseded definition: [3](#0-2) 

This mechanism is directly exposed to an unprivileged AA trigger sender through the `is_valid_signed_package` oscript/formula operator, which AAs commonly use to authorize actions (e.g. verifying that a message/action really comes from a specific address). The only freshness constraint applied there is that the referenced `last_ball_unit`'s MCI must not be in the future relative to the AA's evaluation MCI and must be on the main chain — there is no requirement that it be recent: [4](#0-3) 

Because any main-chain-included, non-future `last_ball_unit` qualifies, an attacker who once controlled a private key belonging to a definition that the true address owner has since replaced (via `address_definition_change`, e.g. after the key was suspected compromised or revoked) can still forge a `signed_message` that validates successfully by anchoring it to an old `last_ball_unit` from before the rotation and signing with the old key. `Definition.validateAuthentifiers` then checks the signature purely against that stale definition: [5](#0-4) 

The same weakness affects other consumers of `validateSignedMessage` with `bNetworkAware` set, such as device-to-device arbiter contract responses, where a peer's signed acceptance/decline is authenticated the same way: [6](#0-5) 

### Impact Explanation
An AA that relies on `is_valid_signed_package` to authenticate a message/action from a particular address (a common pattern for oracle attestations, multi-party protocols, or access-control gates built in oscript) can be tricked into accepting authorization from a key that the legitimate address owner has explicitly revoked/rotated away from. Depending on what the AA gates behind this check (fund releases, governance actions, oracle updates), this can lead to AA fund loss, unauthorized state changes, or acceptance of stale/forged authorization — the direct analog of a deactivated account still being able to authenticate and act.

### Likelihood Explanation
Exploitation requires the attacker to have previously possessed a valid private key for an address that later had its definition changed (a realistic scenario: compromised-key rotation, cosigner removal via redefinition, or routine key hygiene). The attacker only needs to reference an old, already-stable `last_ball_unit` and sign with the old key — no privileged access or race condition is needed, and the AA-side check (`main_chain_index <= mci`) does not filter out stale references.

### Recommendation
When validating network-aware signed packages (both in `is_valid_signed_package` and in `validateSignedMessage`/arbiter flows), require that the referenced `last_ball_unit` reflect the address's *current* definition (e.g., reject if a later `address_definition_change` for that address exists with `main_chain_index <= mci`), or otherwise bound how stale the reference point may be relative to the evaluation MCI.

### Proof of Concept
1. Address `A` is defined with key `K1` (definition D1, `chash160(D1) == A`).
2. `A` posts `address_definition_change` to switch to key `K2` (definition D2); this stabilizes at MCI `M2`.
3. Attacker, who has `K1`, crafts `objSignedMessage = { signed_message: <payload>, last_ball_unit: <a stable unit at MCI M1 < M2>, authors: [{ address: A, authentifiers: { r: sig_with_K1 } }] }`.
4. An AA calls `is_valid_signed_package(objSignedMessage, A)`; per `formula/evaluation.js:1684-1699` the only check is `main_chain_index(last_ball_unit) <= current_mci`, which passes since `M1 <= current_mci`.
5. `validateSignedMessage` resolves `A`'s definition at MCI `M1` (i.e., D1/K1) via `storage.readDefinitionByAddress`, and the signature made with the revoked key `K1` verifies successfully, even though `A`'s current definition is D2/K2.

### Citations

**File:** signed_message.js (L197-239)
```javascript
	function validateOrReadDefinition(objAuthor, cb, bRetrying) {
		var bHasDefinition = ("definition" in objAuthor);
		if (bNetworkAware) {
			conn.query("SELECT main_chain_index, timestamp FROM units WHERE unit=?", [objSignedMessage.last_ball_unit], function (rows) {
				if (rows.length === 0) {
					var network = require('./network.js');
					if (!conf.bLight && !network.isCatchingUp() || bRetrying)
						return handleResult("last_ball_unit " + objSignedMessage.last_ball_unit + " not found");
					if (conf.bLight)
						network.requestHistoryFor([objSignedMessage.last_ball_unit], [objAuthor.address], function () {
							validateOrReadDefinition(objAuthor, cb, true);
						});
					else
						eventBus.once('catching_up_done', function () {
							// no retry flag, will retry multiple times until the catchup is over
							validateOrReadDefinition(objAuthor, cb);
						});
					return;
				}
				bRetrying = false;
				var last_ball_mci = rows[0].main_chain_index;
				var last_ball_timestamp = rows[0].timestamp;
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
			});
```

**File:** signed_message.js (L255-303)
```javascript
	let last_ball_mci;
	let complexity = 0;
	async.eachSeries(
		authors,
		function (objAuthor, cb) {
			validateOrReadDefinition(objAuthor, function (arrAddressDefinition, _last_ball_mci, last_ball_timestamp) {
				last_ball_mci = _last_ball_mci;
				var objUnit = _.clone(objSignedMessage);
				objUnit.messages = []; // some ops need it
				try {
					var objValidationState = {
						unit_hash_to_sign: objectHash.getSignedPackageHashToSign(objSignedMessage),
						last_ball_mci: last_ball_mci,
						last_ball_timestamp: last_ball_timestamp,
						bNoReferences: !bNetworkAware,
						complexity,
						max_complexity,
					};
				}
				catch (e) {
					return cb("failed to calc unit_hash_to_sign: " + e);
				}
				try {
					// passing db as null
					Definition.validateAuthentifiers(
						conn, objAuthor.address, null, arrAddressDefinition, objUnit, objValidationState, objAuthor.authentifiers,
						function (err, res) {
							if (err) // error in address definition
								return cb(err);
							if (!res) // wrong signature or the like
								return cb("authentifier verification failed");
							complexity = objValidationState.complexity;
							cb();
						}
					);
				}
				catch (e) {
					console.log("exception while validating signed message:", e);
					return cb("exception while validating: " + e);
				}
			});
		},
		function (err) {
			if (err)
				return handleResult(err);
			handleResult(null, last_ball_mci);
		}
	);
}
```

**File:** storage.js (L754-768)
```javascript
function readDefinitionChashByAddress(conn, address, max_mci, handle){
	if (!handle)
		return new Promise(resolve => readDefinitionChashByAddress(conn, address, max_mci, resolve));
	if (max_mci == null || max_mci == undefined)
		max_mci = MAX_INT32;
	// try to find last definition change, otherwise definition_chash=address
	conn.query(
		"SELECT definition_chash FROM address_definition_changes CROSS JOIN units USING(unit) \n\
		WHERE address=? AND is_stable=1 AND sequence='good' AND main_chain_index<=? ORDER BY main_chain_index DESC, level DESC LIMIT 1", 
		[address, max_mci], 
		function(rows){
			var definition_chash = (rows.length > 0) ? rows[0].definition_chash : address;
			handle(definition_chash);
	});
}
```

**File:** storage.js (L771-776)
```javascript
// max_mci must be stable
function readDefinitionByAddress(conn, address, max_mci, callbacks){
	readDefinitionChashByAddress(conn, address, max_mci, function(definition_chash){
		readDefinitionAtMci(conn, definition_chash, max_mci, callbacks);
	});
}
```

**File:** formula/evaluation.js (L1684-1699)
```javascript
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
```

**File:** wallet.js (L924-936)
```javascript
					if (body.signed_message) {
						try{
							var signedMessageJson = Buffer.from(body.signed_message, 'base64').toString('utf8');
							var objSignedMessage = JSON.parse(signedMessageJson);
						}
						catch(e){
							return callbacks.ifError("wrong signed message");
						}
						signed_message.validateSignedMessage(db, objSignedMessage, objContract.peer_address, function(err) {
							if (err || objSignedMessage.authors[0].address !== objContract.peer_address || objSignedMessage.signed_message != objContract.title)
								return callbacks.ifError("wrong contract signature");
							processResponse(objSignedMessage);
						});
```
