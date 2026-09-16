### Title
Irreversible one-step `address_definition_change` allows permanent, unrecoverable freezing of an address's funds - (File: `validation.js`, `definition.js`, `composer.js`, `writer.js`)

### Summary
Ocore's `address_definition_change` message lets an address owner replace the address's authentication definition in a single, immediately-binding step, exactly the anti-pattern described in the Beanstalk report: a privileged/critical state change (here, control of an address) is performed by one call with no propose-then-accept, two-step confirmation. Validation only checks that the supplied `definition_chash` is syntactically well-formed, never that the poster actually possesses (or can prove control of) a definition hashing to that value. A single mistake — typo, wrong variable, stale/foreign chash — permanently and irrevocably bricks the address once the change becomes stable, freezing any current or future funds sent to it.

### Finding Description
The message is composed with `composeDefinitionChangeJoint()`, which just wraps the new `definition_chash` into an inline `address_definition_change` message with no further checks: [1](#0-0) 

Validation of this message in `validateInlinePayload()` only verifies the payload shape and that `definition_chash` is a validly-formatted address/chash string — it does not verify that the sender knows a definition whose hash equals the new value, nor does it require any subsequent step from a "new owner" to accept the change: [2](#0-1) 

Once the unit is stable, `writer.js` records the change into `address_definition_changes`, and this becomes the authoritative definition source for the address going forward: [3](#0-2) 

`storage.readDefinitionChashByAddress()`/`readDefinitionByAddress()` resolve the current controlling `definition_chash` as the most recent *stable* entry in `address_definition_changes`, falling back to the address itself only when no change exists: [4](#0-3) 

Any subsequent unit signed from that address must supply a `definition` whose hash equals this stored `definition_chash` (see `validateAuthor`'s `ifDefinitionNotFound`/`ifFound` handling in `validation.js#L1464-1500` and `#L1149-1211`), and `checkNoPendingChangeOfDefinitionChash()` further prevents spending from the address while a change is pending/unstable: [5](#0-4) 

If the `definition_chash` supplied in the one-step change does not correspond to any definition the author (or anyone) actually holds, there is no way to reverse the change: the address can never again produce a unit satisfying `objectHash.getChash160(definition) === definition_chash`, so it is permanently locked. This is architecturally identical to Beanstalk's `transferOwnership()`/`setContractOwner()` pattern: one function call immediately and irreversibly assigns new "ownership" (control) with no proposal + explicit acceptance step to catch mistakes before they take permanent effect.

### Impact Explanation
Unlike an ordinary payment sent to the wrong address (which only loses that one payment), a mistaken `address_definition_change` bricks the *entire address*: all currently-held balances and any future incoming payments to that address become permanently unspendable, because nobody can ever again produce valid authentifiers matching the erroneous `definition_chash`. This is a concrete, severe fund-freezing condition reachable by any ordinary unit poster/wallet user, matching the "AA fund loss or freezing" / permanent-misconfiguration impact class described in the source report.

### Likelihood Explanation
Likelihood is realistic though not trivial: it requires either a bug in wallet/UI code that composes the message with a wrong `definition_chash` (e.g., variable mix-up, hashing the wrong definition, using a chash the user does not actually control), or a user manually crafting/pasting an incorrect value through advanced/API usage of `composeDefinitionChangeJoint()`. Given that the protocol itself performs no possession/control check on the new definition before committing the change, any such application-level or user error becomes an irrecoverable protocol-level state change once the unit stabilizes.

### Recommendation
Introduce a two-step definition-change flow analogous to standard secure ownership-transfer patterns:
1. Treat `address_definition_change` as a "proposal" that only takes effect once the address subsequently signs/authenticates at least once using the *new* definition (i.e., require proof-of-possession of the new definition, such as an accompanying valid signature under the new definition, before committing it as authoritative), or
2. Provide a bounded grace/cancellation window during which the current definition can still override or cancel a pending, not-yet-stable change (partially exists via the "pending change" check, but there is no explicit cancel/accept UX), and ensure wallets always locally verify they hold matching private keys for the new `definition_chash` before broadcasting.
Additionally, document this as a known irreversible action in wallet UIs, with prominent confirmation and dry-run verification that the signing keys for the new definition are available locally before the message is sent.

### Proof of Concept
1. Compose `objMessage = {app: "address_definition_change", payload: {definition_chash: X}}` via `composeDefinitionChangeJoint(from_address, X, signer, callbacks)` where `X` is a base32 chash that is a valid address format (`isValidAddress(X)` returns true) but does not correspond to any definition array the poster actually controls (e.g., accidental use of an unrelated address string, or a chash for a definition template whose private key was never generated).
2. Sign and post the unit from `from_address` using its current, valid definition — validation only checks `isValidAddress(payload.definition_chash)` (`validation.js#L1743`), so the message passes.
3. Once the unit becomes stable, `address_definition_changes` records `X` as the new controlling `definition_chash` for `from_address` (`writer.js#L186-192`), and `readDefinitionChashByAddress` now returns `X` for all future signature checks (`storage.js#L754-768`).
4. Any future unit from `from_address` must supply `definition` such that `getChash160(definition) === X`. Since no such definition is known/controlled, no future unit from `from_address` can ever validate — all current and future funds at `from_address` are permanently frozen, with no on-chain corrective step available.

### Citations

**File:** composer.js (L85-87)
```javascript
function composeDefinitionChangeJoint(from_address, definition_chash, signer, callbacks){
	composeContentJoint(from_address, "address_definition_change", {definition_chash: definition_chash}, signer, callbacks);
}
```

**File:** validation.js (L1345-1377)
```javascript
	// don't allow contradicting pending keychanges.
	// We don't trust pending keychanges even when they are serial, as another unit may arrive and make them nonserial
	function checkNoPendingChangeOfDefinitionChash(){
		var next = checkNoPendingDefinition;
		//var filter = bNonserial ? "AND sequence='good'" : "";
		conn.query(
			"SELECT unit FROM address_definition_changes JOIN units USING(unit) \n\
			WHERE address=? AND (is_stable=0 OR main_chain_index>? OR main_chain_index IS NULL)", 
			[objAuthor.address, objValidationState.last_ball_mci], 
			function(rows){
				if (rows.length === 0)
					return next();
				if (!bNonserial || objValidationState.arrAddressesWithForkedPath.indexOf(objAuthor.address) === -1)
					return callback("you can't send anything before your last keychange is stable and before last ball");
				// from this point, our unit is nonserial
				async.eachSeries(
					rows,
					function(row, cb){
						graph.determineIfIncludedOrEqual(conn, row.unit, objUnit.parent_units, function(bIncluded){
							if (bIncluded)
								console.log("checkNoPendingChangeOfDefinitionChash: unit "+row.unit+" is included");
							bIncluded ? cb("found") : cb();
						});
					},
					function(err){
						(err === "found") 
							? callback("you can't send anything before your last included keychange is stable and before last ball (self is nonserial)") 
							: next();
					}
				);
			}
		);
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

**File:** writer.js (L184-192)
```javascript
				if (message.payload_location === "inline"){
					switch (message.app){
						case "address_definition_change":
							var definition_chash = message.payload.definition_chash;
							var address = message.payload.address || objUnit.authors[0].address;
							conn.addQuery(arrQueries, 
								"INSERT INTO address_definition_changes (unit, message_index, address, definition_chash) VALUES(?,?,?,?)", 
								[objUnit.unit, i, address, definition_chash]);
							break;
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
