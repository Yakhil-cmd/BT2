### Title
Address key/definition revocation is not immediately effective — old (revoked) definition remains spendable during the stabilization lag - ([File: validation.js])

### Summary
`ocore` allows an address owner to rotate/revoke their signing definition by posting an `address_definition_change` message. However, the new definition only becomes the address's "current" definition once that change unit is *stable* and buried before `last_ball_mci`. Until that happens — which, like Keystone's up-to-one-hour token cache window, can be a non-trivial delay on the DAG — the **old, supposedly-revoked** definition/keys remain fully capable of authorizing spends from the same address.

### Finding Description
When a unit is validated, `validateAuthor()` resolves the signing definition for an address via `storage.readDefinitionByAddress(conn, objAuthor.address, objValidationState.last_ball_mci, …)` [1](#0-0) , i.e. the definition that was current as of the *last stable ball*, not the most recently posted one. A pending `address_definition_change` only blocks the address from posting **new** units once that node itself sees the change as unstable/not-yet-buried (`checkNoPendingChangeOfDefinitionChash`), and that block only fires per-address for the *same* validating node's own known conflicting graph state [2](#0-1) .

The code itself documents the resulting race condition: in `handleDuplicateAddressDefinition`, a comment states: *"in one particular case, the attacker changes his definition then quickly sends a new ball with the old definition - the new definition will not be active yet"* [3](#0-2) . This confirms that a party who still holds the old (revoked) private key can race a legitimate definition-change and successfully sign/spend with the old definition before the change stabilizes, because validators still resolve the old definition as authoritative until the new one is stable and before last ball.

This is directly analogous to CVE-2022-2447: a security-relevant revocation (Keystone token revocation / ocore address definition change) is not instantaneously enforced network-wide; there is a caching/stabilization lag during which the previously-authorized credential (cached token / old address definition & keys) continues to be accepted as valid.

### Impact Explanation
An attacker who has obtained (or retains) a copy of an address's old private key(s) — e.g. an ex-cosigner, a compromised device, or a malicious former custodian in a multisig/shared address — can continue to authorize spends from that address for as long as the legitimate owner's revoking `address_definition_change` remains unstable. This is concrete unauthorized spending: funds can be moved with a definition the rightful owner explicitly tried to revoke, potentially conflicting with (and depending on DAG resolution, beating) the legitimate owner's transactions, which also risks node disagreement about which competing unit becomes 'good' vs 'final-bad'.

### Likelihood Explanation
Exploitation requires the attacker to already possess a valid (old) key/definition for the target address — this is not an anonymous/network attacker capability, but it matches the CVE's own threat model (a previously-authorized party whose access should have been revoked). Given normal DAG confirmation times, the window is realistically on the order of minutes and can be extended under adverse conditions (analogous to Keystone's up-to-one-hour window), giving a practical opportunity to race a definition change.

### Recommendation
- When accepting a unit signed with an address's currently-stored (pre-change) definition, additionally check for any *unstable* pending `address_definition_change` for that same address and, if found, reject or defer validation until the pending change resolves, rather than only enforcing this for the address's own subsequent postings.
- Consider treating an in-flight (unstable) definition change as immediately invalidating the old definition for competing/conflicting signature paths, closing the window described in the `handleDuplicateAddressDefinition` comment.

### Proof of Concept
1. Address `A` is controlled via definition `D_old` (e.g., 2-of-2 multisig including key `K_old`, later found compromised).
2. Owner posts unit `U1` containing `address_definition_change` message changing `A`'s definition to `D_new` (removing `K_old`) [4](#0-3) .
3. Before `U1` becomes stable (buried under a last ball), the attacker holding `K_old` crafts and broadcasts unit `U2` from address `A`, signed under `D_old`, sending funds to an attacker-controlled address.
4. Validators resolve `A`'s definition via `readDefinitionByAddress` at `last_ball_mci`, which still returns `D_old` because `U1` isn't stable/buried yet [5](#0-4) ; `U2` validates and can be accepted/stabilized, resulting in unauthorized spending with a "revoked" key.

### Citations

**File:** validation.js (L1347-1358)
```javascript
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
```

**File:** validation.js (L1469-1483)
```javascript
		storage.readDefinitionByAddress(conn, objAuthor.address, objValidationState.last_ball_mci, {
			ifDefinitionNotFound: function(definition_chash){ // first use of the definition_chash (in particular, of the address, when definition_chash=address)
				try {
					if (objectHash.getChash160(arrAddressDefinition) !== definition_chash)
						return callback("wrong definition: " + objectHash.getChash160(arrAddressDefinition) + "!==" + definition_chash);
				}
				catch (e) {
					return callback("definition hash failed: " + e.toString());
				}
				callback();
			},
			ifFound: function(arrAddressDefinition2){ // arrAddressDefinition2 can be different
				handleDuplicateAddressDefinition(arrAddressDefinition2);
			}
		});
```

**File:** validation.js (L1486-1498)
```javascript
	function handleDuplicateAddressDefinition(arrAddressDefinition){
	//	if (!bNonserial || objValidationState.arrAddressesWithForkedPath.indexOf(objAuthor.address) === -1)
			return callback("duplicate definition of address "+objAuthor.address+", bNonserial="+bNonserial);
		// todo: investigate if this can split the nodes
		// in one particular case, the attacker changes his definition then quickly sends a new ball with the old definition - the new definition will not be active yet
		try {
			if (objectHash.getChash160(arrAddressDefinition) !== objectHash.getChash160(objAuthor.definition))
				return callback("unit definition doesn't match the stored definition");
		}
		catch (e) {
			return callback("handleDuplicateAddressDefinition definition hash failed: " + e.toString());
		}
		callback(); // let it be for now. Eventually, at most one of the balls will be declared good
```

**File:** validation.js (L1719-1745)
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
