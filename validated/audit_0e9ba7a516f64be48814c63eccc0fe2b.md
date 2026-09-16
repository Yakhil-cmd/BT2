### Title
Unrestricted `'any'` wildcard in `has/seen definition change` lets a single address owner unilaterally invalidate agreed spending conditions in shared/smart-contract addresses - (File: definition.js)

### Summary
Ocore addresses are, like a `SetToken`'s module set, defined by a mutable "definition" (spending-condition script) that can be swapped out post-deployment via an `address_definition_change` message, without any grace period for counterparties to react. Multi-party contracts (shared addresses, arbiter/prosaic contracts) commonly rely on the `'has definition change'` / `'seen definition change'` oscript operators to gate spending rights on "the co-signer changed their definition." Because these operators accept a `'any'` wildcard for the new definition hash, a contract clause can be satisfied by *any* replacement definition, regardless of its content — mirroring the SetToken issue where a manager can remove and re-add a module with different (unagreed) parameters and there is no delay for the counterparty to opt out.

### Finding Description
An oscript address definition can reference `['has definition change', [address, new_definition_chash]]` or `['seen definition change', [address, new_definition_chash]]` to make a spending branch conditional on some other party's definition having changed. Validation of these operators is in [1](#0-0) , and the operator's runtime evaluation (matching against `address_definition_changes`) is in [2](#0-1) .

Critically, `new_definition_chash` can be the literal `'any'`, which is accepted once `anyDefinitionChangeUpgradeMci` is reached, and this simply drops the `definition_chash=?` filter from the underlying SQL query: [3](#0-2) . This means the clause is satisfied merely because *a* definition change occurred for the referenced address — the actual new spending rules are never inspected or constrained by the contract.

The definition change itself is a first-class, unrestricted operation: any address owner can post an `address_definition_change` message (validated at [4](#0-3) ) as long as they satisfy their *current* definition, and the change is recorded verbatim and takes effect once stable, with no cool-down or veto window for other parties relying on the address's prior rules: [5](#0-4) , [6](#0-5) .

This is structurally identical to the SetToken finding: a party who legitimately controls a "module"-like extensible component (the address definition) can replace it with a self-serving version, and any co-signed contract that trusts "a change happened" (rather than validating what the change was) inherits whatever new, possibly hostile, rules the changer chose — with no time delay for the counterparty to exit or object.

### Impact Explanation
In a shared/multisig or arbiter-style contract address that uses `'has definition change'`/`'seen definition change'` with `'any'` as an unlock condition (e.g., "party A can act alone once they signal by changing their own definition"), party A can craft a self-authored definition change and then immediately claim funds or override co-signature/timelock/oracle requirements that the counterparty believed were still binding, because the contract clause cannot distinguish an agreed key-rotation from an adversarial removal of previously agreed constraints. This can result in unauthorized spending of shared funds or bypass of oracle/timelock/attestation conditions that the other party relied on — a concrete fund-loss/unauthorized-spending outcome for a private-payment/shared-address counterparty.

### Likelihood Explanation
Exploitation requires that a real-world contract composed with `'has definition change'`/`'seen definition change'` uses the `'any'` wildcard (rather than pinning an exact expected `new_definition_chash`), which is a design/usage risk rather than a universal one — I could not find a concrete production usage of the `'any'` wildcard in the wiki-provided contract templates (`arbiter_contract.js`, ICO sample) during this analysis, so likelihood depends on external/user-authored contract templates that adopt this pattern. Given the primitive is exposed and explicitly supported since `anyDefinitionChangeUpgradeMci`, and definition changes are single-party operations requiring no counterparty consent, the risk is real wherever `'any'` is used, but I was unable to confirm it is used in any shipped, widely-deployed contract template within the indexed code.

### Recommendation
- Discourage/deprecate the `'any'` wildcard for `new_definition_chash` in `'has definition change'`/`'seen definition change'`, or require contract authors to pin an exact expected chash so the clause only fires for a mutually pre-agreed replacement definition.
- Consider requiring a stability/time delay between when an `address_definition_change` is posted and when it can be relied upon by a *different* signer's spending branch, so co-signers have a window to react to hostile definition swaps.
- Add tooling/lint warnings in contract composition helpers (`arbiter_contract.js`, wallet contract builders) flagging use of `'any'` in definition-change conditions as high risk.

### Proof of Concept
Conceptual (oscript), not executed:
1. Two parties, A and B, jointly control shared address S via a definition containing a branch: `['and', [['sig', {pubkey: B}], ['has definition change', ['this address', 'any']]]]` intended to let A recover funds if B "signals" recovery by rotating their own key.
2. A, who is also a legitimate co-signer of S under the *current* definition, posts an `address_definition_change` for their own address to a definition that still satisfies the branch's syntactic requirement, then constructs a spending unit exploiting the `'has definition change' → 'any'` clause to bypass the intended timelock/oracle gate that B assumed was still enforced, since the SQL check in `evaluate` (`definition.js:843-852`) only checks that *some* change occurred, not what it changed to.
3. Because `address_definition_change` requires only satisfying the *current* definition (`validation.js:1719-1745`) and is applied without a cooling-off period (`writer.js:186-192`, `storage.js:754-768`), A can execute step 2 unilaterally and before B can react. [1](#0-0) [2](#0-1) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** definition.js (L352-368)
```javascript
			case 'seen definition change':
			case 'has definition change':
				if (objValidationState.bNoReferences)
					return cb("no references allowed in address definition");
				if (!isArrayOfLength(args, 2))
					return cb(op+" must have 2 args");
				var changed_address = args[0];
				var new_definition_chash = args[1];
				if (bAssetCondition && (changed_address === 'this address' || new_definition_chash === 'this address' || changed_address === 'other address' || new_definition_chash === 'other address'))
					return cb("asset condition cannot reference this/other address in "+op);
				if (!isValidAddress(changed_address) && changed_address !== 'this address') // it is ok if the address was never used yet
					return cb("invalid changed address");
				if (!isValidAddress(new_definition_chash) && new_definition_chash !== 'this address' && new_definition_chash !== 'any')
					return cb("invalid new definition chash");
				if (new_definition_chash === 'any' && objValidationState.last_ball_mci < constants.anyDefinitionChangeUpgradeMci)
					return cb("too early use of 'any' in new_definition_chash");
				return cb();
```

**File:** definition.js (L835-853)
```javascript
			case 'seen definition change':
				// ['seen definition change', ['BASE32', 'BASE32']]
				var changed_address = args[0];
				var new_definition_chash = args[1];
				if (changed_address === 'this address')
					changed_address = address;
				if (new_definition_chash === 'this address')
					new_definition_chash = address;
				var and_definition_chash = (new_definition_chash === 'any') ? '' : 'AND definition_chash='+db.escape(new_definition_chash);
				conn.query(
					"SELECT 1 FROM address_definition_changes CROSS JOIN units USING(unit) \n\
					WHERE address=? "+and_definition_chash+" AND main_chain_index<=? AND sequence='good' AND is_stable=1 \n\
					LIMIT 1",
					[changed_address, objValidationState.last_ball_mci],
					function(rows){
						cb2(rows.length > 0);
					}
				);
				break;
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

**File:** writer.js (L186-192)
```javascript
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
