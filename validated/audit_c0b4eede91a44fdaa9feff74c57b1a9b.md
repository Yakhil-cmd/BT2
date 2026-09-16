### Title
Co-signer can retroactively alter a shared address's spending conditions via `address` definition reference, permanently freezing or overriding co-owners' funds - (File: definition.js)

### Summary
When an Obyte address definition embeds an `['address', 'OTHER_ADDRESS']` reference to another address (a common pattern for building shared/multisig addresses composed of independently-owned sub-addresses), the referenced address's definition is not fixed at composition time. It is dynamically re-fetched at validation time using `storage.readDefinitionByAddress`, keyed only on `last_ball_mci`. This means the owner of the referenced address can unilaterally submit an ordinary `address_definition_change` message at any time and change the effective spending rules of every composite address that references them, with no consent, cooldown, or notice to the other co-owners.

### Finding Description
In `definition.js`, the `'address'` opcode is evaluated as: [1](#0-0) 

```
case 'address':
    ...
    var other_address = args;
    storage.readDefinitionByAddress(conn, other_address, objValidationState.last_ball_mci, {
        ifFound: function(arrInnerAddressDefinition){
            needToEvaluateNestedAddress(path) ? evaluate(arrInnerAddressDefinition, path, bInNegation, cb) : cb(null, true);
        },
        ...
```

`storage.readDefinitionByAddress` in turn calls `readDefinitionChashByAddress`, which looks up the **most recent stable** `address_definition_changes` row for that address as of `max_mci`: [2](#0-1) 

There is no mechanism that pins the nested address's definition to the value it had when the composite (outer) address was created/agreed upon. Any address owner who is referenced via `['address', X]` inside someone else's (or a shared) definition can later post a normal, unprivileged `address_definition_change` message (validated generically in `validation.js`, `writer.js` — see `address_definition_change` handling at `validation.js:1719-1745` and `writer.js:186-192`) to swap their definition for an arbitrary new one (e.g. `['sig', {pubkey: attacker_key}]` or a definition with a huge age/timestamp lock such as `['and', [['sig', ...], ['age', ['>=', 1e15]]]]`). Because the outer/composite definition dereferences the *current* definition of the inner address at validation time, this single, ordinary transaction from an unprivileged co-signer retroactively rewrites the spending/authorization conditions of every unit that has ever been secured by, or every fund locked into, the composite address — without the consent of the other parties who built or funded that shared address.

This mirrors the UMA `Staker.setUnstakeCoolDown` class of bug precisely: a party who is trusted only as one component of a shared arrangement can, through a fully permitted, unprivileged action on their own account, retroactively change the terms that govern funds/authorization that other parties reasonably expected to remain fixed, up to and including making those funds permanently unspendable (e.g. by referencing an `age`/`timestamp` condition set arbitrarily far in the future) or permanently redirecting authorization to themselves.

### Impact Explanation
- Funds sent to, or authorization granted through, a shared address that nests an `['address', X]` reference can be frozen indefinitely if the referenced address owner redefines their address to an unsatisfiable or extremely restrictive condition (e.g., `['age', ['>=', huge_number]]`), directly matching the "stake withheld indefinitely" impact class (AA fund loss / freezing, unauthorized spending).
- Alternatively, the referenced owner could redefine to a condition that grants themselves unilateral spending rights over the composite address, enabling unauthorized/unexpected fund movement that other co-owners never agreed to when the shared address was established.
- This affects any oscript/AA or wallet-composed address that relies on `['address', ...]` referencing another party's address as a component of authorization logic — a documented, intentional feature of Obyte's definition language, but one whose trust boundary (mutable-by-reference, non-snapshotted) is not obvious to composers of multisig/shared arrangements and directly causes fund freezing/loss for the non-controlling party.

### Likelihood Explanation
- No privileged role is required. Any address owner can send a standard `address_definition_change` for their own address at any time; this is core, always-available functionality, not an admin/governance-only action.
- The only precondition is that some other party's spending/authorization logic references the attacker's address via `['address', ...]`. This is a supported and encouraged composition pattern (see `wallet_defined_by_addresses.js`), so it is realistically used for shared/multisig wallets.
- No fork, race, or double-spend detection currently rejects or restricts a change of an address referenced elsewhere; `checkNoPendingChangeOfDefinitionChash` in `validation.js` only prevents an address from sending further messages while its own keychange is pending — it does not protect addresses that merely *reference* the changed address.

### Recommendation
- When composing definitions with `['address', X]`, snapshot/pin the chash of the referenced address's definition at the time the outer/composite address (or the deposit into it) was created, and validate the referenced address against that pinned chash rather than the "current" definition at `last_ball_mci`.
- Alternatively, require an explicit cooldown or a two-phase commit for `address_definition_change` when the address is known to be referenced by other live/funded definitions, so that funds already secured under the old definition cannot be retroactively subjected to the new one without an opportunity to exit.
- At minimum, document and surface this trust dependency clearly to composers of shared addresses/AA authors, and consider adding an opt-in "definition template" style mechanism that lets composers require the referenced definition to remain byte-for-byte identical, bouncing/rejecting evaluation if it has changed since a recorded baseline.

### Proof of Concept
1. Alice and Bob agree to create a 2-of-2-style shared address whose definition is `['and', [['sig', {pubkey: alice_pubkey}], ['address', bob_address]]]` (Alice's own signature plus Bob's address's current definition, e.g. `['sig', {pubkey: bob_pubkey}]`).
2. Funds are deposited into this shared address by Alice, Bob, or a third party, under the expectation that spending requires Alice's signature plus Bob's original signing key.
3. Bob later posts an ordinary `address_definition_change` message for `bob_address` (a normal unprivileged transaction), changing its definition to `['and', [['sig', {pubkey: new_bob_pubkey}], ['age', ['>=', 999999999]]]]` or simply to a definition that can never be satisfied.
4. On the next spend attempt from the shared address, `definition.js`'s `'address'` opcode re-resolves `bob_address`'s definition via `storage.readDefinitionByAddress` using the current `last_ball_mci`, picks up Bob's new definition, and evaluates against it — either permanently freezing the shared address's funds (unsatisfiable condition) or granting spending rights exclusively to Bob's `new_bob_pubkey` without Alice's foreknowledge or consent, all via a single standard, unprivileged `address_definition_change` unit that Bob alone authors.

### Citations

**File:** definition.js (L269-283)
```javascript
			case 'address':
				if (objValidationState.bNoReferences)
					return cb("no references allowed in address definition");
				if (bInNegation)
					return cb(op+" cannot be negated");
				if (bAssetCondition)
					return cb("asset condition cannot have "+op);
				var other_address = args;
				if (!isValidAddress(other_address))
					return cb("invalid address");
				storage.readDefinitionByAddress(conn, other_address, objValidationState.last_ball_mci, {
					ifFound: function(arrInnerAddressDefinition){
						console.log("inner address:", arrInnerAddressDefinition);
						needToEvaluateNestedAddress(path) ? evaluate(arrInnerAddressDefinition, path, bInNegation, cb) : cb(null, true);
					},
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
