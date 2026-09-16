### Title
Unhandled synchronous exception in `checkForDoublespends` crashes full nodes on a crafted spend-proof unit - (File: validation.js)

### Summary
`validation.js`'s `checkForDoublespends()` (used to validate `spend_proofs` fields of private/none-payload payment messages) contains an assumption that any conflicting `spend_proofs` row it finds must belong to one of the current unit's author addresses. An attacker who fully controls the `address` field of a `spend_proofs` entry (which is *not* required to equal an existing spend proof's owner) can make this assumption false and trigger an unhandled synchronous `throw Error(...)` deep inside a DB-callback chain, crashing the Node.js process of every full node that validates the unit — analogous to CVE-2016-3615's remote-authenticated-user DML-driven availability impact.

### Finding Description
`validateMessage()` allows a payment message with `payload_location: "none"` plus a `spend_proofs` array (used for private-asset payments). Fields are validated in `validateMessage` at [1](#0-0) , but the check only verifies:
- `spend_proof` is valid base64
- `address` (when multi-authored) is one of the *current* unit's authors

It does **not** constrain what value the attacker picks for `spend_proof` — the attacker chooses an arbitrary 44-byte base64 string as their "spend proof" together with any of their own author addresses.

Later, `validateSpendProofs()` inside `validateMessage` builds a lookup query that matches *any previously stored* `spend_proofs` row with the same `spend_proof` value and an `address` equal either to the field's own `address` or (if omitted) the first author of the *conflicting* row's own unit — not filtered to the current unit's authors: [2](#0-1) 

This query result is passed into `checkForDoublespends()`: [3](#0-2) 

The function then does:
```
if (arrAuthorAddresses.indexOf(objConflictingRecord.address) === -1)
    throw Error("conflicting "+type+" spent from another address?");
```
`arrAuthorAddresses` is the list of authors of the *newly submitted* unit. `objConflictingRecord.address` is the address stored on the *previously accepted* unit's spend-proof row. The code assumes that whenever the same `spend_proof` string appears twice, it must have been produced by the same owner/author — but since `spend_proof` is a free-form base64 string chosen by whoever posts the unit (it is only cryptographically meaningful in the *indivisible/divisible asset* modules that compute it from actual output hashes; the raw `validateMessage` path does not recompute or verify it against any output), an attacker can deliberately reuse an arbitrary `spend_proof` value from an earlier post while presenting a **different address in the new unit** that is one of their own authors but not equal to the stored address. This makes the guarded invariant false and reaches the `throw Error(...)` statement.

Because this throw happens synchronously inside a `conn.query()` callback (itself buried inside `mutex.lock()` → `async.series()` → DB driver callback chains in `network.js`'s `handleJoint()`/`validation.js`'s `validate()`), there is no enclosing `try/catch` or Node `domain`/`process.on('uncaughtException')` guard around it. An uncaught exception thrown inside an async callback crashes the entire Node.js process (Node's default behavior), not just the request.

### Impact Explanation
A single unprivileged unit poster can craft two units — first, one with a `spend_proofs` entry using an arbitrary value V and their own address A; then a second, unrelated unit (potentially posted by the same or a colluding author, or even the same address reused later with a slightly different scenario) whose `spend_proofs` entry reuses V — driving execution into the `throw Error("conflicting spend proof spent from another address?")` branch. Every full node (and any AA/composer instance) that validates that second unit crashes with an unhandled exception, taking the node process down. Because unit validation/relay is unauthenticated peer-to-peer processing of untrusted, attacker-controlled content, this is remotely triggerable against every full node in the network that receives the malicious unit, directly matching "a network unable to confirm new units" (nodes must restart, losing sync, potentially crash-looping if the poisoned unit is retransmitted / already stored as unhandled).

### Likelihood Explanation
Medium-High: the attacker needs no special privilege, only the ability to compose and broadcast two ordinary units with attacker-chosen `spend_proofs.spend_proof` values (this field is not independently checked against actual output/asset data for `payload_location: "none"` messages before reaching `checkForDoublespends`). This is fully achievable by any unprivileged unit poster.

### Recommendation
Replace the `throw Error(...)` in `checkForDoublespends()` (validation.js:1673 and the sibling `throw Error("unreachable code...")`/`throw Error("double spending ... without double spending address?")` at lines 1688/1692) with a normal `cb2(err)` unit-validation-error path (i.e., reject the unit as invalid rather than crashing the process), and additionally cross-validate that reused `spend_proof` values are cryptographically bound to the claimed address/asset/output before comparing them across units.

### Proof of Concept
1. Attacker author X posts unit U1 containing a payment message with `payload_location: "none"` and `spend_proofs: [{spend_proof: "<44-byte-b64-string-V>"}]` (single-authored, so `address` is implicit = X). This gets accepted and stored in `spend_proofs` table with `address = X`.
2. The same or another address Y (different key, but the attacker can just wait/craft any scenario producing a *stored* spend_proofs row whose address does not equal any author of a later unit) later posts unit U2, single- or multi-authored by some other address set not including X, again with a `spend_proofs` entry reusing the same value V.
3. During validation of U2, `validateSpendProofs()` finds the row from U1 (`address = X`) as a "conflict" because `spend_proof` matches. `checkForDoublespends()` then checks `arrAuthorAddresses.indexOf('X') === -1` (true, since U2's authors don't include X) and executes `throw Error("conflicting spend proof spent from another address?")`, crashing the validating node's process.

Note: I was not able to fully trace, within the available indexing/tool budget, every possible caller-side guard (e.g., whether `network.js`'s outer promise/callback wrapping could intercept this specific synchronous throw in some deployment configurations); a Devin session with full repository access and a running test harness would be needed to confirm the exact crash behavior end-to-end and to check whether any higher-level `process.on('uncaughtException')` handler exists elsewhere in the codebase that might turn this into a caught error rather than a full crash.

### Citations

**File:** validation.js (L1539-1585)
```javascript
	if ("spend_proofs" in objMessage){
		if (objValidationState.bAA)
			return callback("spend proofs in AA");
		if (objMessage.app !== "payment")
			return callback("spend proofs in non-payment message");
		if (objMessage.payload_location !== "none")
			return callback("spend proofs in message with payload");
		if (!Array.isArray(objMessage.spend_proofs) || objMessage.spend_proofs.length === 0 || objMessage.spend_proofs.length > constants.MAX_SPEND_PROOFS_PER_MESSAGE)
			return callback("spend_proofs must be non-empty array max "+constants.MAX_SPEND_PROOFS_PER_MESSAGE+" elements");
		var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
		// spend proofs are sorted in the same order as their corresponding inputs
		//var prev_spend_proof = "";
		for (var i=0; i<objMessage.spend_proofs.length; i++){
			var objSpendProof = objMessage.spend_proofs[i];
			if (typeof objSpendProof !== "object")
				return callback("spend_proof must be object");
			if (hasFieldsExcept(objSpendProof, ["spend_proof", "address"]))
				return callback("unknown fields in spend_proof");
			//if (objSpendProof.spend_proof <= prev_spend_proof)
			//    return callback("spend_proofs not sorted");
			
			if (!isValidBase64(objSpendProof.spend_proof, constants.HASH_LENGTH))
				return callback("spend proof " + JSON.stringify(objSpendProof.spend_proof) + " is not a valid base64");
			
			var address = null;
			if (arrAuthorAddresses.length === 1){
				if ("address" in objSpendProof)
					return callback("when single-authored, must not put address in spend proof");
				address = arrAuthorAddresses[0];
			}
			else{
				if (typeof objSpendProof.address !== "string")
					return callback("when multi-authored, must put address in spend_proofs");
				if (arrAuthorAddresses.indexOf(objSpendProof.address) === -1)
					return callback("spend proof address "+objSpendProof.address+" is not an author");
				address = objSpendProof.address;
			}
			
			if (objValidationState.arrInputKeys.indexOf(objSpendProof.spend_proof) >= 0)
				return callback("spend proof "+objSpendProof.spend_proof+" already used");
			objValidationState.arrInputKeys.push(objSpendProof.spend_proof);
			
			//prev_spend_proof = objSpendProof.spend_proof;
		}
		if (objMessage.payload_location === "inline")
			return callback("you don't need spend proofs when you have inline payload");
	}
```

**File:** validation.js (L1643-1655)
```javascript
	function validateSpendProofs(cb){
		if (!("spend_proofs" in objMessage))
			return cb();
		var arrEqs = objMessage.spend_proofs.map(function(objSpendProof){
			return "spend_proof="+conn.escape(objSpendProof.spend_proof)+
				" AND address="+conn.escape(objSpendProof.address ? objSpendProof.address : objUnit.authors[0].address);
		});
		var doubleSpendIndexMySQL = conf.storage == "mysql" ? "USE INDEX(bySpendProof)" : "";
		checkForDoublespends(conn, "spend proof", 
			"SELECT address, unit, main_chain_index, sequence FROM spend_proofs "+ doubleSpendIndexMySQL+" JOIN units USING(unit) WHERE unit != ? AND sequence!='final-bad' AND ("+arrEqs.join(" OR ")+")",
			[objUnit.unit], 
			objUnit, objValidationState, function(cb2){ cb2(); }, cb);
	}
```

**File:** validation.js (L1661-1673)
```javascript
function checkForDoublespends(conn, type, sql, arrSqlArgs, objUnit, objValidationState, onAcceptedDoublespends, cb){
	conn.query(
		sql, 
		arrSqlArgs,
		function(rows){
			if (rows.length === 0)
				return cb();
			var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
			async.eachSeries(
				rows,
				function(objConflictingRecord, cb2){
					if (arrAuthorAddresses.indexOf(objConflictingRecord.address) === -1)
						throw Error("conflicting "+type+" spent from another address?");
```
