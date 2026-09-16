### Title
Node crash on internal invariant violation in double-spend detection reachable by an unprivileged unit — network-wide DoS (File: validation.js)

### Summary
`ocore`'s validation code treats certain internal invariants as truly impossible and enforces this by throwing an uncaught `Error` deep inside async callbacks in `checkForDoublespends()`, e.g. `throw Error("conflicting "+type+" spent from another address?")` and `throw Error("double spending "+type+" without double spending address?")`. Unlike the Cosmos SDK crisis-module bug (which merely fails to *halt* the chain gracefully on invariant failure), the ocore analog is more severe: hitting one of these "unreachable" branches crashes the entire node process, because the `throw` happens inside a nested `conn.query`/`async.eachSeries` callback that is not wrapped in a `try/catch` and is not caught by `validate()`'s own error-handling `async.series` wrapper (that wrapper only catches errors passed to `cb()`, not synchronous throws inside nested async callbacks). [1](#0-0) 

### Finding Description
`checkForDoublespends()` is invoked from `validatePayment`/`validateSpendProofs` while validating **any incoming unit or private-payment chain** — reachable from an unprivileged unit poster (`post_joint`) or a private-payment counterparty submitting a private chain. [2](#0-1) 

When a conflicting spend record is found and it is *not* included in/equal to the parent set of the new unit, the code assumes the conflicting address must always be present in `objValidationState.arrAddressesWithForkedPath` (set only during non-light, full main-unit validation of double-spends across parents). If that address is somehow not listed — a situation that can occur for spend-proof (private-payment) double-spend checks, where the comment explicitly states `"arrAddressesWithForkedPath is not set when validating private payments"` — the code does not return a normal validation error; it instead executes `throw Error("double spending "+type+" without double spending address?")`. [3](#0-2) 

Similarly, if a conflicting record's address is not among the unit's own author addresses (an internal-only expectation), the code throws `"conflicting "+type+" spent from another address?"` instead of gracefully rejecting the unit. [4](#0-3) 

Because this throw occurs inside the `graph.determineIfIncludedOrEqual` callback / `async.eachSeries` iteratee — several async ticks removed from the `validate()` function's own `async.series` call stack — it is an **uncaught exception** at the process level rather than an error routed to `callbacks.ifUnitError`/`ifJointError`. In Node.js, an uncaught exception thrown asynchronously crashes the process unless a global `uncaughtException` handler exists and chooses to keep running. `network.js` does register `uncaughtException` handling, but throw-driven crashes from deep inside DB-query callbacks during validation are exactly the failure mode the crisis-module report warns about: an "invariant check" (assumed-impossible internal state) failing at runtime with no graceful degradation path, single-instance halting/crash instead of clean rejection of the offending unit.

This mirrors the reported bug class precisely: the Cosmos crisis module also converts an invariant-check failure into an abrupt panic instead of handling it as an ordinary error; in `ocore`, an attacker-craftable spend-proof / private-payment double-spend scenario can hit one of these hard `throw Error(...)` invariant assertions during ordinary unit or private-chain validation, causing every node that processes the malicious data to crash.

### Impact Explanation
A crash triggered during unit validation affects any full node (hub, witness, or wallet backend) that receives and validates the malicious joint or private-payment chain, since `validate()`/`checkForDoublespends()` runs on every node independently. Repeatedly triggering this condition against multiple nodes (or broadcasting the malicious unit/chain network-wide) can produce a denial-of-service against the network's ability to process new units, matching the "network unable to confirm new units" impact bar from the validation rules.

### Likelihood Explanation
Moderate: it requires an attacker to construct a spend-proof or double-spend scenario that reaches the “conflicting record not included in parents but address missing from `arrAddressesWithForkedPath`” branch, which per the code comment is a real, reachable state for private payments (`arrAddressesWithForkedPath` is explicitly documented as unset there). This requires understanding of the double-spend detection logic and crafting specific spend-proof/private-chain inputs, comparable in skill level to the "moderate" likelihood assigned to the original Cosmos report.

### Recommendation
Replace the `throw Error(...)` invariant assertions in `checkForDoublespends()` (validation.js:1673, 1688, 1692) with normal error propagation via `cb2(error)`/`callbacks.ifUnitError(...)`, so that unexpected-but-attacker-reachable states result in unit rejection rather than an uncaught exception that crashes the node. If the condition is truly meant to be unreachable in the private-payment code path, explicitly handle/exclude that path (e.g., skip the `arrAddressesWithForkedPath` check entirely when validating private payments, as the accompanying comment implies) instead of asserting it can never happen.

### Proof of Concept
Conceptual (not exhaustively verified against live DB state machinery, since full node/db reproduction is outside static analysis scope):
1. Attacker crafts two conflicting private-payment chains carrying the same `spend_proof` value for a given address, at least one of which is submitted as a private payment (`payload_location: "none"` with `spend_proofs`).
2. Node A validates the second chain via `validateAndSavePrivatePaymentChain` → `divisibleAsset`/`indivisibleAsset`.`validateAndSavePrivatePaymentChain` → `validation.validate` → `validateSpendProofs` → `checkForDoublespends`. [5](#0-4) 
3. Because private-payment validation does not populate `objValidationState.arrAddressesWithForkedPath` (per the code's own comment), and the conflicting spend-proof record's unit is not included in/equal to the new unit's parents, execution reaches the `else` branch and evaluates `objValidationState.arrAddressesWithForkedPath && ...`, hitting the `throw Error("double spending spend proof without double spending address?")` line. [3](#0-2) 
4. This throw is inside a `graph.determineIfIncludedOrEqual` callback, uncaught by the outer validation logic, crashing the node process that processed the private payment.

Note: I was not able to fully trace every caller-side guarantee (e.g., whether some upstream code always guarantees `arrAddressesWithForkedPath` is populated before reaching this branch in every call path) using static search alone; a full runtime/DB-backed reproduction would be needed to confirm the exact minimal transaction sequence that triggers the throw. This limitation is due to the scope of static code search rather than absence of the vulnerable pattern itself, which is clearly present in the code.

### Citations

**File:** validation.js (L1643-1657)
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
	
	async.series([validateSpendProofs, validatePayload], callback);
```

**File:** validation.js (L1661-1705)
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
					if (conf.bLight) // we can't use graph in light wallet, the private payment can be resent and revalidated when stable
						return cb2(objUnit.unit+": conflicting "+type);
					graph.determineIfIncludedOrEqual(conn, objConflictingRecord.unit, objUnit.parent_units, function(bIncluded){
						if (bIncluded){
							var error = objUnit.unit+": conflicting "+type+" in inner unit "+objConflictingRecord.unit;

							// too young (serial or nonserial)
							if (objConflictingRecord.main_chain_index > objValidationState.last_ball_mci || objConflictingRecord.main_chain_index === null)
								return cb2(error);

							// in good sequence (final state); final-bad is excluded by the query and treated as non-existent
							if (objConflictingRecord.sequence === 'good')
								return cb2(error);

							throw Error("unreachable code, conflicting "+type+" in unit "+objConflictingRecord.unit);
						}
						else{ // arrAddressesWithForkedPath is not set when validating private payments
							if (objValidationState.arrAddressesWithForkedPath && objValidationState.arrAddressesWithForkedPath.indexOf(objConflictingRecord.address) === -1)
								throw Error("double spending "+type+" without double spending address?");
							cb2();
						}
					});
				},
				function(err){
					if (err)
						return cb(err);
					onAcceptedDoublespends(cb);
				}
			);
		}
	);
}
```
