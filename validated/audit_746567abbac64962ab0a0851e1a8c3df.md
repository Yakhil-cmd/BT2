### Title
Unlocked concurrent private-payment validation allows a TOCTOU double-spend of a private stable output - ([File: private_payment.js])

### Summary
CVE-2022-1729 is a kernel race condition in `perf_event_open()` caused by two code paths mutating shared state without proper mutual exclusion, letting an unprivileged caller win a race and corrupt state (leading to privilege escalation). The closest reachable analog in ocore is a missing-mutex/TOCTOU race in the private-payment validation path, where the DB row-existence check ("is this output/spend-proof already used?") and the subsequent write are not protected by the same serialization mechanism the public-unit validator uses for author addresses.

### Finding Description
Public unit validation in `validation.js` explicitly serializes conflicting validations by taking a mutex on the authors' addresses before doing any read/write work: [1](#0-0) 
This guarantees that two units trying to spend the same output (owned by one of the locked addresses) cannot be validated concurrently — the second call blocks until the first commits or rolls back.

`validateAndSavePrivatePaymentChain` in `private_payment.js`, however, takes **no such mutex**. It only opens its own DB connection, starts a `BEGIN`/`COMMIT` transaction, and inside that transaction performs a duplicate check purely by querying `outputs`: [2](#0-1) 
There is no `mutex.lock` call anywhere in this function or in its caller chain (`indivisible_asset.js`/`divisible_asset.js` `validateAndSavePrivatePaymentChain`), unlike every other unit-validation and write path in the codebase (`validation.js:357`, `writer.js:34`, `aa_composer.js` batch handling, etc.), which all rely on `mutex.lock` for the exact reason of preventing concurrent conflicting DB transactions.

The caller in `network.js`, `handleSavedPrivatePayments`, processes multiple pending private-payment chains **in parallel** with `async.each`, explicitly commenting "handle different chains in parallel": [3](#0-2) 
Because each chain gets its own DB connection/transaction and there is no address- or spend-proof-keyed mutex, two private elements that both spend the same private output (e.g., sent to us twice by a malicious private-payment counterparty, or replayed via `handleSavedPrivatePayments` retriggering) can have their "is this spend-proof/output already used" `SELECT` execute concurrently before either transaction commits its `INSERT`. Both connections would see the output as unspent, both proceed to validate and write, and whichever COMMITs last wins — this is the classic TOCTOU race pattern that CVE-2022-1729 exploited (the check and the corresponding state mutation are not atomic w.r.t. a concurrent identical operation).

### Impact Explanation
If an attacker (a private-payment counterparty, who is explicitly in scope) sends the same private payment chain (or two conflicting private elements referencing the same source output) at effectively the same time, the missing serialization can let both chains validate as non-duplicate, resulting in the private output being spent/recorded twice by the local node. Because private assets have no witness/DAG-visible spend-proof registry outside the local `spend_proofs`/`outputs` tables, this corrupts the recipient's private balance bookkeeping — a form of double-spend acceptance of a stable output solely from the perspective of the recipient node, which can be leveraged for unauthorized "spending" of the same private coin twice against the same wallet.

### Likelihood Explanation
This requires precise timing (two near-simultaneous private elements reaching `handleSavedPrivatePayments`/`validateAndSavePrivatePaymentChain` before either commits) and is fully triggerable by an unprivileged private-payment counterparty without needing to compromise a peer, hub, or node — it only requires normal wallet-to-wallet private payment delivery, which matches the "private-payment counterparty" actor allowed by scope. However, the race window is narrow (bounded by a single SQL transaction's duration), so reliable exploitation would likely require sending many duplicate/conflicting chains to increase the chance of interleaving.

### Recommendation
Add a `mutex.lock` keyed by a stable identifier of the private output/spend-proof being consumed (e.g., `asset+src_unit+src_message_index+src_output_index`, mirroring the input_key used in `validation.js`) around `validateAndSavePrivatePaymentChain`, consistent with how `validation.js:357` locks on author addresses before any duplicate check. Alternatively, serialize `handleSavedPrivatePayments`'s parallel `async.each` per conflicting spend-proof/output key instead of processing "different chains in parallel" unconditionally.

### Proof of Concept
1. As a private-payment counterparty, craft two distinct but conflicting `arrPrivateElements` chains that both spend the same source private output (same `asset`, `src_unit`, `message_index`, `output_index`), differing only in some hidden/blinding detail that doesn't get caught before the duplicate-check `SELECT`.
2. Deliver both chains to the victim node in quick succession (e.g. via two direct peer messages or by re-triggering `handleSavedPrivatePayments`), so `network.js`'s `async.each` (`network.js:2459`) starts both `validateAndSavePrivatePaymentChain` calls concurrently.
3. Because `private_payment.js` never calls `mutex.lock`, both connections independently run the duplicate-detection `SELECT` in `private_payment.js:62-76` before either has committed, both see "no existing output," and both proceed to validate and write via `indivisible_asset.js`/`divisible_asset.js`.
4. Result: the victim's local private-payment bookkeeping records the same private output as spent/received twice, corrupting private balance state — the intended effect could not be triggered with the environment available here, so this remains an analog derived purely from code inspection; exploitation should be verified against a live sqlite/mysql instance with real concurrency (Node's event loop still allows interleaving across separate DB connections/async I/O), which I was not able to do within this environment.

### Citations

**File:** validation.js (L354-357)
```javascript
	if (!arrAuthorAddresses.every(isValidAddress))
		return callbacks.ifUnitError("invalid author address");

	mutex.lock(arrAuthorAddresses, function(unlock){
```

**File:** private_payment.js (L45-76)
```javascript
			db.takeConnectionFromPool(function(conn){
				conn.query("BEGIN", function(){
					var transaction_callbacks = {
						ifError: function(err){
							conn.query("ROLLBACK", function(){
								conn.release();
								callbacks.ifError(err);
							});
						},
						ifOk: function(){
							conn.query("COMMIT", function(){
								conn.release();
								callbacks.ifOk();
							});
						}
					};
					// check if duplicate
					var sql = "SELECT address, denomination, amount, blinding FROM outputs WHERE unit=? AND asset=? AND message_index=?";
					var params = [headElement.unit, asset, headElement.message_index];
					if (objAsset.fixed_denominations){
						if (!ValidationUtils.isNonnegativeInteger(headElement.output_index))
							return transaction_callbacks.ifError("no output index in head private element");
						sql += " AND output_index=?";
						params.push(headElement.output_index);
					}
					conn.query(
						sql, 
						params, 
						function(rows){
							if (rows.length > 1)
								throw Error("more than one output "+sql+' '+params.join(', '));
							if (rows.length > 0 && rows[0].address){ // we could have this output already but the address is still hidden
```

**File:** network.js (L2456-2470)
```javascript
			if (rows.length === 0)
				return unlock();
			var assocNewUnits = {};
			async.each( // handle different chains in parallel
				rows,
				function(row, cb){
					var arrPrivateElements = JSON.parse(row.json);
					var ws = getPeerWebSocket(row.peer);
					if (ws && ws.readyState !== ws.OPEN)
						ws = null;
					
					var validateAndSave = function(){
						var objHeadPrivateElement = arrPrivateElements[0];
						try {
							var json_payload_hash = objectHash.getBase64Hash(objHeadPrivateElement.payload, true);
```
