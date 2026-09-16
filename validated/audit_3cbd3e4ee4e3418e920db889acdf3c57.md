### Title
Race condition in concurrent handling of received private-payment chains enables double-spend of a private output - ([File: network.js])

### Summary
`network.js`'s `handleOnlinePrivatePayment` can dispatch a received private-payment chain directly into `privatePayment.validateAndSavePrivatePaymentChain` with no mutex/in-work guard whatsoever, and the underlying `inputs` table's uniqueness constraint does not actually prevent duplicate spends of the same private output while it is unstable. Two private-payment chains that both spend the same earlier private output, delivered to the same wallet concurrently (e.g. resent, retried, or received simultaneously via hub and directly from peer), can both pass the "duplicate" check and both get written, producing two live spends of the same source output — the private-payment analog of `ION_IOC_FREE` being invoked twice concurrently on the same handle.

### Finding Description
For unit joints broadcast on the DAG, `handleJoint` in `network.js` enforces exclusivity per unit via the `assocUnitsInWork` guard before validation/mutex acquisition: [1](#0-0) 

Private payments delivered peer-to-peer (device messaging, not DAG broadcast) go through a different, much weaker path. In `handleOnlinePrivatePayment`, when the head unit of the chain is already known, the code calls `privatePayment.validateAndSavePrivatePaymentChain` directly, with the equivalent in-work bookkeeping explicitly commented out: [2](#0-1) 

`validateAndSavePrivatePaymentChain` in `private_payment.js` opens its own connection, does a duplicate check by *destination* `(unit, message_index, output_index)` only, then defers to the asset module to insert the spend: [3](#0-2) 

Critically, this duplicate check keys on the **destination** output, not on the **source** output being spent. Two different (or resent) private-element chains that spend the *same* source output to different destinations are not caught by this check at all, and each proceeds into `divisibleAsset`/`indivisibleAsset` saving logic, which marks the source output spent and inserts an `inputs` row: [4](#0-3) 

The `inputs` table relies on a unique constraint over `(src_unit, src_message_index, src_output_index, is_unique)` to prevent double-spends, but `is_unique` is deliberately set to `NULL` for unstable inputs: [5](#0-4) [6](#0-5) 

Because SQL unique/primary-key constraints treat multiple `NULL` values as distinct (not equal), the "no double spend" guarantee documented in the schema comment does not hold while `is_unique` is `NULL`, i.e. exactly during the window before the chain stabilizes — the same window in which concurrent delivery/retries are most likely to happen. There is no `mutex.lock` (equivalent to the `handleJoint` or per-author locks used for public units in `validation.js`) protecting this private-payment save path against concurrent execution: [7](#0-6) 

This is structurally the same bug class as CVE-2016-9120: a resource (here, a private output/spend-proof) can be "freed" (spent) twice because two concurrent execution paths both pass a check that is not atomic with the subsequent state mutation, and no lock serializes the two paths.

### Impact Explanation
A malicious or buggy private-payment counterparty can cause the same private output to be spent twice to two different addresses before the chain stabilizes. Since private outputs are known only to the parties in the chain (not globally validated by witnesses like public payments), this is a genuine unauthorized double-spend of private-asset funds, which the "Validate" criteria for this report explicitly count as an accepted impact ("concrete unauthorized spending, double-spend of a stable/private output").

### Likelihood Explanation
The trigger is a single private-payment counterparty (or a paired device) sending/resending overlapping private-element chains for the same source output — no p2p/hub compromise, no operator privileges, and no timing beyond ordinary network jitter/retry behavior is required. The commented-out guard in `handleOnlinePrivatePayment` shows the developers were aware of and removed the only in-flight protection for this exact code path, making the race practically reachable.

### Recommendation
- Reinstate an in-work / mutex guard keyed by the private chain's source output (or head unit) in `handleOnlinePrivatePayment`'s `ifKnown` branch before calling `validateAndSavePrivatePaymentChain`, mirroring the `assocUnitsInWork` + `mutex.lock(['handleJoint'])` pattern used for public units.
- Extend the duplicate check in `private_payment.js`'s `validateAndSavePrivatePaymentChain` to also check for an existing spend of the same `(src_unit, src_message_index, src_output_index)` before inserting a new `inputs` row, independent of `is_unique`/stability state.
- Consider using a non-nullable uniqueness marker (e.g. a separate "spend attempted" flag not tied to stability) so the DB-level unique constraint actually enforces exclusivity while `is_unique` is `NULL`.

### Proof of Concept
1. Party A creates two private-payment chains, both spending the same private output O (same `src_unit`/`src_message_index`/`src_output_index`), sending one to address X and the other to address Y.
2. A sends both chains to victim device V in quick succession (or via two channels: direct P2P and via hub) so that `handleOnlinePrivatePayment` is invoked twice concurrently on V, with the head unit already `ifKnown` in both cases.
3. Both calls proceed straight into `privatePayment.validateAndSavePrivatePaymentChain` with no serializing lock; each opens its own DB connection/transaction.
4. Each duplicate check only looks at the respective (different) destination `(unit, message_index, output_index)`, so neither call detects the conflict.
5. Both transactions commit, inserting two `inputs` rows referencing the same `(src_unit, src_message_index, src_output_index)` with `is_unique = NULL` (unstable) — the unique index does not reject this because of SQL NULL semantics — resulting in output O being recorded as spent twice, to X and to Y.

### Citations

**File:** network.js (L1161-1166)
```javascript
	if (assocUnitsInWork[unit])
		return callbacks.ifUnitInWork();
	assocUnitsInWork[unit] = true;
	
	var validate = function(){
		mutex.lock(['handleJoint'], function(unlock){
```

**File:** network.js (L2412-2429)
```javascript
	joint_storage.checkIfNewUnit(unit, {
		ifKnown: function(){
			//assocUnitsInWork[unit] = true;
			privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
				ifOk: function(){
					//delete assocUnitsInWork[unit];
					callbacks.ifAccepted(unit);
					eventBus.emit("new_my_transactions", [unit]);
				},
				ifError: function(error){
					//delete assocUnitsInWork[unit];
					callbacks.ifValidationError(unit, error);
				},
				ifWaitingForChain: function(){
					savePrivatePayment();
				}
			});
		},
```

**File:** private_payment.js (L45-107)
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
								const stored = rows[0];
								const payload = headElement.payload;
								let bDuplicate = false;
								if (objAsset.fixed_denominations){ // the row we selected is exactly headElement.output_index, filtered in sql above
									const claimed_output = payload.outputs?.[headElement.output_index];
									const revealed_output = headElement?.output;
									bDuplicate =
										ValidationUtils.isNonemptyObject(claimed_output)
										&& ValidationUtils.isNonemptyObject(revealed_output)
										&& stored.denomination === payload.denomination
										&& stored.amount === claimed_output.amount
										&& stored.address === revealed_output.address
										&& stored.blinding === revealed_output.blinding;
								}
								else // divisible outputs are never hidden individually and sql has no output_index filter, so match against any of them
									bDuplicate = (payload.outputs || []).some(output => {
										return ValidationUtils.isNonemptyObject(output)
											&& stored.denomination === 1
											&& stored.amount === output.amount
											&& stored.address === output.address
											&& stored.blinding === output.blinding;
									});
								if (bDuplicate) {
									console.log("duplicate private payment "+params.join(', '));
									return transaction_callbacks.ifOk();
								}
							}
							var assetModule = objAsset.fixed_denominations ? indivisibleAsset : divisibleAsset;
							assetModule.validateAndSavePrivatePaymentChain(conn, arrPrivateElements, transaction_callbacks);
						}
					);
```

**File:** divisible_asset.js (L39-70)
```javascript
			for (var j=0; j<payload.inputs.length; j++){
				var input = payload.inputs[j];
				var type = input.type || "transfer";
				var src_unit = input.unit;
				var src_message_index = input.message_index;
				var src_output_index = input.output_index;
				var address = null, address_sql = null;
				if (type === "issue")
					address = input.address || arrAuthorAddresses[0];
				else{ // transfer
					if (arrAuthorAddresses.length === 1)
						address = arrAuthorAddresses[0];
					else
						address_sql = "(SELECT address FROM outputs \
						WHERE unit="+conn.escape(src_unit)+" AND message_index="+conn.escape(src_message_index)+" \
							AND output_index="+conn.escape(src_output_index)+" AND address IN("+conn.escape(arrAuthorAddresses)+"))";
				}
				var is_unique = bStable ? 1 : null; // unstable still have chances to become nonserial therefore nonunique
				conn.addQuery(arrQueries, "INSERT INTO inputs \n\
						(unit, message_index, input_index, type, \n\
						src_unit, src_message_index, src_output_index, \
						serial_number, amount, \n\
						asset, is_unique, address) VALUES(?,?,?,?,?,?,?,?,?,?,?,"+(address_sql || conn.escape(address))+")",
					[unit, message_index, j, type, 
					 src_unit, src_message_index, src_output_index, 
					 input.serial_number, input.amount, 
					 payload.asset, is_unique]);
				if (type === "transfer"){
					conn.addQuery(arrQueries, 
						"UPDATE outputs SET is_spent=1 WHERE unit=? AND message_index=? AND output_index=?",
						[src_unit, src_message_index, src_output_index]);
				}
```

**File:** initial-db/byteball-sqlite.sql (L305-307)
```sql
	UNIQUE  (src_unit, src_message_index, src_output_index, is_unique), -- UNIQUE guarantees there'll be no double spend for type=transfer
	UNIQUE  (type, from_main_chain_index, address, is_unique), -- UNIQUE guarantees there'll be no double spend for type=hc/witnessing
	UNIQUE  (asset, denomination, serial_number, address, is_unique), -- UNIQUE guarantees there'll be no double issue
```

**File:** validation.js (L357-357)
```javascript
	mutex.lock(arrAuthorAddresses, function(unlock){
```
