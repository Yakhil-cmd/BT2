## Title
TOCTOU race in private-payment output reveal allows a malicious counterparty to make a victim wallet believe it received private funds it never actually got - (File: `indivisible_asset.js`)

### Summary
`private_payment.js` and `indivisible_asset.js`/`divisible_asset.js` implement a check-then-act sequence for saving an incoming private (hidden) payment chain: first a duplicate-check `SELECT` is run, then — inside the *same* application-level flow but with no cross-request lock — the code performs an `UPDATE outputs ... WHERE is_spent=0` to reveal `address`/`blinding` for the underlying hidden output, and unconditionally reports success to the caller regardless of whether that `UPDATE` actually matched a row. A private-payment counterparty who controls when/to whom a private chain is delivered can race two deliveries of the same underlying hidden output (same `unit`/`message_index`/`output_index`) to two different connections/devices so that the loser's write silently no-ops while the loser's wallet is still told "accepted."

### Finding Description
`network.js`'s `handleOnlinePrivatePayment` is reachable by any private-payment counterparty/device and, once the unit is known, calls straight into `privatePayment.validateAndSavePrivatePaymentChain` with no locking: [1](#0-0) 

`private_payment.js` takes its own DB connection per call (`db.takeConnectionFromPool` → `BEGIN`), runs a `SELECT` to detect whether this hidden output was already revealed, and — if not — hands off to the asset-specific save routine, all without any `mutex.lock`: [2](#0-1) 

The actual "reveal" write in `indivisible_asset.js` performs `INSERT IGNORE` for the output row and then a separate `UPDATE outputs SET is_serial=?, is_spent=?, address=?, blinding=? WHERE unit=? AND message_index=? AND output_index=? AND is_spent=0`. The affected-row count of this `UPDATE` is never inspected — `callbacks.ifOk()` fires unconditionally after `async.series(arrQueries, ...)` completes: [3](#0-2) 

Notably, the codebase *is* aware that concurrent private-asset DB writes need explicit serialization: the double-spend "ununique" step for private assets is deliberately wrapped in `mutex.lock(["private_write"], ...)` in `validation.js`, precisely because private-asset row updates aren't otherwise protected against concurrent transactions: [4](#0-3) 

That same protection is absent from the check-then-reveal path in `private_payment.js`/`indivisible_asset.js`. Because each incoming private payment is validated and saved on its own freshly-taken connection/transaction (no `mutex.lock(['write'])` or `mutex.lock(['private_write'])` guarding the whole check-then-act sequence), two concurrent deliveries of a chain revealing the *same* hidden output to two different recipients race: both pass the duplicate-check `SELECT` before either commits, then whichever transaction's `UPDATE ... WHERE is_spent=0` commits first "wins" and persists its `address`/`blinding`. The other transaction's `UPDATE` then matches zero rows (since `is_spent` is already `1`), but this is never checked, so `callbacks.ifOk()` still fires and the losing recipient's wallet is told the payment was accepted.

### Impact Explanation
A private-payment counterparty (e.g. the textcoin/private-asset sender, who fully controls the timing/order/targets of chain delivery) can present the same underlying hidden output as a payment to two different devices/wallets concurrently. One of the two receiving wallets ends up believing it validated and stored a spendable private output (`ifAccepted`/`ifOk` fired, `all_private_payments_handled` event emitted per `wallet.js`'s `handlePrivatePaymentFile`), while the persisted DB row's actual `address`/`blinding` belongs to the other recipient. This is a node/wallet disagreement about ownership of a private output that can result in fund loss for the tricked recipient (they think they hold funds that they cannot actually spend, since the real row is owned by someone else) and inconsistent validity state between peers — precisely the "node disagreement on validity" and private-payment fund-loss class of impact.

### Likelihood Explanation
Exploitation requires only that the attacker (any legitimate correspondent in a private payment, such as a textcoin sender) deliver the same private chain to two different endpoints at close to the same time, which is entirely within a normal sender's control — no cryptographic forgery or protocol violation is needed, and no privileged/network-level position is required.

### Recommendation
Wrap the duplicate-check + save sequence for incoming private payment chains (`private_payment.js`'s `validateAndSave` and the asset-specific `validateAndSavePrivatePaymentChain` routines) in the same kind of serializing lock already used elsewhere for private-asset writes (e.g. `mutex.lock(["private_write"])`), and check the affected-row count of the `UPDATE ... WHERE is_spent=0` reveal query, treating a zero-row result as a genuine conflict/error rather than silently calling `ifOk()`.

### Proof of Concept
1. Attacker (the sender of a private/textcoin payment) builds one private payment chain revealing hidden output `(unit U, message_index M, output_index O)`.
2. Attacker sends this chain to Recipient A's device and, before either save commits, also sends it (or a variant with different `blinding`) to Recipient B's device, e.g. via the hub/direct device message paths that funnel into `network.handleOnlinePrivatePayment` → `private_payment.validateAndSavePrivatePaymentChain`.
3. Both A's and B's nodes independently take fresh connections, pass the "duplicate" `SELECT` check (since the output hasn't been revealed on either connection's view yet), and proceed to run `indivisible_asset.js`'s `validateAndSavePrivatePaymentChain`.
4. Whichever transaction commits its `UPDATE ... WHERE is_spent=0` first "wins" the row; the other's `UPDATE` affects 0 rows but is not checked.
5. Both A and B still receive `ifOk()`/`ifAccepted` in their respective wallets, but only one's `address`/`blinding` is actually persisted in the `outputs` table — the loser now holds a wallet record for funds it does not actually control on-DAG.

### Citations

**File:** network.js (L2412-2428)
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
```

**File:** private_payment.js (L45-110)
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
				});
			});
		});
```

**File:** indivisible_asset.js (L239-297)
```javascript
function validateAndSavePrivatePaymentChain(conn, arrPrivateElements, callbacks){
	parsePrivatePaymentChain(conn, arrPrivateElements, {
		ifError: callbacks.ifError,
		ifOk: function(bAllStable){
			console.log("saving private chain "+JSON.stringify(arrPrivateElements));
			profiler.start();
			var arrQueries = [];
			for (var i=0; i<arrPrivateElements.length; i++){
				var objPrivateElement = arrPrivateElements[i];
				var payload = objPrivateElement.payload;
				var input_address = objPrivateElement.input_address;
				var input = payload.inputs[0];
				var is_unique = objPrivateElement.bStable ? 1 : null; // unstable still have chances to become nonserial therefore nonunique
				if (!input.type) // transfer
					conn.addQuery(arrQueries, 
						"INSERT "+db.getIgnore()+" INTO inputs \n\
						(unit, message_index, input_index, src_unit, src_message_index, src_output_index, asset, denomination, address, type, is_unique) \n\
						VALUES (?,?,?,?,?,?,?,?,?,'transfer',?)", 
						[objPrivateElement.unit, objPrivateElement.message_index, 0, input.unit, input.message_index, input.output_index, 
						payload.asset, payload.denomination, input_address, is_unique]);
				else if (input.type === 'issue')
					conn.addQuery(arrQueries, 
						"INSERT "+db.getIgnore()+" INTO inputs \n\
						(unit, message_index, input_index, serial_number, amount, asset, denomination, address, type, is_unique) \n\
						VALUES (?,?,?,?,?,?,?,?,'issue',?)", 
						[objPrivateElement.unit, objPrivateElement.message_index, 0, input.serial_number, input.amount, 
						payload.asset, payload.denomination, input_address, is_unique]);
				else
					throw Error("neither transfer nor issue after validation");
				var is_serial = objPrivateElement.bStable ? 1 : null; // initPrivatePaymentValidationState already checks for non-serial
				var outputs = payload.outputs;
				for (var output_index=0; output_index<outputs.length; output_index++){
					var output = outputs[output_index];
					console.log("inserting output "+JSON.stringify(output));
					conn.addQuery(arrQueries, 
						"INSERT "+db.getIgnore()+" INTO outputs \n\
						(unit, message_index, output_index, amount, output_hash, asset, denomination) \n\
						VALUES (?,?,?,?,?,?,?)",
						[objPrivateElement.unit, objPrivateElement.message_index, output_index, 
						output.amount, output.output_hash, payload.asset, payload.denomination]);
					var fields = "is_serial=?";
					var params = [is_serial];
					if (output_index === objPrivateElement.output_index){
						var is_spent = (i===0) ? 0 : 1;
						fields += ", is_spent=?, address=?, blinding=?";
						params.push(is_spent, objPrivateElement.output.address, objPrivateElement.output.blinding);
					}
					params.push(objPrivateElement.unit, objPrivateElement.message_index, output_index);
					conn.addQuery(arrQueries, "UPDATE outputs SET "+fields+" WHERE unit=? AND message_index=? AND output_index=? AND is_spent=0", params);
				}
			}
		//	console.log("queries: "+JSON.stringify(arrQueries));
			async.series(arrQueries, function(){
				profiler.stop('save');
				callbacks.ifOk();
			});
		}
	});
}
```

**File:** validation.js (L2283-2295)
```javascript
						mutex.lock(["private_write"], function(unlock){
							console.log("--- will ununique the conflicts of unit "+objUnit.unit);
							conn.query(
								sql, 
								doubleSpendVars, 
								function(){
									console.log("--- ununique done unit "+objUnit.unit);
									objValidationState.arrDoubleSpendInputs.push({message_index: message_index, input_index: input_index});
									unlock();
									cb3();
								}
							);
						});
```
