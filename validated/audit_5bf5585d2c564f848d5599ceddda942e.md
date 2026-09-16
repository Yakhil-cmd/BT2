### Title
Race condition in private payment chain validation due to missing mutex around check-then-insert of double-spend inputs enables double-spend of private assets - (File: private_payment.js)

### Summary
CVE-2016-2546 describes a Linux kernel bug where an incorrect/insufficiently scoped mutex type let concurrent `ioctl` calls race on shared timer state, causing a use-after-free/inconsistent state. The analogous class in ocore is a lock that is either missing or too narrowly scoped around a check-then-act sequence on shared double-spend state for private-asset inputs, letting two concurrently processed private payment chains both pass the "not yet spent" check before either commits, resulting in acceptance of a genuine double-spend of a private asset.

### Finding Description
`privatePayment.validateAndSavePrivatePaymentChain()` [1](#0-0)  takes its own DB connection and wraps validation+save in a plain `BEGIN`/`COMMIT` transaction, but it never acquires any `mutex.lock()` on the asset, the spent output, or a global serialization key (e.g. `"private_write"` or `"handleJoint"`) before performing its duplicate check and insert.

This function is reachable from an unprivileged private-payment counterparty via two paths that can run concurrently:
- `network.js` `handleOnlinePrivatePayment()`, invoked when a device/peer sends a private payment directly [2](#0-1) .
- `network.js` `handleSavedPrivatePayments()`, which processes queued unhandled private payments using `async.each` (parallel, not serial) and calls `privatePayment.validateAndSavePrivatePaymentChain` once per row without any per-output or per-asset lock [3](#0-2) .

Deeper in the call chain, `validation.js`'s `checkInputDoubleSpend()` does hold `mutex.lock(["private_write"])`, but only around the final `UPDATE inputs SET is_unique=NULL ...` statement used to "ununique" a losing competitor — not around the preceding `SELECT`-based doublespend detection query executed by `checkForDoublespends()` [4](#0-3)  nor around the whole validate-then-insert sequence [5](#0-4) . Each private-chain validation opens its own DB connection/transaction via `db.takeConnectionFromPool` + `BEGIN` [6](#0-5) , so two concurrently running validations of chains that spend the same private output can each execute their doublespend `SELECT` before either has committed its own conflicting `INSERT INTO inputs`. Both see "no conflicting record" and both proceed to insert their input as `is_unique=1`/`NULL`-with-stable-conversion via `validateAndSaveDivisiblePrivatePayment`/`indivisible_asset.js` `validateAndSavePrivatePaymentChain`, which insert rows keyed by `(src_unit, src_message_index, src_output_index, is_unique)` [7](#0-6)  and mark the source output spent [8](#0-7) .

This is the same bug class as CVE-2016-2546: the lock protecting shared state does not cover the full read-modify-write critical section, so a legitimate concurrent user action (receiving/replaying two conflicting private payment chains, e.g. from a payer sending the same private coin to two different recipients/cosigners, or a device replaying an old chain while a new one is in flight) can race through validation before the SQLite/MySQL row-level uniqueness constraints on `inputs` are actually committed and checked.

### Impact Explanation
A private-payment counterparty (attacker acting as sender/payer of a private asset, or a malicious/duplicated device message) can cause two conflicting private-payment chains for the same private-asset output to be independently accepted by a victim's wallet or hub before either transaction commits, since the validate-then-insert sequence for private inputs is not fully serialized by a mutex covering both the doublespend check and the insert. This can result in a local double-spend of a private (indivisible or divisible) asset being recorded as accepted (`ifAccepted`/`ifOk` fired for both chains), i.e., unauthorized/duplicate spending of the same private funds from the victim's perspective, until/unless the asset later reaches full-node consensus resolution (which private/light clients may never fully observe).

### Likelihood Explanation
Exploitation requires a specific race window: two conflicting private-payment chains for the same output must be processed by `handleSavedPrivatePayments` (which explicitly runs rows in parallel via `async.each`) or arrive at close to the same time via `handleOnlinePrivatePayment`/direct-peer delivery. Because private payment delivery is peer-to-peer/device-to-device and can be resent, an attacker fully controls the timing of sending duplicate/conflicting private chains to a target device, making the race practically triggerable, though success depends on winning the timing window against the target's I/O scheduling — hence Medium likelihood.

### Recommendation
Serialize the entire check-and-save critical section for private payment inputs (from the `checkForDoublespends` SELECT through the corresponding INSERT of the `inputs` row) under a single mutex key scoped to the spent output/asset (e.g. `asset+src_unit+src_message_index+src_output_index`), not just around the narrow `UPDATE ... is_unique=NULL` statement. Additionally, change `handleSavedPrivatePayments` to serialize (or lock per spent-output) instead of using `async.each` to process potentially conflicting private chains in parallel, and ensure `privatePayment.validateAndSavePrivatePaymentChain` acquires this lock before opening its transaction in `private_payment.js`.

### Proof of Concept
1. Attacker (payer) owns a private-asset output O.
2. Attacker builds two private payment chains, chain A spending O to recipient device R1, and chain B spending the same O to recipient device R2 (or resends the same chain twice with a manipulated peer field), and sends both to the victim/hub in quick succession.
3. `network.js` `handleSavedPrivatePayments()` (or two nearly simultaneous `handleOnlinePrivatePayment` calls) triggers two parallel invocations of `privatePayment.validateAndSavePrivatePaymentChain` (`network.js:2459-2510`, `private_payment.js:23-119`), each opening its own DB connection/transaction.
4. Both transactions independently run the doublespend-detection `SELECT` in `checkForDoublespends` (`validation.js:1661-1705`) before either has committed its `INSERT INTO inputs`, so both see no conflicting record and proceed to insert/mark the same output as spent (`divisible_asset.js:39-70` / `indivisible_asset.js:239-297`).
5. Both chains are accepted (`ifOk`/`ifAccepted`), giving the victim's client two locally-valid records of spending the same private output — a double-spend acceptance at the wallet/hub level.

### Citations

**File:** private_payment.js (L23-60)
```javascript
function validateAndSavePrivatePaymentChain(arrPrivateElements, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("no priv elements array");
	var headElement = arrPrivateElements[0];
	if (!headElement.payload)
		return callbacks.ifError("no payload in head element");
	var asset = headElement.payload.asset;
	if (!asset)
		return callbacks.ifError("no asset in head element");
	if (!ValidationUtils.isNonnegativeInteger(headElement.message_index))
		return callbacks.ifError("no message index in head private element");
	
	var validateAndSave = function(){
		storage.readAsset(db, asset, null, function(err, objAsset){
			if (err)
				return callbacks.ifError(err);
			if (objAsset.is_private !== 1)
				return callbacks.ifError("asset is not private");
			if (!!objAsset.fixed_denominations !== !!headElement.payload.denomination)
				return callbacks.ifError("presence of denomination field doesn't match the asset type");
			if (!!objAsset.fixed_denominations !== ("output" in headElement))
				return callbacks.ifError("divisible asset must not have output field, indivisible must");
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

**File:** network.js (L2459-2510)
```javascript
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
						}
						catch (e) {
							console.log("getBase64Hash failed for private element", objHeadPrivateElement.payload, e);
							if (ws)
								sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: e.toString()});
							deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
						}
						var key = 'private_payment_validated-'+objHeadPrivateElement.unit+'-'+json_payload_hash+'-'+row.output_index;
						privatePayment.validateAndSavePrivatePaymentChain(arrPrivateElements, {
							ifOk: function(){
								if (ws)
									sendResult(ws, {private_payment_in_unit: row.unit, result: 'accepted'});
								if (row.peer) // received directly from a peer, not through the hub
									eventBus.emit("new_direct_private_chains", [arrPrivateElements]);
								assocNewUnits[row.unit] = true;
								deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
								console.log('emit '+key);
								eventBus.emit(key, true);
							},
							ifError: function(error){
								console.log("validation of priv: "+error);
							//	throw Error(error);
								if (ws)
									sendResult(ws, {private_payment_in_unit: row.unit, result: 'error', error: error});
								deleteHandledPrivateChain(row.unit, row.message_index, row.output_index, cb);
								eventBus.emit(key, false);
							},
							// light only. Means that chain joints (excluding the head) not downloaded yet or not stable yet
							ifWaitingForChain: function(){
								console.log('waiting for chain: unit '+row.unit+', message '+row.message_index+' output '+row.output_index);
								cb();
							}
						});
					};
					
					if (conf.bLight && arrPrivateElements.length > 1 && !row.linked)
						updateLinkProofsOfPrivateChain(arrPrivateElements, row.unit, row.message_index, row.output_index, cb, validateAndSave);
					else
						validateAndSave();
					
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

**File:** validation.js (L2258-2296)
```javascript
			function checkInputDoubleSpend(cb2){
			//	if (objAsset)
			//		profiler2.start();
				doubleSpendWhere += " AND unit != " + conn.escape(objUnit.unit);
				if (objAsset){
					doubleSpendWhere += " AND asset=?";
					doubleSpendVars.push(payload.asset);
				}
				else
					doubleSpendWhere += " AND asset IS NULL";
				// final-bad units are treated as non-existent competitors (their inputs.is_unique is kept NULL)
				var doubleSpendQuery = "SELECT "+doubleSpendFields+" FROM inputs " + doubleSpendIndexMySQL + " JOIN units USING(unit) WHERE "+doubleSpendWhere+" AND sequence!='final-bad'";
				checkForDoublespends(
					conn, "divisible input", 
					doubleSpendQuery, doubleSpendVars, 
					objUnit, objValidationState, 
					function acceptDoublespends(cb3){
						console.log("--- accepting doublespend on unit "+objUnit.unit);
						var sql = "UPDATE inputs SET is_unique=NULL WHERE "+doubleSpendWhere+
							" AND (SELECT is_stable FROM units WHERE units.unit=inputs.unit)=0";
						if (!(objAsset && objAsset.is_private)){
							objValidationState.arrAdditionalQueries.push({sql: sql, params: doubleSpendVars});
							objValidationState.arrDoubleSpendInputs.push({message_index: message_index, input_index: input_index});
							return cb3();
						}
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
					}, 
```

**File:** divisible_asset.js (L39-65)
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
```

**File:** divisible_asset.js (L66-70)
```javascript
				if (type === "transfer"){
					conn.addQuery(arrQueries, 
						"UPDATE outputs SET is_spent=1 WHERE unit=? AND message_index=? AND output_index=?",
						[src_unit, src_message_index, src_output_index]);
				}
```
