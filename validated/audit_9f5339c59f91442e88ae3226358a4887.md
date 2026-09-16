### Title
Premature, non-transactional mutation of `is_unique` before overall unit validation completes enables private-asset double-spend - ([File: validation.js])

### Summary
`validatePaymentInputsAndOutputs()` in `validation.js` runs the "accept doublespend" mutation (`UPDATE inputs SET is_unique=NULL ...`) for private-asset inputs synchronously, directly on the shared DB connection, *before* the rest of the unit's validation has finished and before the unit is known to be accepted. This mirrors the WireGuard bug class: an authenticity-style check (recognizing a legitimate forked-path doublespend) triggers a persistent state mutation ahead of the final accept/reject decision, with no rollback if the containing unit is ultimately rejected for an unrelated reason.

### Finding Description
For a normal (non-private) asset, when `checkForDoublespends()` decides a conflicting input should be accepted as a legitimate fork doublespend, the corresponding `UPDATE inputs SET is_unique=NULL ...` is only *queued* into `objValidationState.arrAdditionalQueries`: [1](#0-0) 
These queued queries are only executed later, inside `writer.saveJoint()`, which only runs after the entire unit has passed *all* validation: [2](#0-1) 

However, for **private assets** (`objAsset.is_private`), the code takes a different path: it executes the mutation immediately against the live `conn`, inside the validation phase itself: [3](#0-2) 

The comment on the transfer-input branch explains why private fixed-denomination assets are handled specially ("we validate the entire chain before saving anything"), but this special-casing is only safely contained for the *private payment chain* save path (`private_payment.js`), which wraps the whole chain validate-and-save in an explicit `BEGIN`/`COMMIT`/`ROLLBACK` transaction: [4](#0-3) 

The generic unit-validation entry point `validation.validate()` (invoked from `network.js` `handleJoint` for ordinary posted units) does **not** wrap the connection in such a transaction — `writer.saveJoint()` opens its own transaction only later, only if validation as a whole succeeds: [5](#0-4) 

Consequently, if a unit containing a private-asset payment message reaches `checkInputDoubleSpend` → `acceptDoublespends` for one of its inputs (a legitimate, address-forked doublespend scenario), the code immediately commits `is_unique=NULL` on the previously-unique conflicting input row, using `mutex.lock(["private_write"])` only to serialize concurrent writers, not to provide atomicity/rollback: [6](#0-5) 
`async.forEachOfSeries` then proceeds to validate the *rest* of the inputs/outputs of the same message, and other messages of the same unit, in `validatePayment`/`validateMessage`. If validation subsequently fails for any unrelated reason (e.g., another input/output in the same unit is malformed, an asset/attestation/denomination check elsewhere fails, or a later message is invalid), `ifUnitError` is returned and the unit is discarded — but the `is_unique=NULL` mutation performed moments earlier is never undone, because it was committed outside any transaction that gets rolled back on this failure path.

The `inputs` table enforces double-spend prevention purely through the `UNIQUE KEY bySrcOutput(src_unit, src_message_index, src_output_index, is_unique)` constraint: [7](#0-6) 
Once `is_unique` is cleared to `NULL` for a legitimate, previously-unique input row, that row is no longer counted by the unique index, so a subsequent conflicting `transfer` input referencing the same `(src_unit, src_message_index, src_output_index)` for the same private asset can be inserted without violating the constraint — i.e., the private output can be spent a second time.

### Impact Explanation
This allows an unprivileged unit poster to permanently weaken the double-spend protection on a specific private-asset output: by crafting one throwaway unit that (a) legitimately triggers the "accept doublespend" branch for a private-asset input against an existing, real forked-path competitor, and (b) is designed to fail validation later in the same unit for an unrelated reason, the attacker leaves the targeted output's `is_unique` flag cleared in the DB even though their poisoning unit itself is rejected and never saved. A subsequent, otherwise-invalid second spend of the same private output can then be accepted because the uniqueness constraint no longer blocks it, resulting in double-spend of a private asset — fund duplication/loss for the counterparty of the private payment. This satisfies the "double-spend of a stable/committed output" impact bar.

### Likelihood Explanation
Reaching this code path requires only posting an ordinary unit containing a private-asset payment message with a transfer input that qualifies as an "accepted" fork doublespend (i.e., `objValidationState.arrAddressesWithForkedPath` includes the spending address — reachable whenever the attacker legitimately forks their own address, which they fully control) and arranging for a later part of the same unit to fail validation. Both conditions are fully within an ordinary unit-posting author's control; no privileged network position, hub/witness role, or victim cooperation is required. The main uncertainty is exact reproduction complexity (constructing a unit that both triggers the accept-doublespend branch and fails later), but the underlying execution order and lack of rollback are directly demonstrated in the code.

### Recommendation
Defer the `is_unique=NULL` mutation for private assets the same way it is done for public assets — via `objValidationState.arrAdditionalQueries`, executed only inside `writer.saveJoint()` after the entire unit has passed validation — instead of issuing a direct `conn.query()` during `validatePaymentInputsAndOutputs()`. If immediate execution is required for private-chain validation ordering reasons, ensure it happens only within a connection/transaction that is guaranteed to roll back if any later part of the same unit's validation fails.

### Proof of Concept
Conceptual outline (exact unit construction was not executed against a live node):
1. Attacker controls address A and previously has two forked units spending the same private-asset output from address A (a legitimate fork scenario), so `objValidationState.arrAddressesWithForkedPath` contains A when a new conflicting unit U1 is validated.
2. Attacker posts unit U1 with a private-asset transfer input referencing the same `(src_unit, src_message_index, src_output_index)` as an existing, currently-unique input row. `checkForDoublespends` → `acceptDoublespends` runs, and because `objAsset.is_private` is true, `conn.query("UPDATE inputs SET is_unique=NULL WHERE ...")` executes immediately at [6](#0-5) .
3. Unit U1 also contains a second message/input crafted to fail later validation (e.g., bad denomination, invalid output address, or unrelated malformed field), causing `validate()` to return `ifUnitError` for U1; U1 is never saved by `writer.saveJoint()`.
4. Despite U1 being rejected, the earlier `UPDATE` already cleared `is_unique` on the original input row in the live DB (no transaction rollback occurred for this path).
5. Attacker (or anyone) now posts unit U2 with another transfer input pointing at the same `(src_unit, src_message_index, src_output_index)`. Because the unique index `bySrcOutput(src_unit, src_message_index, src_output_index, is_unique)` no longer has two rows with `is_unique=1` for that source output, the double-spend insert succeeds where it should have been rejected, resulting in the private-asset output being spent twice.

### Citations

**File:** validation.js (L2274-2296)
```javascript
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

**File:** writer.js (L58-74)
```javascript
		// additional queries generated by the validator, used only when received a doublespend
		for (var i=0; i<objValidationState.arrAdditionalQueries.length; i++){
			var objAdditionalQuery = objValidationState.arrAdditionalQueries[i];
			conn.addQuery(arrQueries, objAdditionalQuery.sql, objAdditionalQuery.params);
			breadcrumbs.add('====== additional query '+JSON.stringify(objAdditionalQuery));
			if (objAdditionalQuery.sql.match(/temp-bad/)){
				var arrUnstableConflictingUnits = objAdditionalQuery.params[0];
				breadcrumbs.add('====== conflicting units in additional queries '+arrUnstableConflictingUnits.join(', '));
				arrUnstableConflictingUnits.forEach(function(conflicting_unit){
					var objConflictingUnitProps = storage.assocUnstableUnits[conflicting_unit];
					if (!objConflictingUnitProps)
						return breadcrumbs.add("====== conflicting unit "+conflicting_unit+" not found in unstable cache"); // already removed as uncovered
					if (objConflictingUnitProps.sequence === 'good')
						objConflictingUnitProps.sequence = 'temp-bad';
				});
			}
		}
```

**File:** private_payment.js (L45-60)
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
```

**File:** network.js (L1258-1286)
```javascript
				ifOk: async function(objValidationState, validation_unlock){
					clearHost();
					if (objJoint.unsigned)
						throw Error("ifOk() unsigned");
					if (bPosted && objValidationState.sequence !== 'good') {
						validation_unlock();
						callbacks.ifUnitError("The transaction would be non-serial (a double spend)");
						delete assocUnitsInWork[unit];
						unlock();
						if (ws)
							writeEvent('nonserial', ws.host);
						return;
					}
					if (conf.bDryRunNewTriggers && !conf.bLight && !objJoint.ball && objValidationState.count_primary_aa_triggers) {
						const outputAddresses = objJoint.unit.messages
							.filter(msg => msg.app === 'payment')
							.reduce((acc, msg) => acc.concat(msg.payload.outputs.map(output => output.address)), []);
						const rows = await db.query("SELECT address, definition FROM aa_addresses WHERE address IN (?)", [outputAddresses]);
						for (let { address, definition } of rows) {
							console.log(`dry run trigger for AA address ${address} in submitted unit ${unit}`);
							const trigger = aa_composer.getTrigger(objJoint.unit, address);
							// if it would crash, let it crash now, not when we execute the trigger for real
							await aa_composer.dryRunPrimaryAATrigger(trigger, address, JSON.parse(definition));
						}
					}
					writer.saveJoint(objJoint, objValidationState, null, function(){
						validation_unlock();
						callbacks.ifOk();
						unlock();
```

**File:** initial-db/byteball-mysql.sql (L278-296)
```sql
CREATE TABLE inputs (
	unit CHAR(44) CHARACTER SET latin1 COLLATE latin1_bin NOT NULL,
	message_index TINYINT NOT NULL,
	input_index TINYINT NOT NULL,
	asset CHAR(44) CHARACTER SET latin1 COLLATE latin1_bin NULL,
	denomination INT NOT NULL DEFAULT 1,
	is_unique TINYINT NULL DEFAULT 1,
	type ENUM('transfer','headers_commission','witnessing','issue') NOT NULL,
	src_unit CHAR(44) CHARACTER SET latin1 COLLATE latin1_bin NULL, -- transfer
	src_message_index TINYINT NULL, -- transfer
	src_output_index TINYINT NULL, -- transfer
	from_main_chain_index INT NULL, -- witnessing/hc
	to_main_chain_index INT NULL, -- witnessing/hc
	serial_number BIGINT NULL, -- issue
	amount BIGINT NULL, -- issue
	address CHAR(32) NOT NULL,
	PRIMARY KEY (unit, message_index, input_index),
	UNIQUE KEY bySrcOutput(src_unit, src_message_index, src_output_index, is_unique), -- UNIQUE guarantees there'll be no double spend for type=transfer
	UNIQUE KEY byIndexAddress(type, from_main_chain_index, address, is_unique), -- UNIQUE guarantees there'll be no double spend for type=hc/witnessing
```
