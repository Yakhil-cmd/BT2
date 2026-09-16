### Title
Non-atomic `MAX(serial_number)` counter in AA asset issuance can generate colliding `serial_number`s, causing loss of a triggered AA response's issued coins - (File: `aa_composer.js`)

### Summary
The XDEFI report shows a `tokenId` generated from `totalSupply()+1`, a value derived by re-reading current storage rather than a persistent monotonic counter; because supply can be reduced without erasing the underlying record, the same id is regenerated and collides. `aa_composer.js`'s `issueAsset()` has the same structural weakness: for uncapped assets it derives the next `serial_number` by querying `SELECT MAX(serial_number) ... FROM inputs` at response-composition time instead of using an atomically incremented, persisted counter.

### Finding Description
When an AA response message issues a non-capped asset, the composer computes the next `serial_number` from a live query over the `inputs` table rather than from a dedicated counter: [1](#0-0) 
This value is embedded in the `issue` input of the newly composed response unit: [2](#0-1) 

If the same AA is triggered by two nearly-simultaneous, independently-composed trigger units (an unprivileged AA-trigger sender only needs to send two payments to the AA in short succession, landing in different, still-unstable/parallel branches of the DAG), both response compositions can run their `SELECT MAX(serial_number) ...` query against the same pre-existing set of `inputs` rows (neither response has been written yet), and both will compute and embed the identical `max_serial_number+1`. This is exactly the report's edge case: a value used to derive a "next unique id" is read from mutable state instead of tracked with a durable, monotonically-incrementing counter, so two mints can collide on the same id.

Ocore's protocol-level uniqueness constraint on `(asset, denomination, serial_number, address)` in the `inputs` table and the doublespend-resolution logic in `validatePaymentInputsAndOutputs` are the only backstop: [3](#0-2) 
When the collision is detected, one of the two conflicting issue inputs is "ununique"'d once its containing unit is decided to be on the losing side of the DAG: [4](#0-3) 

### Impact Explanation
Because `is_unique` on the losing issue input is set to `NULL`, that response unit's `issue` input no longer counts as backing value for the asset (loses its uniqueness/validity as a fresh coin), even though the unit itself remains in the DAG and its outputs otherwise look like a normal AA response to the counterparty who triggered it. The trigger sender for the losing branch receives a response unit whose issued-asset input is ultimately invalidated - concretely, an AA fund loss/freezing scenario for that user, and both trigger senders reasonably observe divergent outcomes for what appears to be a normal same-block AA interaction, depending on which branch stabilizes as the winner. This matches the required impact class (AA fund loss/freezing) since a legitimately-triggered AA output silently becomes invalid, and it is fully reachable by unprivileged users who simply send parallel trigger payments to an AA that issues an uncapped asset (a common oscript pattern for token-issuing AAs).

### Likelihood Explanation
Any AA whose bytecode/oscript issues a non-capped asset in a `payment`-type "asset issuance" branch relies on `aa_composer.js`'s `issueAsset()` for serial number assignment. Two ordinary users triggering the same AA at close to the same time (a routine occurrence for a popular token-issuing AA, requiring no special privilege, timing side channel, or malicious peer/hub behavior) is sufficient to hit the race, since the `SELECT MAX(serial_number)` reads happen before either composed unit is committed/broadcast. This is a normal-usage collision, not a contrived adversarial setup, making the likelihood moderate-to-high for any live, popular uncapped-asset-issuing AA.

### Recommendation
Replace the read-then-compute-next `MAX(serial_number)` pattern with an atomically reserved/incremented persistent counter (analogous to the XDEFI fix of using an internal always-incrementing `_tokensMinted` variable instead of `totalSupply()`), e.g., maintain a dedicated `asset_state`/`aa_asset_counters` row per `(asset, address)` that is incremented under the same DB transaction/lock used to compose and commit the AA response unit, so concurrent compositions for the same address/asset cannot observe the same "next" serial number before either is durably reserved.

### Proof of Concept
1. Deploy an AA (oscript) whose response, when triggered, issues a non-capped custom asset via an `asset` message with `issued_by_definer_only` referencing the AA's own address (a supported and common pattern, see `aa_composer.js:1175-1211`).
2. Have two different users each send a triggering payment to the AA at nearly the same time so both trigger units land as parallel (currently-unstable) units before either AA response is composed/written.
3. During composition of both AA responses, `issueAsset()` executes `SELECT MAX(serial_number) AS max_serial_number FROM inputs WHERE type='issue' AND asset=? AND address=?` (`aa_composer.js:1203-1205`) against the same set of not-yet-updated `inputs` rows, so both responses compute the same `max_serial_number+1` and embed it as their `issue.serial_number`.
4. Once both response units are broadcast, `validatePaymentInputsAndOutputs` in `validation.js` detects the duplicate `(asset, denomination, serial_number, address)` combination via the `checkInputDoubleSpend`/`byAssetDenominationSerialAddress` uniqueness constraint (`validation.js:2356-2384`) and marks the loser's issue input `is_unique=NULL` once stability is determined (`validation.js:2276-2295`), invalidating the coin issuance for that triggering user's AA response.

### Citations

**File:** aa_composer.js (L1181-1193)
```javascript
				function addIssueInput(serial_number){
					var input = {
						type: "issue",
						amount: issue_amount,
						serial_number: serial_number
					};
					payload.inputs.unshift(input);
					total_amount += issue_amount;
					var change_amount = total_amount - target_amount;
					if (change_amount > 0)
						payload.outputs.push({ address: address, amount: change_amount });
					cb2();
				}
```

**File:** aa_composer.js (L1202-1211)
```javascript
				else{
					conn.query( // filtered by our AA's address, all equally visible on all nodes
						"SELECT MAX(serial_number) AS max_serial_number FROM inputs WHERE type='issue' AND asset=? AND address=?",
						[asset, address],
						function(rows){
							var max_serial_number = (rows.length === 0) ? 0 : rows[0].max_serial_number;
							addIssueInput(max_serial_number+1);
						}
					);
				}
```

**File:** validation.js (L2276-2295)
```javascript
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
```

**File:** validation.js (L2356-2384)
```javascript
					var input_key = (payload.asset || "base") + "-" + denomination + "-" + address + "-" + input.serial_number;
					if (objValidationState.arrInputKeys.indexOf(input_key) >= 0)
						return callback("input "+input_key+" already used");
					objValidationState.arrInputKeys.push(input_key);
					doubleSpendWhere = "type='issue'";
					doubleSpendVars = [];
				//	if (objAsset && objAsset.fixed_denominations){
						doubleSpendWhere += " AND denomination=?";
						doubleSpendVars.push(denomination);
				//	}
					if (objAsset){
						doubleSpendWhere += " AND serial_number=?";
						doubleSpendVars.push(input.serial_number);
					}
					if (objAsset && !objAsset.issued_by_definer_only){
						doubleSpendWhere += " AND address=?";
						doubleSpendVars.push(address);
					}
				//	if (objAsset)
				//		profiler2.stop('validate issue');
					if (objAsset && objAsset.fixed_denominations){
						validateIndivisibleIssue(input, function(err){
							if (err)
								return cb(err);
							checkInputDoubleSpend(cb);
						});
					}
					else
						checkInputDoubleSpend(cb);
```
