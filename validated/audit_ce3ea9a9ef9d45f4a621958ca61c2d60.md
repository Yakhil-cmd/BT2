### Title
AA-defined asset with a formula-based `cap` that evaluates to 0 is silently treated as uncapped, letting an AA mint unlimited supply of an asset it declared as capped - (File: `aa_validation.js`, `aa_composer.js`, `inputs.js`, `formula/evaluation.js`)

### Summary
`ocore` allows an AA to define a new asset with a `cap` field expressed as a formula string (evaluated at execution time), rather than only a fixed positive integer. Everywhere the resulting `objAsset.cap` value is later consumed, the code treats a falsy `cap` (i.e. `0`) as "uncapped" (mint at will), exactly the same "0 == infinity" logic flagged in the referenced VTVL report for `VariableSupplyERC20Token`.

### Finding Description
When an AA defines an asset (`case 'asset':` message), `cap` may be a string formula instead of a literal positive integer: [1](#0-0) 

The validator only checks that the formula parses (`getFormula(payload.cap) !== null`); it never constrains what the formula can *evaluate to* at execution time - it could legitimately compute to `0` (e.g., based on a data feed, a trigger parameter, or state var that is 0 at the moment of asset creation).

Downstream, every consumer of `objAsset.cap` uses the same "falsy cap ⇒ uncapped" idiom that the VTVL bug exploited:

- In the AA composer, when the AA later needs to issue the asset it just defined: `var issue_amount = objAsset.cap || (target_amount - total_amount);` and the capped/uncapped issuance branch is chosen with `if (objAsset.cap) { ... } else { /* unlimited issuance keyed by serial_number */ }` [2](#0-1) 

- In the divisible-payment input picker used by plain wallets/units: `var issue_amount = objAsset.cap || (required_amount - total_amount) || 1;` and `if (objAsset.cap){ ... } else { /* issue with incrementing serial_number, unlimited */ }` [3](#0-2) 

- In the oscript/AA formula evaluator, `asset[...]['cap']` explicitly returns `0` for "no cap": `if (field === 'cap') // can be null\n return cb(convertValue(objAsset.cap || 0));` [4](#0-3) 

- In wallet composing logic: `if (!objAsset.cap){ // uncapped asset: can be issued from definer_address or from any address ... }` [5](#0-4) 

Because a cap of `0` is indistinguishable from "no cap defined" throughout the codebase, an AA (or asset definer relying on AA-computed values) that intends to cap total issuance at a formula-derived value which momentarily evaluates to `0` will instead create a **permanently uncapped asset** - the `objAsset.cap` field is fixed once at asset-definition time (stored in the `assets` table), but the interpretation logic (`||`) means a stored `cap = 0` is forever read back as "uncapped," enabling unlimited re-issuance of what users believe is a fixed-supply, scarce asset.

Note: for plain (non-AA) unit-authored asset definitions, `validateAssetDefinition` in `validation.js` requires `cap` to be `isPositiveInteger` when present, which rejects `0` outright: [6](#0-5) 
This protection does not exist for the AA definition path, where `cap` can be an arbitrary oscript formula whose runtime value is never checked against `isPositiveInteger`/non-zero before being persisted as the asset's cap.

### Impact Explanation
If an AA is designed to issue a capped/scarce asset (e.g., a governance token, a fixed-supply reward token) with a `cap` computed from a formula (data feed, trigger param, prior state var), and that formula can evaluate to `0` under some reachable input, the resulting asset silently becomes uncapped. Any address able to trigger issuance through that AA (or the AA itself acting as definer) can then mint an unbounded amount of the "capped" asset, diluting all holders and breaking the supply guarantee the asset was advertised with. This is a genuine supply-inflation / asset-integrity issue reachable purely by a user sending a trigger to a maliciously or carelessly designed AA — no privileged/operator access is required, matching the required "concrete supply inflation" impact class.

### Likelihood Explanation
This requires an AA definer to write a cap formula that can produce `0` (e.g., `cap: "trigger.data.cap"` or one derived from a data feed/state var that can be zero or missing) - an easy and plausible mistake given nothing in `aa_validation.js` forbids or warns against it, unlike the hard-coded `isPositiveInteger` check that already exists for the non-AA path. Given ocore's stated design intent to give AAs first-class ability to issue their own capped assets (`aa_composer.js` explicitly special-cases `objAsset.cap` to skip consensus-breaking issues), this asymmetry between the AA path and the legacy unit-authored path suggests the omission was not deliberate.

### Recommendation
- In `aa_validation.js`, when evaluating/accepting a `cap` formula for an AA asset definition, disallow (or clamp/reject) a runtime-evaluated value of `0`; require the evaluated cap to satisfy `isPositiveInteger` (mirroring the check already applied to literal `cap` in `validation.js:2735`) at the point the asset is actually created via the AA response.
- Alternatively, change the internal representation so "uncapped" is a distinct sentinel (e.g., `null`/`undefined`) rather than overloading `0`, and update all the `objAsset.cap || X` idioms in `aa_composer.js`, `inputs.js`, `formula/evaluation.js`, and `wallet.js` to explicitly check `objAsset.cap === null` instead of falsy-checking, closing the "0 means infinity" ambiguity system-wide.

### Proof of Concept
1. An AA defines a new asset via an `asset` message where `cap` is a formula, e.g. `cap: "trigger.data.max_supply"`.
2. `aa_validation.js` accepts this because `getFormula(payload.cap) !== null` (lines 235-239) — no check is done on the possible runtime values.
3. A user sends a trigger with `data.max_supply = 0` (or any external input that resolves the formula to `0` at execution time, e.g., a data feed value of `0`).
4. The asset gets created/stored with `cap = 0`.
5. On every subsequent issuance attempt (via `aa_composer.js` `issueAsset()` at lines 1179 and 1195, or via `inputs.js` `issueAsset()` at lines 226-280), `objAsset.cap` is falsy, so the code takes the "uncapped" branch, incrementing `serial_number` and permitting repeated `type: 'issue'` inputs of arbitrary amounts, defeating the intended supply cap.

### Citations

**File:** aa_validation.js (L230-242)
```javascript
					if ("cap" in payload) {
						if (typeof payload.cap === 'number') {
							if (!(isPositiveInteger(payload.cap) && payload.cap <= constants.MAX_CAP))
								return cb2("invalid cap: " + payload.cap);
						}
						else if (typeof payload.cap === 'string') {
							var f = getFormula(payload.cap);
							if (f === null)
								return cb2("bad formula in cap: " + payload.cap);
						}
						else
							return cb2("wrong cap: " + JSON.stringify(payload.cap));
					}
```

**File:** aa_composer.js (L1179-1211)
```javascript
				var issue_amount = objAsset.cap || (target_amount - total_amount);

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
				
				if (objAsset.cap) { // only our AA can issue, no unstable consensus-breaking issues possible
					conn.query("SELECT 1 FROM inputs WHERE type='issue' AND asset=?", [asset], function(rows){
						if (rows.length > 0) // already issued
							return cb2('already issued');
						addIssueInput(1);
					});
				}
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

**File:** inputs.js (L226-280)
```javascript
			if (amount === Infinity && !objAsset.cap) // don't try to create infinite issue
				return onDone(null);
		}
		console.log("will try to issue asset "+asset);
		// for issue, we use full list of addresses rather than spendable addresses
		if (objAsset.issued_by_definer_only && arrAddresses.indexOf(objAsset.definer_address) === -1)
			return finish();
		var issuer_address = objAsset.issued_by_definer_only ? objAsset.definer_address : arrAddresses[0];
		var issue_amount = objAsset.cap || (required_amount - total_amount) || 1; // 1 currency unit in case required_amount = total_amount

		function addIssueInput(serial_number){
			total_amount += issue_amount;
			var input = {
				type: "issue",
				amount: issue_amount,
				serial_number: serial_number
			};
			if (bMultiAuthored)
				input.address = issuer_address;
			var objInputWithProof = {input: input};
			if (objAsset && objAsset.is_private){
				var spend_proof = objectHash.getBase64Hash({
					asset: asset,
					amount: issue_amount,
					denomination: 1,
					address: issuer_address,
					serial_number: serial_number
				});
				var objSpendProof = {spend_proof: spend_proof};
				if (bMultiAuthored)
					objSpendProof.address = input.address;
				objInputWithProof.spend_proof = objSpendProof;
			}
			arrInputsWithProofs.unshift(objInputWithProof);
			var bFound = is_base ? (total_amount > required_amount) : (total_amount >= required_amount);
			bFound ? onDone(arrInputsWithProofs, total_amount) : finish();
		}

		if (objAsset.cap){
			conn.query("SELECT 1 FROM inputs WHERE type='issue' AND asset=?", [asset], function(rows){
				if (rows.length > 0) // already issued
					return finish();
				addIssueInput(1);
			});
		}
		else{
			conn.query(
				"SELECT MAX(serial_number) AS max_serial_number FROM inputs WHERE type='issue' AND asset=? AND address=?",
				[asset, issuer_address],
				function(rows){
					var max_serial_number = (rows.length === 0) ? 0 : rows[0].max_serial_number;
					addIssueInput(max_serial_number+1);
				}
			);
		}
```

**File:** formula/evaluation.js (L1555-1556)
```javascript
							if (field === 'cap') // can be null
								return cb(convertValue(objAsset.cap || 0));
```

**File:** wallet.js (L1833-1845)
```javascript
				if (!objAsset.cap){ // uncapped asset: can be issued from definer_address or from any address
					var and_address = objAsset.issued_by_definer_only ? " AND address="+db.escape(objAsset.definer_address) : '';
					db.query("SELECT address FROM my_addresses WHERE wallet=? "+and_address+" LIMIT 1", [wallet], function(issuer_rows){
						issuer_rows.forEach(issuer_row => {
							issuer_row.total = Infinity;
						});
						var arrNonIssuerAddresses = rows.map(row => row.address);
						issuer_rows = issuer_rows.filter(issuer_row => arrNonIssuerAddresses.indexOf(issuer_row.address) === -1);
						rows = rows.concat(issuer_rows);
						handleFundedAddresses(composer.filterMostFundedAddresses(rows, estimated_amount));
					});
					return;
				}
```

**File:** validation.js (L2735-2736)
```javascript
	if ("cap" in payload && !(isPositiveInteger(payload.cap) && payload.cap <= constants.MAX_CAP))
		return callback("invalid cap");
```
