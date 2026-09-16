### Title
AA Fund Freezing via Mutable Asset `transfer_condition` / `spender_attested` Attestor List Blocking Payments - (File: `validation.js`)

### Summary
Custom assets in ocore can define a `transfer_condition`/`issue_condition` (an oscript expression evaluated on every payment) and/or `spender_attested` with an `attestors` list that the asset **definer can update at any time** via a subsequent `asset_attestors` message. Both mechanisms are re-evaluated for every single payment of the asset, including payments made by an Autonomous Agent (AA). If an asset issuer changes the attestor list (or the referenced condition/oracle state) after users have already deposited that asset into an AA-based protocol (e.g. a lending/vault AA), the AA can become permanently unable to pay the asset back out — exactly analogous to a "pausable ERC-20" blocking repay/withdraw/liquidate in the referenced Sherlock report.

### Finding Description
When a payment message spends or issues a custom asset, `validatePaymentInputsAndOutputs` re-checks two mutable conditions on **every** transaction:

1. **Attestor whitelist** — if `objAsset.spender_attested` is true, all **output** addresses must currently be on the attestor-derived whitelist, and the input owner address must be attested too: [1](#0-0) [2](#0-1) 

2. **Issue/transfer condition** — an arbitrary oscript boolean expression re-evaluated against current chain state (data feeds, addresses, etc.) on every transfer: [3](#0-2) 

Both are defined once at asset creation but are **mutable afterward**: the attestor list can be replaced at any time by an `asset_attestors` message from the definer, and `readAsset`/`loadAssetWithListOfAttestedAuthors` always pulls the **latest** attestor list before evaluating a payment: [4](#0-3) [5](#0-4) 

An AA that accepts such a custom asset (e.g., as collateral or a loan/deposit token in a lending/vault protocol) composes outgoing asset payments without any check that the recipient will remain attested or that the transfer condition will still hold: [6](#0-5) 

If the asset issuer (an actor explicitly in scope — "asset issuer") later removes the AA's address (or the withdrawing user's address) from the attestor list, or causes the `transfer_condition` to evaluate false (e.g., via a linked data feed), any AA response unit carrying that asset payment will fail unit validation with `"some output addresses are not attested"`, `"owner address is not attested"`, or `"transfer or issue condition not satisfied"`. The AA has no mechanism to detect this in advance (oscript formulas cannot query attestor lists or arbitrarily evaluate `Definition.evaluateAssetCondition`), so its bounce logic cannot route around the failure — the response unit is simply rejected by the network.

### Impact Explanation
This directly matches the "AA fund loss or freezing" acceptance criterion: once an AA holds a balance of such an asset for users (deposits, collateral, pending repayments), a subsequent, unilateral change to the asset's attestor list or condition by the definer can permanently prevent the AA from paying that asset back out. Since AA state changes (e.g., debt/balance bookkeeping) are typically applied atomically with the response unit, either:
- The AA still updates internal state as if the payment succeeded and then the unit is rejected/bounced, desynchronizing internal accounting from actual on-chain balances, or
- The AA correctly bounces, but then perpetually fails on every retry, since the underlying condition remains unsatisfied — freezing the deposited/collateral funds inside the AA indefinitely, with no path to recovery through the AA's own logic.

This is a direct on-chain analog of the reported issue (pausable token blocking repay/liquidate), with the same multi-layered impact: depositors cannot withdraw, borrowers cannot repay, and liquidators cannot liquidate positions denominated in the affected asset.

### Likelihood Explanation
Likelihood is moderate: it requires a lending/vault-style AA built on top of a custom (non-base) asset with `spender_attested` or `issue_condition`/`transfer_condition`, and it requires the asset issuer to change the attestor list or underlying condition state after the AA has accepted deposits. This is a realistic scenario for any protocol using custom Obyte assets as collateral/loan tokens whose issuers are third parties (not the protocol itself), which is explicitly one of the actors ocore/Obyte contracts must defend against.

### Recommendation
- AA developers integrating third-party assets should treat `spender_attested`/`transfer_condition`-bearing assets as high risk and avoid using them as core protocol collateral/loan tokens, or
- Introduce a protocol-level mechanism (at the oscript/AA level) to detect stuck balances and allow governance/emergency withdrawal paths that don't rely on the asset's own transfer/attestation gating, and/or
- At the ocore level, expose safe oscript primitives (e.g., a getter to check "would this payment currently satisfy the asset's condition/attestor list") so AAs can pre-validate before committing to state changes tied to an asset payment, preventing accounting desync when the underlying transfer subsequently fails.

### Proof of Concept
1. Asset issuer creates asset `A` with `spender_attested: true` and `attestors: [oracle1]`.
2. A lending/vault AA `L` is deployed accepting asset `A` as collateral/deposit; users send `A` to `L` and `L`'s address (and depositors') are currently attested by `oracle1`.
3. Users deposit `A` into `L`; `L` records balances in its state vars.
4. Asset issuer publishes a new `asset_attestors` message for asset `A`, changing/removing attestors such that `L`'s address (or the intended withdrawal recipient) is no longer attested — validated per: [5](#0-4) 
5. A user triggers `L` to withdraw/repay their `A` balance. `L` composes a payment message with `A` as output per: [6](#0-5) 
6. The resulting response unit fails validation: [1](#0-0) 
— either the AA's bounce leaves it retry-looping forever (since the network no longer attests the output), or if the state update is applied before the bounce, the AA's internal accounting for asset `A` becomes permanently detached from what it can actually pay out, freezing user funds.

### Citations

**File:** validation.js (L2033-2042)
```javascript
		case "asset_attestors":
			if (!isStringOfLength(payload.asset, constants.HASH_LENGTH))
				return callback("invalid asset in attestor list update");
			if (!objValidationState.assocHasAssetAttestors)
				objValidationState.assocHasAssetAttestors = {};
			if (objValidationState.assocHasAssetAttestors[payload.asset])
				return callback("can be only one asset attestor list update per asset");
			objValidationState.assocHasAssetAttestors[payload.asset] = true;
			validateAttestorListUpdate(conn, payload, objUnit, objValidationState, callback);
			break;
```

**File:** validation.js (L2506-2507)
```javascript
							if (objAsset && objAsset.spender_attested && objAsset.arrAttestedAddresses.indexOf(owner_address) === -1)
								return cb("owner address is not attested");
```

**File:** validation.js (L2630-2641)
```javascript
				async.series([
					function(cb){
						if (!objAsset.spender_attested)
							return cb();
						storage.filterAttestedAddresses(
							conn, objAsset, objValidationState.last_ball_mci, arrOutputAddresses, 
							function(arrAttestedOutputAddresses){
								if (arrAttestedOutputAddresses.length !== arrOutputAddresses.length)
									return cb("some output addresses are not attested");
								cb();
							}
						);
```

**File:** validation.js (L2643-2658)
```javascript
					function(cb){
						var arrCondition = bIssue ? objAsset.issue_condition : objAsset.transfer_condition;
						if (!arrCondition)
							return cb();
						Definition.evaluateAssetCondition(
							conn, payload.asset, arrCondition, objUnit, objValidationState, 
							function(cond_err, bSatisfiesCondition){
								if (cond_err)
									return cb(cond_err);
								if (!bSatisfiesCondition)
									return cb("transfer or issue condition not satisfied");
								console.log("validatePaymentInputsAndOutputs with transfer/issue conditions done");
								cb();
							}
						);
					}
```

**File:** storage.js (L1917-1946)
```javascript
		function addAttestorsIfNecessary(byAA = false){
			if (!objAsset.spender_attested)
				return handleAsset(null, objAsset);

			// find latest list of attestors
			const before_last_ball_cond = byAA ? "" : `AND main_chain_index<=${+last_ball_mci} AND is_stable=1`;
			conn.query(
				"SELECT unit FROM asset_attestors CROSS JOIN units USING(unit) \n\
				WHERE asset=? " + before_last_ball_cond + " AND sequence='good' ORDER BY "+ (conf.bLight ? "units.rowid" : "level") + " DESC LIMIT 1",
				[asset],
				function (latest_rows) {
					if (latest_rows.length === 0)
						throw Error("no latest attestor list");
					var latest_attestor_list_unit = latest_rows[0].unit;

					// read the list
					conn.query(
						"SELECT attestor_address FROM asset_attestors CROSS JOIN units USING(unit) \n\
						WHERE asset=? AND unit=? " + before_last_ball_cond + " AND sequence='good'",
						[asset, latest_attestor_list_unit],
						function (att_rows) {
							if (att_rows.length === 0)
								throw Error("no attestors?");
							objAsset.arrAttestorAddresses = att_rows.map(function (att_row) { return att_row.attestor_address; });
							handleAsset(null, objAsset);
						}
					);
				}
			);
		}
```

**File:** aa_composer.js (L1312-1344)
```javascript
				var payload = message.payload;
				if (payload.asset === 'base')
					delete payload.asset;
				var asset = payload.asset || null;
				if (asset === null) {
					if (objBasePaymentMessage)
						return cb("already have base payment");
					objBasePaymentMessage = message;
					// we'll add output addresses later, after possibly removing a send-all output
					return cb(); // skip it for now, we can estimate the fees only after all other messages are in place
				}
				storage.loadAssetWithListOfAttestedAuthors(conn, asset, mci, [address], true, function (err, objAsset) {
					if (err)
						return cb(err);
					assetInfos[asset] = objAsset;
					if (objAsset.fixed_denominations) // will skip it later
						return cb();
					if (objAsset.is_private) // it'll fail validation anyway due to lack of spend_proofs
						return cb("sending private asset from AA");
					completePaymentPayload(payload, 0, function (err) {
						if (err)
							return cb(err);
						addOutputAddresses(payload.outputs);
						if (payload.outputs.length > 0) // send-all output might get removed while being the only output
							try {
								completeMessage(message);
							}
							catch (e) {
								return cb("completeMessage failed: " + e.toString());
							}
						cb();
					});
				});
```
