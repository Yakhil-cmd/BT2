### Title
AA addresses cannot claim earned headers-commission (and witnessing) income, causing bytes to be permanently locked - ([File: aa_composer.js])

### Summary
This is an analog of the "no support for rebasing tokens" issue: a smart contract (here, an Autonomous Agent, "AA") has an internal accounting of its funds that is decoupled from the real, network-level balance the address is entitled to. Just as the ERC-20 Vault only knows about the amount it explicitly received and cannot account for a rebasing token's underlying balance growth, an ocore AA only knows about, and can only spend, the funds that arrived to it via ordinary `payment` outputs — never the bytes it may have separately earned as `headers_commission` (or `witnessing`) income for authoring units that end up on the DAG.

### Finding Description
Every unit author (including an AA, which authors its own response units) can earn "headers commission" — a share of a parent unit's `headers_commission` when the author's unit becomes the winning ("best") child, or an explicit share via `earned_headers_commission_recipients` [1](#0-0) . This income is computed and stored per-address in the `headers_commission_outputs` table by `calcHeadersCommissions` [2](#0-1) [3](#0-2) , and it is real, spendable, byte balance belonging to the address — spendable through a dedicated `type: "headers_commission"` input that is validated in `validation.js` and constructed in `inputs.js` for ordinary wallet-composed payments [4](#0-3) [5](#0-4) .

However, AA response units are never built through this normal wallet-composition path. `aa_composer.js`'s own funding logic, `completePaymentPayload`/`readStableOutputs`, only ever selects spendable coins from the plain `outputs` table by address/asset — it never queries `headers_commission_outputs` (or `witnessing_outputs`) and never constructs a `type: "headers_commission"`/`"witnessing"` input [6](#0-5) . Likewise, the AA's internal ledger of what it "has" — `aa_balances`, populated and read via `updateInitialAABalances`/`updateFinalAABalances`, and exposed to oscript via the `balance[asset]` formula operator — is built exclusively from the `outputs` table, never from `headers_commission_outputs`/`witnessing_outputs` [7](#0-6) [8](#0-7) . The network-wide consistency check `checkBalances`, which is meant to guarantee `aa_balances` always matches the AA's real spendable funds, also only sums the `outputs` table, confirming this exclusion is a designed invariant, not an accident [9](#0-8) .

Since an AA address is a normal address that authors real units for every response it sends, and since responses that become the "best child" of their parent (or that specify `earned_headers_commission_recipients`) legitimately accrue headers-commission income to that AA address, this income is credited to the AA's address in `headers_commission_outputs` exactly like it would be for a wallet address — but the AA has no mechanism in oscript, and no code path in `aa_composer.js`, to ever spend it. The bytes are permanently stranded at that address: they can never enter `aa_balances`, are invisible to `balance[base]`, and can never be included as inputs by the AA's own unit-composition logic.

### Impact Explanation
Any AA address that produces multiple competing/child units over time (a common and unavoidable occurrence for active AAs, since headers-commission distribution is a normal DAG mechanic, not something an AA author can opt out of) will accumulate unspendable bytes at its own address. This is a direct, permanent loss of funds belonging to the AA/its users, analogous to airdropped or rebasing-token balances being unreachable in the reported vault issue — except here it is native protocol-level commission income, which is a normal and expected occurrence for busy AAs (not an edge case like an airdrop). Because AAs are frequently used to hold and manage pooled user funds, this leaked income effectively represents value that no one — not even the AA's own logic — can ever retrieve, matching the "funds locked forever" impact described in the source report.

### Likelihood Explanation
Headers-commission distribution to unit authors happens automatically for every stable unit, based on best-child selection in the DAG (`getWinnerInfo`) [10](#0-9) , so any sufficiently active AA (one that produces enough response units to occasionally win headers-commission from a parent) will accrue this income without any attacker action required. This is a systemic, always-present code-path gap rather than a contrived exploit, making the likelihood high for any AA with meaningful transaction volume.

### Recommendation
Extend `aa_composer.js`'s payment-composition logic (`completePaymentPayload`/`readStableOutputs`/`readUnstableOutputsSentByAAs`) to also consider `headers_commission_outputs` and `witnessing_outputs` belonging to the AA address, constructing the corresponding `type: "headers_commission"`/`"witnessing"` inputs (mirroring `inputs.js`'s `addHeadersCommissionInputs`/`addWitnessingInputs`/`addMcInputs`) when funding an AA's outgoing payment. Correspondingly, `updateInitialAABalances`/`updateFinalAABalances` and the `balance[]` formula operator should be updated to include this commission income in `aa_balances`, and `checkBalances` should be updated to include these sources in its reconciliation query, so that AA-earned commissions become visible and spendable rather than permanently stranded.

### Proof of Concept
Not directly executable from static analysis alone, but the code path is traceable:
1. Deploy an AA that frequently responds to triggers, so its response units regularly become authors of new units on the DAG.
2. Over time, some of these AA response units become "best child" of their parent units (per `getWinnerInfo`) and receive headers-commission credit, or the AA explicitly sets `earned_headers_commission_recipients` naming itself, recorded into `headers_commission_outputs` for the AA's address [3](#0-2) .
2. Confirm via `SELECT * FROM headers_commission_outputs WHERE address=<aa_address>` that the AA address has a positive, unspent balance.
3. Trigger the AA to send out all of its bytes (e.g., an oscript `{amount: undefined}` "send all" output, or `balance[base]`); observe that the amount sent never includes the headers-commission balance, because `readStableOutputs` in `aa_composer.js` only reads the `outputs` table [6](#0-5)  and `balance[base]` is computed purely from `aa_balances`/`trigger.outputs` [8](#0-7) .
4. The headers-commission balance remains permanently in `headers_commission_outputs` with `is_spent=0` and is never reachable by any AA-authored unit, since there is no code path in `aa_composer.js` producing a `type: "headers_commission"` input.

### Citations

**File:** composer.js (L248-253)
```javascript
	if (params.earned_headers_commission_recipients) // it needn't be already sorted by address, we'll sort it now
		objUnit.earned_headers_commission_recipients = params.earned_headers_commission_recipients.concat().sort(function(a,b){
			return ((a.address < b.address) ? -1 : 1);
		});
	else if (bMultiAuthored) // by default, the entire earned hc goes to the change address
		objUnit.earned_headers_commission_recipients = [{address: arrChangeOutputs[0].address, earned_headers_commission_share: 100}];
```

**File:** headers_commission.js (L12-19)
```javascript
function calcHeadersCommissions(conn, onDone){
	// we don't require neither source nor recipient to be majority witnessed -- we don't want to return many times to the same MC index.
	console.log("will calc h-comm");
	if (max_spendable_mci === null) // first calc after restart only
		return initMaxSpendableMci(conn, function(){ calcHeadersCommissions(conn, onDone); });
	
	// max_spendable_mci is old, it was last updated after previous calc
	var since_mc_index = max_spendable_mci;
```

**File:** headers_commission.js (L221-237)
```javascript
		function(cb){
			conn.query(
				"INSERT INTO headers_commission_outputs (main_chain_index, address, amount) \n\
				SELECT main_chain_index, address, SUM(amount) FROM units CROSS JOIN headers_commission_contributions USING(unit) \n\
				WHERE main_chain_index>? \n\
				GROUP BY main_chain_index, address",
				[since_mc_index],
				function(){
					if (conf.bFaster)
						return cb();
					conn.query("SELECT DISTINCT main_chain_index FROM units CROSS JOIN headers_commission_contributions USING(unit) WHERE main_chain_index>?", [since_mc_index], function(contrib_rows){
						if (contrib_rows.length === 1 && contrib_rows[0].main_chain_index === since_mc_index+1 || since_mc_index === 0)
							return cb();
						throwError("since_mc_index="+since_mc_index+" but contributions have mcis "+contrib_rows.map(function(r){ return r.main_chain_index}).join(', '));
					});
				}
			);
```

**File:** headers_commission.js (L249-258)
```javascript
function getWinnerInfo(arrChildren){
	if (arrChildren.length === 1)
		return arrChildren[0];
	if (arrChildren.length === 0)
		throw Error("no children for hc");
	arrChildren.forEach(function(child){
		child.hash = crypto.createHash("sha1").update(child.child_unit + child.next_mc_unit, "utf8").digest("hex");
	});
	arrChildren.sort(function(a, b){ return ((a.hash < b.hash) ? -1 : 1); });
	return arrChildren[0];
```

**File:** inputs.js (L173-220)
```javascript
	function addHeadersCommissionInputs(){
		addMcInputs("headers_commission", HEADERS_COMMISSION_INPUT_SIZE + (bWithKeys ? HEADERS_COMMISSION_INPUT_KEYS_SIZE : 0),
			headers_commission.getMaxSpendableMciForLastBallMci(last_ball_mci), addWitnessingInputs);
	}

	function addWitnessingInputs(){
		addMcInputs("witnessing", WITNESSING_INPUT_SIZE + (bWithKeys ? WITNESSING_INPUT_KEYS_SIZE : 0), paid_witnessing.getMaxSpendableMciForLastBallMci(last_ball_mci), issueAsset);
	}

	function addMcInputs(type, input_size, max_mci, onStillNotEnough){
		var address_size = ADDRESS_SIZE + (bWithKeys ? ADDRESS_KEY_SIZE : 0);
		var full_input_size = input_size + (bMultiAuthored ? address_size : 0);
		async.eachSeries(
			arrAddresses,
			function(address, cb){
				var target_amount = net_required_amount - total_amount + full_input_size + getOversizeFee(size + full_input_size);
				mc_outputs.findMcIndexIntervalToTargetAmount(conn, type, address, max_mci, target_amount, {
					ifNothing: cb,
					ifFound: function(from_mc_index, to_mc_index, earnings, bSufficient){
						if (earnings === 0)
							throw Error("earnings === 0");
						if (earnings <= full_input_size) // skip net negative MC inputs
							return cb();
						var input = {
							type: type,
							from_main_chain_index: from_mc_index,
							to_main_chain_index: to_mc_index
						};
						if (bMultiAuthored)
							input.address = address;
						arrInputsWithProofs.push({input: input});
						total_amount += earnings;
						net_required_amount += full_input_size;
						size += full_input_size;
						required_amount = net_required_amount + getOversizeFee(size);
						(total_amount > required_amount)
							? cb("found") // break eachSeries
							: cb(); // try next address
					}
				});
			},
			function(err){
				if (!err)
					console.log(arrAddresses+" "+type+": got only "+total_amount+" out of required "+required_amount);
				(err === "found") ? onDone(arrInputsWithProofs, total_amount) : onStillNotEnough();
			}
		);
	}
```

**File:** validation.js (L2579-2600)
```javascript
					mc_outputs.readNextSpendableMcIndex(conn, type, address, objValidationState.arrConflictingUnits, function(next_spendable_mc_index){
						if (input.from_main_chain_index < next_spendable_mc_index)
							return cb(type + " ranges must not overlap"); // gaps allowed, in case a unit becomes bad due to another address being nonserial
						var max_mci = (type === "headers_commission") 
							? headers_commission.getMaxSpendableMciForLastBallMci(objValidationState.last_ball_mci)
							: paid_witnessing.getMaxSpendableMciForLastBallMci(objValidationState.last_ball_mci);
						if (input.to_main_chain_index > max_mci)
							return cb(type+" to_main_chain_index is too large");

						var calcFunc = (type === "headers_commission") ? mc_outputs.calcEarnings : paid_witnessing.calcWitnessEarnings;
						calcFunc(conn, type, input.from_main_chain_index, input.to_main_chain_index, address, {
							ifError: function(err){
								throw Error(err);
							},
							ifOk: function(commission){
								if (commission === 0)
									return cb("zero "+type+" commission");
								total_input += commission;
								checkInputDoubleSpend(cb);
							}
						});
					});
```

**File:** aa_composer.js (L474-541)
```javascript
	// add the coins received in the trigger
	function updateInitialAABalances(cb) {
		let bOverflow = false;
		if (trigger_opts.assocBalances) {
			if (!trigger_opts.assocBalances[address])
				trigger_opts.assocBalances[address] = {};
			originalBalances = _.cloneDeep(trigger_opts.assocBalances);
			for (var asset in trigger.outputs) {
				trigger_opts.assocBalances[address][asset] = (trigger_opts.assocBalances[address][asset] || 0) + trigger.outputs[asset];
				if (trigger_opts.assocBalances[address][asset] > MAX_BALANCE)
					bOverflow = true;
			}
			objValidationState.assocBalances = trigger_opts.assocBalances;
			byte_balance = trigger_opts.assocBalances[address].base || 0;
			storage_size = 0;
			return cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
		}
		objValidationState.assocBalances[address] = {};
		var arrAssets = Object.keys(trigger.outputs);
		conn.query(
			"SELECT asset, balance FROM aa_balances WHERE address=?",
			[address],
			function (rows) {
				var arrQueries = [];
				// 1. update balances of existing assets
				rows.forEach(function (row) {
					if (constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
						reintroduceBalanceBug(address, row);
					if (!trigger.outputs[row.asset]) {
						objValidationState.assocBalances[address][row.asset] = row.balance;
						return;
					}
					conn.addQuery(
						arrQueries,
						"UPDATE aa_balances SET balance=balance+? WHERE address=? AND asset=? ",
						[trigger.outputs[row.asset], address, row.asset]
					);
					objValidationState.assocBalances[address][row.asset] = row.balance + trigger.outputs[row.asset];
					if (objValidationState.assocBalances[address][row.asset] > MAX_BALANCE)
						bOverflow = true;
				});
				// 2. insert balances of new assets
				var arrExistingAssets = rows.map(function (row) { return row.asset; });
				var arrNewAssets = _.difference(arrAssets, arrExistingAssets);
				if (arrNewAssets.length > 0) {
					var arrValues = arrNewAssets.map(function (asset) {
						objValidationState.assocBalances[address][asset] = trigger.outputs[asset];
						return "(" + conn.escape(address) + ", " + conn.escape(asset) + ", " + trigger.outputs[asset] + ")"
					});
					conn.addQuery(arrQueries, "INSERT INTO aa_balances (address, asset, balance) VALUES "+arrValues.join(', '));
				}
				byte_balance = objValidationState.assocBalances[address].base;
				if (trigger.outputs.base === undefined && mci < constants.aa3UpgradeMci) // bug-compatible
					byte_balance = undefined;
				if (!bSecondary)
					conn.addQuery(arrQueries, "SAVEPOINT initial_balances");
				async.series(arrQueries, function () {
					conn.query("SELECT storage_size FROM aa_addresses WHERE address=?", [address], function (rows) {
						if (rows.length === 0)
							throw Error("AA not found? " + address);
						storage_size = rows[0].storage_size;
						objValidationState.storage_size = storage_size;
						cb(bOverflow && mci >= constants.pemCurvesFixMci ? "balance overflow" : null);
					});
				});
			}
		);
	}
```

**File:** aa_composer.js (L1140-1155)
```javascript
			function readStableOutputs(handleRows) {
			//	console.log('--- readStableOutputs');
				if (asset && assetInfos[asset].auto_destroy && assetInfos[asset].definer_address === address && mci >= constants.pemCurvesFixMci)
					return handleRows([]);
				// byte outputs less than 60 bytes (which are net negative) are ignored to prevent dust attack: spamming the AA with very small outputs so that the AA spends all its money for fees when it tries to respond
				conn.query(
					"SELECT unit, message_index, output_index, amount, output_id \n\
					FROM outputs \n\
					CROSS JOIN units USING(unit) \n\
					WHERE address=? AND asset"+(asset ? "="+conn.escape(asset) : " IS NULL AND amount>=" + FULL_TRANSFER_INPUT_SIZE)+" AND is_spent=0 \n\
						AND sequence='good' AND main_chain_index<=? \n\
						AND output_id NOT IN("+(arrUsedOutputIds.length === 0 ? "-1" : arrUsedOutputIds.join(', '))+") \n\
					ORDER BY main_chain_index, unit, output_index", // sort order must be deterministic
					[address, mci], handleRows
				);
			}
```

**File:** aa_composer.js (L1963-1979)
```javascript
				var sql_create_temp = "CREATE TEMPORARY TABLE aa_outputs_balances ( \n\
					address CHAR(32) NOT NULL, \n\
					asset CHAR(44) NOT NULL, \n\
					calculated_balance BIGINT NOT NULL, \n\
					PRIMARY KEY (address, asset) \n\
				)" + (conf.storage === 'mysql' ? " ENGINE=MEMORY DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci" : "");
				var sql_fill_temp = "INSERT INTO aa_outputs_balances (address, asset, calculated_balance) \n\
					SELECT address, IFNULL(asset, 'base'), SUM(CAST(amount AS DOUBLE)) \n\
					FROM aa_addresses \n\
					CROSS JOIN outputs USING(address) \n\
					CROSS JOIN units ON outputs.unit=units.unit \n\
					LEFT JOIN assets ON outputs.asset=assets.unit \n\
					WHERE is_spent=0 AND sequence='good' AND ( \n\
						is_stable=1 \n\
						OR is_stable=0 AND is_aa_response=1 \n\
					) AND (is_private=0 OR is_private IS NULL) \n\
					GROUP BY address, asset";
```

**File:** formula/evaluation.js (L1510-1528)
```javascript
				function readBalance(param_address, bal_asset, cb2) {
					if (bal_asset !== 'base' && !ValidationUtils.isValidBase64(bal_asset, constants.HASH_LENGTH))
						return setFatalError('bad asset ' + bal_asset, { arr }, false, cb);

					if (!objValidationState.assocBalances[param_address])
						objValidationState.assocBalances[param_address] = {};
					var balance = objValidationState.assocBalances[param_address][bal_asset];
					if (balance !== undefined)
						return cb2(new Decimal(balance));
					conn.query(
						"SELECT balance FROM aa_balances WHERE address=? AND asset=? ",
						[param_address, bal_asset],
						function (rows) {
							balance = rows.length ? rows[0].balance : 0;
							objValidationState.assocBalances[param_address][bal_asset] = balance;
							cb2(new Decimal(balance));
						}
					);
				}
```
