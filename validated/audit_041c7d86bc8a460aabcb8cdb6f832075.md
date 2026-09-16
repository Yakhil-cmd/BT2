### Title
Spot-price AMM valuation in AA `balance[]`/getter reads enables same-unit price manipulation for collateral/valuation logic - ([File: test/samples/uniswap_like_market_maker.oscript])

### Summary
The Hegic/Sharwa exploit worked because collateral was valued from a manipulable, unprotected spot price (a thin Uniswap V3 pool) read inside the same atomic flash-loan transaction that used the manipulated value to over-borrow. Ocore's Autonomous Agent (AA) formula language provides the exact building blocks for an analogous pattern: an AMM-style AA computes its "price" purely from its own instantaneous reserve balances (`balance[asset]`, `balance[base]`), and any other AA can read that same value through cross-address balance/getter primitives — all executable atomically within a single posted unit before any external arbitrage or oracle correction can occur.

### Finding Description
The reference AMM AA computes its exchange price directly from live reserves with no time-weighting, external oracle, or manipulation resistance: [1](#0-0) [2](#0-1) 

Any second AA can read this same instantaneous, unprotected reserve state of another AA address via the `balance[address][asset]` formula primitive, which queries the live `aa_balances` table (or the in-memory `assocBalances` cache during trigger processing) with no stability or staleness requirement: [3](#0-2) 

Or via a synchronous cross-AA getter call, which executes the target AA's `getters` formula (which can expose `balance[...]` or any state derived from it) in the caller's own trigger-processing pipeline: [4](#0-3) 

Crucially, ocore explicitly supports and processes multiple AA triggers stemming from a single unit sequentially, with each trigger's balance changes committed before the next trigger in the same MCI runs: [5](#0-4) [6](#0-5) 

This is the atomicity primitive equivalent to an EVM flash-loan/flash-swap-then-consume pattern: a single unposted unit can contain (1) a large swap into/out of an AMM AA that shifts its `balance[asset]`/`balance[base]` ratio, and (2) a payment/trigger to a second "consumer" AA (e.g. a lending/valuation/insurance AA) whose logic reads the first AA's manipulated reserve ratio via `balance[amm_address][asset]` or a getter call, uses it to price collateral or determine a payout, and then a further message can reverse the initial swap — all within the same atomic unit, before any other unit can be interleaved to arbitrage the price back.

### Impact Explanation
Any AA design that prices collateral, redemption, or issuance amounts from another AA's live reserve ratio (exactly the pattern demonstrated in ocore's own reference AMM sample) is exposed to atomic spot-price manipulation analogous to the Hegic incident: an attacker can inflate or deflate the reported price within a single unit, cause a consumer AA to mint/pay out based on the distorted price, and reverse the manipulation in the same unit, extracting funds without providing real economic value. This is a fund-loss vector for any AA that composes with another AA's balance-derived spot price as an oracle, reachable by any unprivileged unit poster/AA trigger sender.

### Likelihood Explanation
The primitives (`balance[address][asset]` cross-reads, cross-AA getter calls, and same-unit sequential multi-AA triggering) are core, intentional and documented AA features — not edge-case bugs — and the ocore sample library itself ships an AMM design that derives price solely from spot reserves. Any developer following this documented pattern for a lending/insurance/valuation AA that reads another AA's balance as a price feed inherits the vulnerability, and exploitation requires only composing and posting a single ordinary unit with the appropriate payment/trigger messages — no privileged access, network position, or off-chain infrastructure needed.

### Recommendation
Do not treat a single AA's instantaneous `balance[asset]`/`balance[base]` ratio as a manipulation-resistant price oracle. AA authors composing valuation logic across AAs (lending, collateral, redemption) should require external, TWAP-like, or multi-block/multi-source data feeds (`data_feed[[...]]`) rather than another AA's live spot balances, and should avoid trusting a same-unit reserve ratio read from a counterpart AA whose balance can be moved within the same atomic trigger chain. Consider documenting this risk prominently in the ocore AA/oscript guides and reference AMM samples (e.g., `uniswap_like_market_maker.oscript`) so third-party AA authors do not replicate the spot-price-as-oracle anti-pattern in fund-bearing AAs.

### Proof of Concept
1. Deploy `AMM_AA` per `test/samples/uniswap_like_market_maker.oscript`, seeded with modest reserves of `base` and `$asset` (a thin pool, mirroring the thin USDC/USDC.e pool in the Hegic incident).
2. Deploy `Consumer_AA`, whose logic includes `$price = balance[AMM_AA][$asset] / balance[AMM_AA][base]` (via `formula/evaluation.js` `balance[address][asset]`, or via a getter call into `AMM_AA` per `formula/evaluation.js:3289-3377`) and uses `$price` to size a payout/loan/mint to the trigger address.
3. Post a single unit containing three messages to the network:
   - Message 1: large payment output to `AMM_AA` swapping bytes for `$asset` (or vice versa), distorting `$asset_balance / $bytes_balance`.
   - Message 2: payment output to `Consumer_AA`, whose trigger fires after message 1's balance update is committed (per `main_chain.js:1691-1706` / `aa_composer.js:59-89` sequential same-MCI trigger processing), causing `Consumer_AA` to compute an inflated/deflated `$price` and issue an outsized payout.
   - Message 3 (optional, in a follow-up unit or same unit if AMM logic permits): reverse the initial swap in `AMM_AA` to restore reserves, minimizing attacker cost.
4. Observe that `Consumer_AA` pays out based on the manipulated spot ratio rather than a manipulation-resistant price, replicating the Hegic/Sharwa collateral over-valuation exploit within ocore's AA execution model.

### Citations

**File:** test/samples/uniswap_like_market_maker.oscript (L35-47)
```text
				init: `{
					$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
					$bytes_balance = balance[base] - trigger.output[[asset=base]];
					if ($asset_balance == 0 OR $bytes_balance == 0){ // initial deposit
						$issue_amount = balance[base];
						return;
					}
					$current_ratio = $asset_balance / $bytes_balance;
					$expected_asset_amount = round($current_ratio * trigger.output[[asset=base]]);
					if ($expected_asset_amount != trigger.output[[asset=$asset]])
						bounce('wrong ratio of amounts, expected ' || $expected_asset_amount || ' of asset');
					$investor_share_of_prev_balance = trigger.output[[asset=base]] / $bytes_balance;
					$issue_amount = round($investor_share_of_prev_balance * var['mm_asset_outstanding']);
```

**File:** test/samples/uniswap_like_market_maker.oscript (L104-111)
```text
				init: `{
					$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
					$bytes_balance = balance[base] - trigger.output[[asset=base]];
					// other formula can be used for product, e.g. $asset_balance * $bytes_balance ^ 2
					$p = $asset_balance * $bytes_balance;
					$new_asset_balance = round($p / balance[base]);
					$amount = $asset_balance - $new_asset_balance; // we can deduct exchange fees here
				}`,
```

**File:** formula/evaluation.js (L1480-1528)
```javascript
			case 'var':
			case 'balance':
				var param1 = arr[1];
				var param2 = arr[2];
				evaluate(param1, function (evaluated_param1) {
					if (fatal_error)
						return cb(false);
					if (typeof evaluated_param1 !== 'string')
						return setFatalError("1st var name is not a string: " + evaluated_param1, { arr }, false, cb);
					if (op === 'var' && !evaluated_param1.isWellFormed())
						return setFatalError("state var name not well formed: " + evaluated_param1, { arr }, false, cb);
					if (param2 === null)
						return ((op === 'var') ? readVar(address, evaluated_param1, cb) : readBalance(address, evaluated_param1, cb));
					// then, the 1st param is the address of an AA whose state or balance we are going to query
					var param_address = evaluated_param1;
					if (!ValidationUtils.isValidAddress(param_address))
						return setFatalError("var address is invalid: " + param_address, { arr }, false, cb);
					evaluate(param2, function (evaluated_param2) {
						if (fatal_error)
							return cb(false);
						if (typeof evaluated_param2 !== 'string')
							return setFatalError("2nd var name is not a string: " + evaluated_param2, { arr }, false, cb);
						if (op === 'var' && !evaluated_param2.isWellFormed())
							return setFatalError("state var name not well formed: " + evaluated_param2, { arr }, false, cb);
						(op === 'var')
							? readVar(param_address, evaluated_param2, cb)
							: readBalance(param_address, evaluated_param2, cb);
					});
				});

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

**File:** formula/evaluation.js (L3289-3377)
```javascript
function callGetter(conn, aa_address, getter, args, stateVars, objValidationState, astTrace, xpath, callerInfo, cb) {
	var i = 0;
	var locals = {};
	function getNextArgName() {
		i++;
		while (locals['arg' + i])
			i++;
		return 'arg' + i;
	}

	function addAstTrace(value) {
		if (astTrace) {
			astTrace.push(value);
		}
	}

	// no need to cloneDeep, we need to rewrite only storage size, assocBalances cache can be updated by reference
	let objGetterValidationState = _.clone(objValidationState);
	storage.readBaseAADefinitionAndParams(conn, aa_address, objValidationState.last_ball_mci, function (arrBaseDefinition, params, storage_size) {
		if (!arrBaseDefinition)
			return cb("remote AA not found: " + aa_address);
		// rewrite storage size with the storage size of the AA being called
		objGetterValidationState.storage_size = storage_size;
		var f = getFormula(arrBaseDefinition[1].getters);
		const caller_aa = callerInfo && callerInfo.caller_aa;
		const call_line = callerInfo && callerInfo.call_line;
		const call_xpath = callerInfo && callerInfo.call_xpath;

		addAstTrace({ system: 'enter to getters', aa: aa_address, formula: f, caller_aa, call_line, call_xpath });

		var opts = {
			conn: conn,
			formula: f,
			trigger: null,
			params: params,
			locals: locals,
			stateVars: stateVars,
			responseVars: null,
			bStatementsOnly: true,
			objValidationState: objGetterValidationState,
			address: aa_address
		};
		exports.evaluate(opts, astTrace, xpath, function (err, res) {
			if (res === null) 
				return cb(err.formattedError || "formula " + f + " failed: " + err);
			if (!hasOwnProperty(locals, getter))
				return cb("no such getter: " + JSON.stringify(getter));
			if (!(locals[getter] instanceof Func))
				return cb(getter + " is not a function");
			if (typeof args === 'function') // callback function passed instead of args
				args = args(locals[getter]);
			if (!Array.isArray(args))
				throw Error("args is not an array");
			var argNames = [];
			args.forEach(arg => {
				var arg_name = getNextArgName();
				argNames.push('$' + arg_name);
				assignField(locals, arg_name, toOscriptType(arg));
			});
			var call_formula = '$' + getter + '(' + argNames.join(', ') + ')';
			var call_opts = {
				conn: conn,
				formula: call_formula,
				trigger: null,
				params: params,
				locals: locals,
				stateVars: stateVars,
				responseVars: null,
				bObjectResultAllowed: true,
				objValidationState: objGetterValidationState,
				address: aa_address
			};
			exports.evaluate(call_opts, astTrace, xpath, function (err, res) {
				if (res === null) {
					addAstTrace({ system: 'error in getter', aa: aa_address, formula: opts.formula, getter: getter });
					return cb(err.formattedError || "formula " + call_formula + " failed: " + err);
				}
				// fractional and large numbers are returned as strings, attempt to convert back
				if (typeof res === 'string') {
					var f = string_utils.toNumber(res);
					if (f !== null)
						res = f;
				}
				objValidationState.count_signed_packages = objGetterValidationState.count_signed_packages;
				cb(null, toOscriptType(res));
			});
		});
	});
}
```

**File:** main_chain.js (L1691-1706)
```javascript
	function handleAATriggers() {
		// a single unit can send to several AA addresses
		// a single unit can have multiple outputs to the same AA address, even in the same asset
		const mci_column = mci >= constants.pemCurvesFixMci ? 'aa_addresses.mci' : 'aa_definition_units.main_chain_index';
		conn.query(
			"SELECT DISTINCT address, definition, units.unit, units.level \n\
			FROM units \n\
			CROSS JOIN outputs USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			LEFT JOIN assets ON asset=assets.unit \n\
			CROSS JOIN units AS aa_definition_units ON aa_addresses.unit=aa_definition_units.unit \n\
			WHERE units.main_chain_index = ? AND units.sequence = 'good' AND (outputs.asset IS NULL OR is_private=0) \n\
				AND NOT EXISTS (SELECT 1 FROM unit_authors CROSS JOIN aa_addresses USING(address) WHERE unit_authors.unit=units.unit) \n\
				AND " + mci_column + "<=? \n\
			ORDER BY units.level, units.unit, address", // deterministic order
			[mci, mci],
```

**File:** aa_composer.js (L59-89)
```javascript
function handleAATriggers(onDone) {
	if (!onDone)
		return new Promise(resolve => handleAATriggers(resolve));
	mutex.lock(['aa_triggers'], function (unlock) {
		db.query(
			"SELECT aa_triggers.mci, aa_triggers.unit, address, definition \n\
			FROM aa_triggers \n\
			CROSS JOIN units USING(unit) \n\
			CROSS JOIN aa_addresses USING(address) \n\
			ORDER BY aa_triggers.mci, level, aa_triggers.unit, address",
			function (rows) {
				var arrPostedUnits = [];
				async.eachSeries(
					rows,
					function (row, cb) {
						console.log('handleAATriggers', row.unit, row.mci, row.address);
						var arrDefinition = JSON.parse(row.definition);
						handlePrimaryAATrigger(row.mci, row.unit, row.address, arrDefinition, arrPostedUnits, cb);
					},
					function () {
						arrPostedUnits.forEach(function (objUnit) {
							eventBus.emit('new_aa_unit', objUnit);
						});
						unlock();
						onDone();
					}
				);
			}
		);
	});
}
```
