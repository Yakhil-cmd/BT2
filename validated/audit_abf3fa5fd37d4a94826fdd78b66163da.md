Confirmed: `data_feed` messages have no permission restriction — any address can post an arbitrary `app: "data_feed"` message with any feed name/value, validated only for size/format at `validation.js:1925-1952`, and stored keyed by `author_addresses` at `main_chain.js:1587-1617` (`addDataFeeds`). Any AA can then be pointed at that attacker-controlled address as an "oracle" because the `oracles` parameter of `data_feed[[...]]`/`in_data_feed[[...]]` is a general formula, not a compile-time-fixed literal — this is proven by the passing test `formula - datafeed: oracle address from input` [1](#0-0)  which resolves `oracles=input[[asset=base]].address` at runtime. Enforcement in `formula/evaluation.js` only checks that the resolved string parses into valid Obyte addresses [2](#0-1)  and, for `in_data_feed`, similarly at [3](#0-2) ; it never restricts the address to a compile-time constant. This is unlike `remote_aa`, where the validator explicitly rejects a non-constant/formula-derived address [4](#0-3)  and [5](#0-4) .

### Title
AA definitions that source a `data_feed`/`in_data_feed` "oracles" address from trigger-controlled data allow a trigger sender to forge the price/condition and drain AA funds - (File: `formula/evaluation.js`, `formula/validation.js`, `data_feeds.js`)

### Summary
The `data_feed[[...]]` and `in_data_feed[[...]]` oscript primitives resolve their `oracles` parameter as an arbitrary formula, evaluated at trigger-processing time, rather than requiring it to be a fixed literal known at AA-definition validation time. Combined with the fact that posting a `data_feed` message is permissionless (any address may author one), an AA author who (intentionally or by mistake) lets the oracle address be influenced by trigger/input data creates a path for the trigger sender to substitute their own address as the "oracle," pre-post whatever feed value benefits them, and have the AA treat it as ground truth for a price check, slippage check, or other condition that gates a payment — draining the AA's balance. This is the same bug class as the reported Unstoppable DCA issue, where the caller controls which price source (Uniswap pool) is consulted for `min_amount_out`.

### Finding Description
`data_feed`/`in_data_feed` evaluation in `formula/evaluation.js` requires `oracles.value` to be a string that splits into valid addresses [6](#0-5) , and identically for `in_data_feed` [3](#0-2) . Nothing requires this string to be a constant baked into the AA definition — it is evaluated from `params.oracles.value`, an arbitrary sub-formula, at line 672 (`evaluate(params[param_name].value, ...)`) [7](#0-6) . The static AA-definition validator (`formula/validation.js` `validateDataFeed`) only enforces the address-format check when the value happens to already be a literal string at validation time; if it's a non-literal expression, the branch is skipped entirely (`if (typeof value !== 'string') continue;`) [8](#0-7) . The existing test suite explicitly demonstrates and accepts `oracles=input[[asset=base]].address` resolving successfully from trigger-supplied payment input at evaluation time [1](#0-0) .

By contrast, for `remote_aa` calls the language deliberately forbids a non-constant address, throwing a validation error for a computed or conditionally-assigned address [9](#0-8)  enforced in `parseRemoteAA` [5](#0-4) . No equivalent restriction exists for the `oracles` field of `data_feed`/`in_data_feed`.

Separately, posting a `data_feed` message carries no special authorization: `validateMessage` in `validation.js` only checks payload size/format for `app: "data_feed"`, with no ACL over which addresses may act as oracles [10](#0-9) , and stabilized feeds are indexed simply by the author addresses of the posting unit in `addDataFeeds` [11](#0-10) . Any account can therefore become a "data feed provider" for any feed name/value of their choosing.

The concrete danger arises in AA logic (analogous to the DEX/DCA contract in the reported bug) that composes the oracle address from trigger data instead of hardcoding a trusted, definer-controlled address, e.g. `data_feed[[oracles=trigger.data.oracle, feed_name='PRICE', ...]]` used to compute a payout or slippage bound. Because the trigger sender fully controls `trigger.data`, they can name their own address as the oracle, pre-post a favorable `data_feed` value from that address in an earlier unit, then send the trigger; the AA reads the attacker-fabricated value as truth and pays out accordingly — the exact analog of the attacker-controlled TWAP pool in the reported Vyper contract.

### Impact Explanation
Any AA whose fund-release, pricing, or slippage logic derives the `oracles` address for `data_feed`/`in_data_feed` from trigger-controlled input (a pattern the language explicitly allows and tests for) can have its price/condition data forged by the trigger sender, leading to outright theft of the AA's balance or arbitrary bypass of price-based safety checks. This is a High-severity fund-loss vector for any AA built on this pattern, mirroring "theft of order value in entirety" from the source report.

### Likelihood Explanation
Likelihood depends on AA authors using a dynamic/attacker-influenced `oracles` expression, which is not prevented by protocol validation and is demonstrably supported and tested behavior of the formula engine [1](#0-0) . Given `data_feed`/`in_data_feed` are commonly used in price-dependent AAs (see `test/samples/futures_contract.oscript` using `data_feed[[oracles='X55IWSNMHNDUIYKICDW3EOYAWHRUKANP', ...]]`) [12](#0-11) , and since nothing in `aa_validation.js`/`formula/validation.js` flags or disallows a non-constant `oracles` expression the way it does for `remote_aa`, this is a realistic and easy-to-introduce footgun rather than a purely theoretical one.

### Recommendation
Mirror the `remote_aa` restriction: require the `oracles` parameter of `data_feed` and `in_data_feed` to resolve to a compile-time constant (or restrict it to string literals/definition-time constants) so it cannot be derived from `trigger.data`, `trigger.address`, `input[[...]]`, or other attacker-controlled state, closing the parallel with `parseRemoteAA`'s constant-address requirement [5](#0-4) . At minimum, document and lint against dynamic oracle addresses so AA authors do not unknowingly create attacker-selectable price sources.

### Proof of Concept
1. Attacker controls address `EVIL`.
2. Attacker posts a unit from `EVIL` with `app: "data_feed"`, `payload: { PRICE: <favorable value> }` — permitted by `validateMessage`'s `data_feed` case, which imposes no sender restriction [10](#0-9) .
3. Attacker sends a trigger unit to a victim AA whose logic contains something like:
   `$oracle = trigger.data.oracle; $price = data_feed[[oracles=$oracle, feed_name='PRICE']];`
   and uses `$price` to compute a payout amount, with `trigger.data.oracle = 'EVIL'`.
4. As shown by the accepted test pattern for dynamic oracle resolution [1](#0-0) , `data_feed[[...]]` resolves `EVIL`'s self-posted feed value as if it were a legitimate oracle, and the AA pays out based on the forged price, draining its balance to the attacker — the same end effect as the reported attacker-controlled-TWAP theft.

### Citations

**File:** test/formula.test.js (L827-832)
```javascript
test.cb('formula - datafeed: oracle address from input', t => {
	evalFormula({}, "data_feed[[oracles=input[[asset=base]].address, feed_name=\"test\", ifseveral=\"last\"]] == 10", objValidationState.arrAugmentedMessages, objValidationState, 'KRPWY2QQBLWPCFK3DZGDZYALSWCOEDWA', res => {
		t.deepEqual(res, true);
		t.end();
	});
});
```

**File:** test/formula.test.js (L5477-5502)
```javascript
test('remote call with non-constant address', t => {
	var trigger = { data: { q: { a: 6 } } };
	var stateVars = { MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU: { s: { value: new Decimal(10) } } };
	var locals = { };
	var formula = `
		$remote_aa = 'MXMEKGN37H5QO2AWHT7XRG6LHJVV'||'TAWU';
		$b = $remote_aa.$f(3);
	`;
	evalFormulaWithVars({ conn: null, formula, trigger, locals, stateVars, objValidationState, bStatementsOnly: true, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU'}, (res, complexity, count_ops, val_locals) => {
		t.deepEqual(res, null);
	})
});

test('remote call with conditionally assigned address', t => {
	var trigger = { data: { q: { a: 6 } } };
	var stateVars = { MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU: { s: { value: new Decimal(10) } } };
	var locals = { };
	var formula = `
		if (true)
			$remote_aa = 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU';
		$b = $remote_aa.$f(3);
	`;
	evalFormulaWithVars({ conn: null, formula, trigger, locals, stateVars, objValidationState, bStatementsOnly: true, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU'}, (res, complexity, count_ops, val_locals) => {
		t.deepEqual(res, null);
	})
});
```

**File:** formula/evaluation.js (L602-607)
```javascript
				function getDataFeed(params, cb) {
					if (typeof params.oracles.value !== 'string')
						return cb("oracles not a string "+params.oracles.value);
					var arrAddresses = params.oracles.value.split(':');
					if (!arrAddresses.every(ValidationUtils.isValidAddress))
						return cb("bad oracles "+arrAddresses);
```

**File:** formula/evaluation.js (L666-687)
```javascript
				var params = arr[1];
				var evaluated_params = {};
				async.eachSeries(
					// here and below, the order of keys is standardized since ECMAScript 2020
					Object.keys(params),
					function(param_name, cb2){
						evaluate(params[param_name].value, function(res){
							if (fatal_error)
								return cb2(fatal_error);
							if (res instanceof wrappedObject)
								res = true;
							// boolean allowed for ifnone
							if (!isValidValue(res) || typeof res === 'boolean' && param_name !== 'ifnone')
								return setFatalError('bad value in data feed: '+res, undefined, undefined, cb2);
							if (Decimal.isDecimal(res))
								res = toDoubleRange(res);
							evaluated_params[param_name] = {
								operator: params[param_name].operator,
								value: res
							};
							cb2();
						});
```

**File:** formula/evaluation.js (L726-730)
```javascript
						if (typeof evaluated_params.oracles.value !== 'string')
							return setFatalError('oracles is not a string', { arr }, false, cb);
						var arrAddresses = evaluated_params.oracles.value.split(':');
						if (!arrAddresses.every(ValidationUtils.isValidAddress)) // even if some addresses are ok
							return setFatalError('bad oracles', { arr }, false, cb);
```

**File:** formula/validation.js (L26-49)
```javascript
function validateDataFeed(params) {
	var complexity = 1;
	if (params.oracles && params.feed_name) {
		for (var name in params) {
			var operator = params[name].operator;
			var value = params[name].value;
			if (Decimal.isDecimal(value)){
				if (!isFiniteDecimal(value))
					return {error: 'not finite', complexity};
				value = toDoubleRange(value).toString();
			}
			if (operator !== '=') return {error: 'not =', complexity};
			if (['oracles', 'feed_name', 'min_mci', 'feed_value', 'ifseveral', 'ifnone', 'what', 'type'].indexOf(name) === -1)
				return {error: 'unknown df param: ' + name, complexity};
			if (typeof value !== 'string')
				continue;
			switch (name) {
				case 'oracles':
					if (value.trim() === '') return {error: 'empty oracle', complexity};
					var addresses = value.split(':');
					if (addresses.length === 0) return {error: 'empty oracle list', complexity};
				//	complexity += addresses.length;
					if (!addresses.every(ValidationUtils.isValidAddress)) return {error: 'oracle address not valid', complexity};
					break;
```

**File:** formula/validation.js (L1486-1500)
```javascript
	function parseRemoteAA(remote_aa) {
		if (typeof remote_aa === 'object' && remote_aa[0] === 'local_var') {
			var var_name = remote_aa[1];
			if (typeof var_name !== 'string')
				return { error: "remote AA var name must be literal" };
			if (!hasOwnProperty(locals, var_name))
				return { error: "remote AA var " + var_name + " does not exist" };
			remote_aa = locals[var_name].value;
			if (remote_aa === undefined)
				return { error: "remote AA var " + var_name + " must be a constant" };
		}
		if (!ValidationUtils.isValidAddress(remote_aa))
			return { error: "not valid AA address: " + util.inspect(remote_aa, { depth: 5 }) };
		return { remote_aa };
	}
```

**File:** validation.js (L1925-1952)
```javascript
		case "data_feed":
			if (objValidationState.bHasDataFeed)
				return callback("can be only one data feed");
			objValidationState.bHasDataFeed = true;
			if (!isNonemptyObject(payload))
				return callback("data feed payload must be non-empty object");
			if (Object.keys(payload).length * objUnit.authors.length > constants.MAX_DATA_FEEDS_PER_MESSAGE)
				return callback("too many data feeds in message");
			for (var feed_name in payload){
				if (feed_name.length > constants.MAX_DATA_FEED_NAME_LENGTH)
					return callback("feed name "+feed_name+" too long");
				if (feed_name.indexOf('\n') >=0 )
					return callback("feed name "+feed_name+" contains \\n");
				var value = payload[feed_name];
				if (typeof value === 'string'){
					if (value.length > constants.MAX_DATA_FEED_VALUE_LENGTH)
						return callback("data feed value too long: " + value);
					if (value.indexOf('\n') >=0 )
						return callback("value "+value+" of feed name "+feed_name+" contains \\n");
				}
				else if (typeof value === 'number'){
					if (!isInteger(value))
						return callback("fractional numbers not allowed in data feeds");
				}
				else
					return callback("data feed "+feed_name+" must be string or number");
			}
			return callback();
```

**File:** main_chain.js (L1587-1617)
```javascript
								function addDataFeeds(payload){
									if (!storage.assocStableUnits[unit])
										throw Error("no stable unit "+unit);
									var arrAuthorAddresses = storage.assocStableUnits[unit].author_addresses;
									if (!arrAuthorAddresses)
										throw Error("no author addresses in "+unit);
									var strMci = string_utils.encodeMci(mci);
									for (var feed_name in payload){
										var value = payload[feed_name];
										var strValue = null;
										var numValue = null;
										if (typeof value === 'string'){
											strValue = value;
											var bLimitedPrecision = (mci < constants.aa2UpgradeMci);
											var float = string_utils.toNumber(value, bLimitedPrecision);
											if (float !== null)
												numValue = string_utils.encodeDoubleInLexicograpicOrder(float);
										}
										else
											numValue = string_utils.encodeDoubleInLexicograpicOrder(value);
										arrAuthorAddresses.forEach(function(address){
											// duplicates will be overwritten, that's ok for data feed search
											if (strValue !== null)
												batch.put('df\n'+address+'\n'+feed_name+'\ns\n'+strValue+'\n'+strMci, unit);
											if (numValue !== null)
												batch.put('df\n'+address+'\n'+feed_name+'\nn\n'+numValue+'\n'+strMci, unit);
											// if several values posted on the same mci, the latest one wins
											batch.put('dfv\n'+address+'\n'+feed_name+'\n'+strMci, value+'\n'+unit);
										});
									}
								}
```

**File:** test/samples/futures_contract.oscript (L60-90)
```text
				if: `{ trigger.data.blackswan AND !var['blackswan'] AND data_feed[[oracles='X55IWSNMHNDUIYKICDW3EOYAWHRUKANP', feed_name='GBYTE_USD_MA']] < 25 AND timestamp < 1556668800 }`,
				messages: [{
					app: 'state',
					state: `{
						var['blackswan'] = 1;
						response['blackswan'] = 1;
					}`
				}]
			},
			// 1 GB is now 50 USD, 1 byte is 50e-9 = 5e-8 USD
			// 1 usd asset is always 2.5e-8 USD, 1 gb asset is 1 byte minus 2.5e-8 USD
			{ // pay bytes in exchange for the assets
				if: `{
					if (trigger.output[[asset!=base]].asset == 'none')
						return false;
					$gb_asset_amount = trigger.output[[asset=var['gb_asset']]];
					$usd_asset_amount = trigger.output[[asset=var['usd_asset']]];
					if ($gb_asset_amount < 1e4 AND $usd_asset_amount < 1e4)
						return false;
					if ($gb_asset_amount == $usd_asset_amount){ // helps in case the exchange rate is never posted
						$bytes = $gb_asset_amount;
						return true;
					}
					if (var['blackswan'])
						$bytes = $usd_asset_amount;
					else{
						if (timestamp < 1556668800)
							bounce('wait for maturity date');
						// data_feed will abort if the exchange rate not posted yet
						$exchange_rate = data_feed[[oracles='X55IWSNMHNDUIYKICDW3EOYAWHRUKANP', feed_name='GBYTE_USD_MA_2019_04_30']];
						$bytes_per_usd_asset = min(50/$exchange_rate/2, 1);
```
