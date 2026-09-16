## Analysis

This report's root cause pattern — a contract that permanently hardcodes a reference to an external address (a token contract), cannot be updated once deployed, and thereby loses the ability to track legitimate state after the referenced entity migrates to a new address — maps onto Obyte's Autonomous Agent (AA) `data_feed` oracle mechanism.

### Title
AA definitions permanently hardcode oracle addresses in `data_feed`/`in_data_feed`; funds relying on a migrated oracle become permanently unreadable/frozen - (File: formula/evaluation.js, validation.js)

### Summary
An AA's oscript code references a trusted data-feed provider ("oracle") by its literal address string, e.g. `data_feed[[oracles="ADDR", feed_name="price"]]`. AA definitions are immutable once deployed — the definition hash **is** the address, so it can never be altered or migrated to point at a new oracle address. If the oracle operator needs (or is forced) to migrate to a new posting address, any already-deployed AA that depends on that oracle can never again read updated values: it will keep querying the old, now-stale address forever, exactly as the token pool in the original report kept referencing a token contract's old address.

### Finding Description
`data_feed`/`in_data_feed` opcodes take an `oracles` parameter validated as one or more literal Obyte addresses [1](#0-0) , and the value is looked up from posted `data_feed` messages authored by exactly those addresses [2](#0-1) . The `oracles` value is checked purely for address-format validity — there is no on-chain concept of "the current address of oracle X"; it's whatever literal string is baked into the AA's oscript.

Critically, once an AA is deployed, its definition (including this hardcoded oracle address) can never be changed: the AA's address is derived from the chash of its own definition, and the validation code explicitly documents "AA definition cannot be changed and its address is also its definition_chash" [3](#0-2) . Unlike a regular wallet address, whose keys/definition can be rotated via `address_definition_change` while keeping the same address [4](#0-3) , an AA has no equivalent mechanism to redirect which address it treats as the trusted oracle. A "parameterized AA" can redirect logic to a different `base_aa` [5](#0-4) , but the `oracles` string embedded in a regular AA's messages/state formulas is not parameterizable at the base-AA level, and even a parameterized AA's `params` are fixed at deployment and cannot subsequently be changed either.

### Impact Explanation
If a data-feed provider (oracle) that many AAs depend on migrates its publishing address — e.g. due to a compromised key requiring migration to a brand-new address (not just a definition change of the old address, but literally a new address because the private key material is discarded), an infrastructure change, or provider handover — every already-deployed AA referencing the old oracle address by literal string permanently stops receiving fresh data. Depending on the AA's logic this can:
- Freeze user funds inside the AA indefinitely if the AA's payout/close-out logic is gated on a `data_feed` condition that can never again be satisfied (e.g., "pay out once price data_feed >= X" for a betting/insurance/prediction AA).
- Cause the AA to act on stale data forever, allowing users who know the old data is frozen to exploit price/value discrepancies (analogous to "all the liquidators are likely to withdraw their deposits...causing the slowest liquidators to lose their deposits") — an arbitrage race where users who react first drain value from the AA, while late responders lose funds.

This is a Medium/High severity fund-freezing/fund-loss issue for any AA-based financial product (lending, synthetic assets, prediction markets, insurance) that depends on `data_feed` from a single or fixed set of oracle addresses, since there is no on-chain remediation path.

### Likelihood Explanation
This is not an attack requiring a malicious actor — it is a systemic limitation triggered by any legitimate oracle key/address migration (which is a realistic, foreseeable event, e.g. security incident forcing key rotation to a fresh address, provider handover, or provider ceasing operation and a new provider taking over under a new address). Any AA author who hardcodes a single oracle address without a fallback/multi-oracle/quorum design is exposed. Given oscript's `oracles` parameter typically takes a fixed, literal address (as shown throughout the test suite) [6](#0-5) , this is the common usage pattern.

### Recommendation
- **Short-term:** Document prominently for AA authors that oracle addresses referenced via `data_feed`/`in_data_feed` are immutable for the lifetime of the AA, and recommend patterns such as: designing AAs to accept the oracle address as a mutable state variable settable by a trusted governance address (via a `data`/`state` message) rather than a literal in oscript, or supporting a quorum/list of oracle addresses with a defined fallback procedure.
- **Long-term:** Consider standard library/base-AA patterns that formalize an "oracle registry" state variable pattern (oracle address stored in AA state and updatable under a defined authorization scheme) so applications aren't forced to hardcode a single point of failure. If no on-chain mechanism is added, ensure the AA documentation/dev-tooling formally warns of this migration limitation, similar to the recommendation given in the original report for BToken.sol.

### Proof of Concept
1. Oracle `O` posts price data via `data_feed` messages from address `Addr_O1`.
2. AA `A` is deployed with oscript containing `data_feed[[oracles="Addr_O1", feed_name="price"]]` used to gate a payout condition, e.g. `if (data_feed[[oracles="Addr_O1", feed_name="price"]] >= trigger.data.target) { payout }` [7](#0-6) .
3. Users deposit funds into `A`, expecting resolution once `price` data is posted.
4. `Addr_O1`'s private key is compromised/retired; oracle `O` must migrate to publishing from a brand-new address `Addr_O2` (no on-chain link possible between `Addr_O1` and `Addr_O2` in a way `A` can consume, because `A`'s oscript is immutable per `validation.js` lines 1747-1758).
5. `A` never sees any further `data_feed` postings matching `oracles="Addr_O1"`, so the payout condition can never be satisfied again — user funds remain locked in `A`'s balance indefinitely, or a race occurs among users to withdraw before others realize the oracle has stopped updating.

### Citations

**File:** formula/evaluation.js (L600-663)
```javascript
			case 'data_feed':

				function getDataFeed(params, cb) {
					if (typeof params.oracles.value !== 'string')
						return cb("oracles not a string "+params.oracles.value);
					var arrAddresses = params.oracles.value.split(':');
					if (!arrAddresses.every(ValidationUtils.isValidAddress))
						return cb("bad oracles "+arrAddresses);
					var feed_name = params.feed_name.value;
					if (!feed_name || typeof feed_name !== 'string')
						return cb("empty feed_name or not a string");
					var value = null;
					var relation = '';
					var min_mci = 0;
					if (params.feed_value) {
						value = params.feed_value.value;
						relation = params.feed_value.operator;
						if (!isValidValue(value))
							return cb("bad feed_value: "+value);
					}
					if (params.min_mci) {
						min_mci = params.min_mci.value.toString();
						if (!(/^\d+$/.test(min_mci) && ValidationUtils.isNonnegativeInteger(parseInt(min_mci))))
							return cb("bad min_mci: "+min_mci);
						min_mci = parseInt(min_mci);
					}
					var ifseveral = 'last';
					if (params.ifseveral){
						ifseveral = params.ifseveral.value;
						if (ifseveral !== 'abort' && ifseveral !== 'last')
							return cb("bad ifseveral: "+ifseveral);
					}
					var what = 'value';
					if (params.what){
						what = params.what.value;
						if (what !== 'unit' && what !== 'value')
							return cb("bad what: "+what);
					}
					var type = 'auto';
					if (params.type){
						type = params.type.value;
						if (type !== 'string' && type !== 'auto')
							return cb("bad df type: "+type);
					}
					if (params.ifnone && !isValidValue(params.ifnone.value))
						return cb("bad ifnone: "+params.ifnone.value);
					dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, objValidationState.last_ball_timestamp, function(objResult){
					//	console.log(arrAddresses, feed_name, value, min_mci, ifseveral);
					//	console.log('---- objResult', objResult);
						if (objResult.bAbortedBecauseOfSeveral)
							return cb("several values found");
						if (objResult.value !== undefined){
							if (what === 'unit')
								return cb(null, objResult.unit);
							if (type === 'string')
								return cb(null, objResult.value.toString());
							return cb(null, (typeof objResult.value === 'string') ? objResult.value : createDecimal(objResult.value));
						}
						if (params.ifnone && params.ifnone.value !== 'abort'){
						//	console.log('===== ifnone=', params.ifnone.value, typeof params.ifnone.value);
							return cb(null, params.ifnone.value); // the type of ifnone (string, decimal, boolean) is preserved
						}
						cb("data feed " + feed_name + " not found");
					});
```

**File:** data_feeds.js (L34-43)
```javascript
		for (var unit in storage.assocUnstableMessages) {
			var objUnit = storage.assocUnstableUnits[unit] || storage.assocStableUnits[unit];
			if (!objUnit)
				throw Error("unstable unit " + unit + " not in assoc");
			if (!objUnit.bAA)
				continue;
			if (objUnit.latest_included_mc_index < min_mci || objUnit.latest_included_mc_index > max_mci)
				continue;
			if (_.intersection(arrAddresses, objUnit.author_addresses).length === 0)
				continue;
```

**File:** validation.js (L1719-1745)
```javascript
		case "address_definition_change":
			if (!isNonemptyObject(payload))
				return callback("payload must be a non empty object");
			if (hasFieldsExcept(payload, ["definition_chash", "address"]))
				return callback("unknown fields in address_definition_change");
			var arrAuthorAddresses = objUnit.authors.map(function(author) { return author.address; } );
			var address;
			if (objUnit.authors.length > 1){
				if (!isValidAddress(payload.address))
					return callback("when multi-authored, must indicate address");
				if (arrAuthorAddresses.indexOf(payload.address) === -1)
					return callback("foreign address");
				address = payload.address;
			}
			else{
				if ('address' in payload)
					return callback("when single-authored, must not indicate address");
				address = arrAuthorAddresses[0];
			}
			if (!objValidationState.arrDefinitionChangeFlags)
				objValidationState.arrDefinitionChangeFlags = {};
			if (objValidationState.arrDefinitionChangeFlags[address])
				return callback("can be only one definition change per address");
			objValidationState.arrDefinitionChangeFlags[address] = true;
			if (!isValidAddress(payload.definition_chash))
				return callback("bad new definition_chash");
			return callback();
```

**File:** validation.js (L1747-1758)
```javascript
		case "definition": // for AAs only
			if (!isNonemptyObject(payload))
				return callback("payload must be a non empty object");
			if (hasFieldsExcept(payload, ["address", "definition"])) // AA definition cannot be changed and its address is also its definition_chash
				return callback("unknown fields in app definition");
			try{
				if (payload.address !== objectHash.getChash160(payload.definition))
					return callback("definition doesn't match the chash");
			}
			catch(e){
				return callback("bad definition");
			}
```

**File:** aa_composer.js (L433-444)
```javascript
	if (template.base_aa) { // parameterized AA
		if (params && Object.keys(params).length > 0)
			throw Error("unexpected params");
		storage.readAADefinition(conn, template.base_aa, mci, function (arrBaseDefinition) {
			if (!arrBaseDefinition)
				throw Error("base AA not found: " + template.base_aa);
			console.log("redirecting to base AA " + template.base_aa + " with params " + JSON.stringify(template.params));
			trigger_opts.params = template.params;
			trigger_opts.arrDefinition = arrBaseDefinition;
			handleTrigger(trigger_opts);
		});
		return;
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
