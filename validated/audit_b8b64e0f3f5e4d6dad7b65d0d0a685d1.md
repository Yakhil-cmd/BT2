### Title
Atomic AA-to-AA trigger chains allow attackers to sandwich a balance-priced AMM against a stale oracle-priced maker within a single unit, extracting AA funds - (File: aa_composer.js, test/samples/uniswap_like_market_maker.oscript)

### Summary
The Sherlock M-8 bug allows an attacker to atomically skew a spot pool's price, settle a trade against a maker that only checks a bounded "price band," and reverse the skew, all inside one transaction — extracting value because the maker's price band tolerance is wider than zero (to accommodate pool fees) while the pool itself can be temporarily driven far from the oracle price. The ocore analog exists because Autonomous Agent (AA) trigger chains execute fully atomically and deterministically inside a single DB transaction, and because ocore ships (and by extension, developers commonly build) AA templates where one AA prices trades purely from its own internal balance ratio (a constant-product AMM) while another AA in the same trigger chain settles payouts using a previously-posted, and therefore lagging, oracle `data_feed` value.

### Finding Description
`handlePrimaryAATrigger` processes a triggering unit and all of its cascading "secondary" AA triggers inside one `BEGIN ... COMMIT` transaction and one `kvstore` batch write, with no way for an intervening unit or oracle update to be interleaved: [1](#0-0) . Secondary triggers fire automatically and synchronously when a payment output from one AA response lands on another AA address, chained via `handleSecondaryTriggers`, and any AA that receives funds mid-chain can act on balances that were just modified earlier in the very same chain: [2](#0-1) . This atomic, uninterruptible AA-call chain is the ocore analog of the "single flash-loan transaction" that the Sherlock finding relies on to sandwich the SpotHedgeBaseMaker.

The ocore documentation ships a reference constant-product AMM AA whose swap price is derived purely from the AA's own token/byte balance ratio, with no external price check or price band at all: `$p = $asset_balance * $bytes_balance; $amount = $asset_balance - round($p / balance[base])` [3](#0-2) . Separately, ocore also ships reference AAs that settle payouts using an oracle `data_feed` exchange rate posted by a trusted oracle address, explicitly noting that the feed can be stale ("the price gapped...within the last 60 seconds, and nobody has updated the pyth price" is exactly the scenario the oracle-consuming pattern is vulnerable to): [4](#0-3) .

If an AA author (as the ocore documentation implicitly encourages via these two composable templates) wires a balance-priced AMM AA into the same secondary-trigger chain as an oracle-priced settlement/maker AA, an attacker can, within one posted unit:
1. Swap a large amount into the AMM AA, skewing its internal balance ratio (and hence its quoted price) far from the true market price — there is no price band or external oracle check on this AMM template.
2. Chain (via secondary trigger, same unit, same atomic transaction) into the oracle-priced AA, which still reads the pre-existing (unchanged, un-updated) `data_feed` value, and settle a trade at a price divergent from the just-skewed AMM balance.
3. Reverse the initial skew within the same unit/chain, walking away with the extracted balance.

Because the whole sequence is one atomic, deterministic execution with no room for third parties (keepers, oracle updaters, arbitrageurs) to react in between, this is structurally identical to the Sherlock M-8 root cause: a maker's price protection (whatever price band exists) is checked against a value that lags behind an AMM whose price the same attacker just manipulated in the same atomic operation.

### Impact Explanation
An attacker can extract real base-asset/AA-issued-token balance from an AA (or interconnected group of AAs) by combining a manipulable, balance-priced AMM AA with a stale-oracle-priced settlement AA in the same atomic trigger chain, analogous to bad debt / value extraction demonstrated in the Sherlock report. This is a concrete AA fund loss, matching the "Medium/High" bar (unauthorized value extraction from AA-held funds), not merely a low/resource issue.

### Likelihood Explanation
Likelihood depends on real-world AA authors deploying two specific composable pieces together (a balance-only-priced AMM and an oracle-price-consuming settlement AA) in the same secondary-trigger chain, and on the oracle feed lagging the true price during the attack unit's construction (bounded by feed update latency, similar to the 7% gap window relied upon in the original report). Because ocore explicitly ships and documents both AMM-by-balance and oracle-settlement templates as building blocks (`test/samples/uniswap_like_market_maker.oscript`, `test/samples/futures_contract.oscript`, `test/samples/ico_with_milestones.oscript`), and the AA-chaining primitive (`handleSecondaryTriggers`) is a core, actively encouraged composition feature, this is a realistic, unprivileged-user-reachable pattern for any market built from these documented pieces, but requires deliberate protocol design combining them without additional protections (e.g., without an internal price-deviation check comparing the AMM's spot price to the oracle price before settling).

### Recommendation
- Any AA that prices trades from its own internal balances (constant-product or otherwise) and is composed with — or feeds — another AA that trusts an oracle `data_feed` for settlement should independently cross-check that its own computed spot price is within a bounded deviation of the oracle price (data_feed) before executing the trade, not rely solely on whichever AA in the chain performs the check.
- Since `handleSecondaryTriggers` guarantees full atomic composability of AA chains (aa_composer.js:1702-1741), documentation/templates for AMM-style AAs (uniswap_like_market_maker.oscript) should be updated to include an oracle-based price-band guard, and any oracle-consuming settlement AA templates (futures_contract.oscript) should avoid being chained, in the same unit/trigger sequence, with AAs whose balances they implicitly price against.
- Consider adding tooling/guidance flagging AA definitions that both (a) read `balance[...]` to compute a trade price and (b) are reachable as a secondary trigger target from another AA that also manipulates the same asset's balance in the same chain.

### Proof of Concept
1. Deploy the reference `uniswap_like_market_maker.oscript` AA holding `$asset` and bytes reserves [3](#0-2) .
2. Deploy a second AA ("SettlementAA") that, on receiving `$asset` (or bytes) from the AMM AA as a secondary trigger, computes a payout using `data_feed[[oracles=..., feed_name=...]]` similar to `futures_contract.oscript`'s exchange-rate lookup [4](#0-3) , with only a static price band tolerance and no cross-check against the AMM's current spot price.
3. Post a single unit that:
   a. Sends a large amount of bytes to the AMM AA, receiving `$asset` at a skewed rate (moves `$asset_balance`/`$bytes_balance` far from the last-known market price).
   b. In the same unit's message set, forwards the received `$asset` to SettlementAA as part of the same trigger's outputs, causing a secondary trigger in the same atomic transaction.
   c. SettlementAA settles against the stale `data_feed` price (posted before this unit), producing a payout inconsistent with the AMM's now-skewed price.
   d. Within the same chain (or via a compensating follow-up unit before the AMM AA rebalances/before the oracle updates), swap back through the AMM AA to restore its balance ratio, retaining the SettlementAA payout difference as profit.
4. Verify final combined balances (bytes + `$asset`) of the attacker across steps (a)-(d) exceed their starting balances net of bounce fees, demonstrating extracted value analogous to the Sherlock M-8 `testSandwich` PoC — enabled by the atomic execution guaranteed in `handlePrimaryAATrigger`/`handleSecondaryTriggers` [5](#0-4) .

### Citations

**File:** aa_composer.js (L91-149)
```javascript
function handlePrimaryAATrigger(mci, unit, address, arrDefinition, arrPostedUnits, onDone) {
	db.takeConnectionFromPool(function (conn) {
		conn.query("BEGIN", function () {
			var batch = kvstore.batch();
			readMcUnit(conn, mci, function (objMcUnit) {
				readUnit(conn, unit, function (objUnit) {
					var arrResponses = [];
					var trigger = getTrigger(objUnit, address);
					trigger.initial_address = trigger.address;
					trigger.initial_unit = trigger.unit;
					handleTrigger(conn, batch, trigger, {}, {}, arrDefinition, address, mci, objMcUnit, false, arrResponses, function(){
						conn.query("DELETE FROM aa_triggers WHERE mci=? AND unit=? AND address=?", [mci, unit, address], async function(){
							await conn.query("UPDATE units SET count_aa_responses=IFNULL(count_aa_responses, 0)+? WHERE unit=?", [arrResponses.length, unit]);
							let objUnitProps = storage.assocStableUnits[unit];
							if (!objUnitProps)
								throw Error(`handlePrimaryAATrigger: unit ${unit} not found in cache`);
							if (!objUnitProps.count_aa_responses)
								objUnitProps.count_aa_responses = 0;
							objUnitProps.count_aa_responses += arrResponses.length;
							var batch_start_time = Date.now();
							batch.write({ sync: true }, function(err){
								console.log("AA batch write took "+(Date.now()-batch_start_time)+'ms');
								if (err)
									throw Error("AA composer: batch write failed: "+err);
								conn.query("COMMIT", function () {
									conn.release();
									if (arrResponses.length > 1) {
										// copy updatedStateVars to all responses
										if (arrResponses[0].updatedStateVars)
											for (var i = 1; i < arrResponses.length; i++)
												arrResponses[i].updatedStateVars = arrResponses[0].updatedStateVars;
										// merge all changes of balances if the same AA was called more than once
										let assocBalances = {};
										for (let { aa_address, balances } of arrResponses)
											assocBalances[aa_address] = balances; // overwrite if repeated
										for (let r of arrResponses) {
											r.balances = assocBalances[r.aa_address];
											r.allBalances = assocBalances;
										}
									}
									else
										arrResponses[0].allBalances = { [address]: arrResponses[0].balances };
									arrResponses.forEach(function (objAAResponse) {
										if (objAAResponse.objResponseUnit)
											arrPostedUnits.push(objAAResponse.objResponseUnit);
										eventBus.emit('aa_response', objAAResponse);
										eventBus.emit('aa_response_to_unit-'+objAAResponse.trigger_unit, objAAResponse);
										eventBus.emit('aa_response_to_address-'+objAAResponse.trigger_address, objAAResponse);
										eventBus.emit('aa_response_from_aa-'+objAAResponse.aa_address, objAAResponse);
									});
									onDone();
								});
							});
						});
					});
				});
			});
		});
	});
```

**File:** aa_composer.js (L1702-1741)
```javascript
	function handleSecondaryTriggers(objUnit, arrOutputAddresses) {
		conn.query("SELECT address, definition, mci, main_chain_index FROM aa_addresses LEFT JOIN units USING(unit) WHERE address IN(?) AND mci<=? ORDER BY address", [arrOutputAddresses, mci], function (rows) {
			if (rows.length > 0 && constants.bTestnet && mci < testnetAAsDefinedByAAsAreActiveImmediatelyUpgradeMci)
				rows = rows.filter(function (row) {
					if (row.main_chain_index && row.main_chain_index < mci) // previous definition is already stable
						return true;
					var len = storage.getUnconfirmedAADefinitionsPostedByAAs([row.address]).length;
					if (len > 0)
						console.log("not calling secondary trigger from unit " + objUnit.unit + " to AA " + row.address);
					return (len === 0);
				});
			if (rows.length === 0) {
				saveStateVars();
				addUpdatedStateVarsIntoPrimaryResponse();
				return onDone(objUnit, bBouncing ? error_message : false);
			}
			if (bBouncing)
				throw Error("secondary triggers while bouncing");
			async.eachSeries(
				rows,
				function (row, cb) {
					var child_trigger = getTrigger(objUnit, row.address);
					child_trigger.initial_address = trigger.initial_address;
					child_trigger.initial_unit = trigger.initial_unit;
					if ("max_aa_responses" in trigger && mci >= constants.pemCurvesFixMci) // propagate the cap set on the primary trigger to secondary triggers
						child_trigger.max_aa_responses = trigger.max_aa_responses;
					var arrChildDefinition = JSON.parse(row.definition);

					var child_trigger_opts = { ...trigger_opts };
					child_trigger_opts.trigger = child_trigger;
					child_trigger_opts.params = {};
					child_trigger_opts.arrDefinition = arrChildDefinition;
					child_trigger_opts.address = row.address;
					child_trigger_opts.bSecondary = true;
					child_trigger_opts.onDone = function (objSecondaryUnit, bounce_message) {
						if (bounce_message)
							return cb(bounce_message);
						cb();
					};
					handleTrigger(child_trigger_opts);
```

**File:** test/samples/uniswap_like_market_maker.oscript (L102-123)
```text
			{ // exchange bytes to asset
				if: `{trigger.output[[asset=base]] > 1e5 AND trigger.output[[asset=$asset]] == 0 AND var['mm_asset_outstanding']}`,
				init: `{
					$asset_balance = balance[$asset] - trigger.output[[asset=$asset]];
					$bytes_balance = balance[base] - trigger.output[[asset=base]];
					// other formula can be used for product, e.g. $asset_balance * $bytes_balance ^ 2
					$p = $asset_balance * $bytes_balance;
					$new_asset_balance = round($p / balance[base]);
					$amount = $asset_balance - $new_asset_balance; // we can deduct exchange fees here
				}`,
				messages: [
					{
						app: 'payment',
						payload: {
							asset: "{$asset}",
							outputs: [
								{address: "{trigger.address}", amount: "{ $amount }"}
							]
						}
					},
				]
			},
```

**File:** test/samples/futures_contract.oscript (L59-90)
```text
			{ // record blackswan event
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
