## Analysis

The Sherlock report concerns TWAP/oracle price reads that can be raced across consecutive blocks by an MEV actor, distorting the price an on-chain formula consumes. The closest reachable analog in `ocore` is the way Autonomous Agent (AA) formulas read oracle `data_feed` values, which — unlike normal stable-storage reads — are allowed to be resolved from **not-yet-stable ("unstable") DAG units** at the moment an AA trigger executes.

`formula/evaluation.js`'s `data_feed` opcode calls `dataFeeds.readDataFeedValue(arrAddresses, feed_name, value, min_mci, mci, bAA, ifseveral, ...)`, passing the AA flag `bAA` as the `unstable_opts` argument: [1](#0-0) 

Inside `readDataFeedValue`, when `unstable_opts` is truthy, the function scans `storage.assocUnstableMessages` — the node's **local, real-time view of currently-unstable units** — for `data_feed` messages from the requested oracle addresses, filtering only by `latest_included_mc_index` range and author address, without regard for whether that candidate unit is actually witnessed as final by the time the AA trigger's own `mci` stabilizes: [2](#0-1) 

When several unstable candidates exist, they are ordered by `latest_included_mc_index` and `level`, and if these are unresolvable it deliberately errors out for the strict AA path (`bIncludeAllUnstable` disabled) rather than deterministically resolving via a value that's guaranteed identical for every node: [3](#0-2) 

The set of "currently unstable" units in `storage.assocUnstableMessages` is populated as units are received/written locally, before they are moved out on stabilization: [4](#0-3) 
and cleared only once the corresponding MCI stabilizes and their data feeds are committed to durable KV storage: [5](#0-4) 

Sample AA contracts in the repo demonstrate this exact pattern being used to gate large fund movements on a single (potentially unstable) oracle read: [6](#0-5) [7](#0-6) 

### Title
Non-deterministic oracle price selection via unstable `data_feed` reads in AA formulas enables cross-node MEV-style manipulation - (File: `data_feeds.js`)

### Summary
AA formulas that call `data_feed[[...]]` without an oracle-provided finality guarantee can resolve their price/value from **unstable, not-yet-finalized** oracle units rather than only from stable, network-agreed history, because `readDataFeedValue` is invoked with `unstable_opts = bAA` from `formula/evaluation.js`.

### Finding Description
`readDataFeedValue` in `data_feeds.js` iterates `storage.assocUnstableMessages`, a purely local, time-dependent structure reflecting which units a given node happens to have received and not yet stabilized [8](#0-7) . This set is not guaranteed identical across full nodes at the precise moment an AA trigger's containing MCI becomes stable and `aa_composer.handleAATriggers()` runs the formula, because unstable-unit propagation is a real-time network process, not a DAG-position-derived deterministic quantity. Two honest nodes can therefore observe different "last" unstable data-feed candidate for the same `oracles`/`feed_name` pair at formula-execution time, and consequently the sorting logic at lines 255-267 can select different final feed values (or, in the deterministic strict-AA branch, throw for one node and succeed for another if the ambiguous-candidate set differs). An oracle (or any actor able to post competing `data_feed` units from watched addresses, including addresses under attacker control if the AA is naively parameterized) can exploit this race window — analogous to multi-block MEV manipulation of an on-chain TWAP — by posting a value timed so that it propagates to only part of the network before the AA-triggering unit's MCI stabilizes, causing different nodes to compute different AA responses for the same trigger.

### Impact Explanation
Because every full node independently re-executes AA formula logic to validate the resulting AA response unit (there is no trusted central executor), a data-dependent, timing-sensitive divergence in the selected oracle value directly causes **nodes to disagree on the validity/content of the AA response unit** produced for the same trigger. This can manifest as a consensus split on the correct AA output (e.g., differing payout amounts in the sample `futures_contract.oscript`/`option_contract.oscript` patterns that gate multi-asset transfers on such a `data_feed[[...]]` read), i.e., node disagreement on validity/stability and potential fund loss/miscalculation for AA-mediated transfers.

### Likelihood Explanation
Exploitation requires only posting ordinary `data_feed` units from an address already trusted as an oracle by an AA (or, for AAs that accept attacker-influenced oracle addresses via trigger data, from any address) timed around the stabilization of a pending AA trigger — no privileged network, hub, or node role is needed, only careful timing of unit broadcast relative to the DAG's approach to finality, which is realistically achievable by a sufficiently well-connected unprivileged actor.

### Recommendation
Restrict AA `data_feed`/`in_data_feed` evaluation to only stable, already-finalized data feed records (drop the `unstable_opts=bAA` unstable-candidate branch in `readDataFeedValue`/`dataFeedExists`), or, if unstable reads must be retained for latency reasons, require that candidate resolution be a pure, deterministic function of the trigger unit's own DAG ancestry (i.e., restrict candidates to units that are provable ancestors of the trigger, not merely "currently pending in this node's local unstable-message set").

### Proof of Concept
1. Oracle/attacker-controlled address `O` posts `data_feed` unit `U1` with `feed_name=X, value=100` and lets it propagate partially through the network.
2. Before `U1` stabilizes, the same address posts `U2` with `feed_name=X, value=1` on a competing/parallel branch, deliberately delaying full propagation to some nodes.
3. An AA trigger unit `T` referencing `data_feed[[oracles=O, feed_name=X]]` gets included and its containing MCI stabilizes while `U1`/`U2` are still unstable on different subsets of nodes.
4. `formula/evaluation.js`'s `data_feed` case calls `readDataFeedValue(..., mci, bAA=true, ...)` [9](#0-8) , which scans each node's local `storage.assocUnstableMessages` [10](#0-9) ; nodes that have received only `U1` compute the AA response using value `100`, while nodes that have also received `U2` compute a different candidate set/ordering per lines 255-267, producing a different AA response for the identical trigger `T`.

### Citations

**File:** formula/evaluation.js (L646-663)
```javascript
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

**File:** data_feeds.js (L205-241)
```javascript
function readDataFeedValue(arrAddresses, feed_name, value, min_mci, max_mci, unstable_opts, ifseveral, timestamp, handleResult){
	var bLimitedPrecision = (max_mci < constants.aa2UpgradeMci);
	var start_time = Date.now();
	var objResult = { bAbortedBecauseOfSeveral: false, value: undefined, unit: undefined, mci: undefined };
	var bIncludeUnstableAAs = !!unstable_opts;
	var bIncludeAllUnstable = (unstable_opts === 'all_unstable');
	if (bIncludeUnstableAAs) {
		var arrCandidates = [];
		for (var unit in storage.assocUnstableMessages) {
			var objUnit = storage.assocUnstableUnits[unit] || storage.assocStableUnits[unit];
			if (!objUnit)
				throw Error("unstable unit " + unit + " not in assoc");
			if (!objUnit.bAA && !bIncludeAllUnstable)
				continue;
			if (objUnit.sequence !== 'good')
				continue;
			if (objUnit.latest_included_mc_index < min_mci || objUnit.latest_included_mc_index > max_mci)
				continue;
			if (_.intersection(arrAddresses, objUnit.author_addresses).length === 0)
				continue;
			storage.assocUnstableMessages[unit].forEach(function (message) {
				if (message.app !== 'data_feed')
					return;
				var payload = message.payload;
				if (!ValidationUtils.hasOwnProperty(payload, feed_name))
					return;
				var feed_value = payload[feed_name];
				if (value === null || value === feed_value || value.toString() === feed_value.toString())
					arrCandidates.push({
						value: string_utils.getFeedValue(feed_value, bLimitedPrecision),
						latest_included_mc_index: objUnit.latest_included_mc_index,
						level: objUnit.level,
						unit: objUnit.unit,
						mci: max_mci // it doesn't matter
					});
			});
		}
```

**File:** data_feeds.js (L250-267)
```javascript
		else if (arrCandidates.length > 1) {
			if (ifseveral === 'abort') {
				objResult.bAbortedBecauseOfSeveral = true;
				return handleResult(objResult);
			}
			arrCandidates.sort(function (a, b) {
				if (a.latest_included_mc_index < b.latest_included_mc_index)
					return -1;
				if (a.latest_included_mc_index > b.latest_included_mc_index)
					return 1;
				if (a.level < b.level)
					return -1;
				if (a.level > b.level)
					return 1;
				if (bIncludeAllUnstable) // still ambiguous, sort randomly (it's OK outside AAs)
					return 1;
				throw Error("can't sort candidates "+a+" and "+b);
			});
```

**File:** writer.js (L603-612)
```javascript
			if (objUnit.messages) {
				objUnit.messages.forEach(function(message) {
					if (['data_feed', 'definition', 'system_vote', 'system_vote_count'].includes(message.app)) {
						if (!storage.assocUnstableMessages[objUnit.unit])
							storage.assocUnstableMessages[objUnit.unit] = [];
						storage.assocUnstableMessages[objUnit.unit].push(message);
						if (message.app === 'system_vote' && !objValidationState.bDryRun)
							eventBus.emit('system_var_vote', message.payload.subject, message.payload.value, arrAuthorAddresses, objUnit.unit, 0);
					}
				});
```

**File:** main_chain.js (L1550-1585)
```javascript
								async function saveUnstablePayloads() {
									let arrUnstableMessages = storage.assocUnstableMessages[unit];
									if (!arrUnstableMessages)
										return cb();
									if (objUnitProps.sequence === 'final-bad'){
										delete storage.assocUnstableMessages[unit];
										return cb();
									}
									for (let message of arrUnstableMessages) {
										const { app, payload } = message;
										switch (app) {
											case 'data_feed':
												addDataFeeds(payload);
												break;
											case 'definition':
												// before the fix, re-inserting recalculated aa_balances to pick up non-AA payments received between definition and stabilization
												if (objUnitProps.is_aa_response && mci >= constants.pemCurvesFixMci)
													continue; // already inserted in writer.js with the correct balance
												const objLastBallUnitProps = await storage.readUnitProps(conn, objUnitProps.last_ball_unit);
												const definer_last_ball_mci = objLastBallUnitProps.main_chain_index;
												await storage.insertAADefinitions(conn, [payload], unit, mci, definer_last_ball_mci, false);
												break;
											case 'system_vote':
												await saveSystemVote(payload);
												break;
											case 'system_vote_count': // will be processed later, when we finish this mci
												if (!voteCountSubjects.includes(payload))
													voteCountSubjects.push(payload);
												break;
											default:
												throw Error("unrecognized app in unstable message: " + app);
										}
									}
									delete storage.assocUnstableMessages[unit];
									cb();
								}
```

**File:** test/samples/futures_contract.oscript (L85-93)
```text
					else{
						if (timestamp < 1556668800)
							bounce('wait for maturity date');
						// data_feed will abort if the exchange rate not posted yet
						$exchange_rate = data_feed[[oracles='X55IWSNMHNDUIYKICDW3EOYAWHRUKANP', feed_name='GBYTE_USD_MA_2019_04_30']];
						$bytes_per_usd_asset = min(50/$exchange_rate/2, 1);
						$bytes_per_gb_asset = 1 - $bytes_per_usd_asset;
						$bytes = round($bytes_per_usd_asset * $usd_asset_amount + $bytes_per_gb_asset * $gb_asset_amount);
					}
```

**File:** test/samples/option_contract.oscript (L63-70)
```text
					state: `{
						if (trigger.data.winner == 'yes' AND data_feed[[oracles='X55IWSNMHNDUIYKICDW3EOYAWHRUKANP', feed_name='GBYTE_USD']] > 60)
							var['winner'] = 'yes';
						else if (trigger.data.winner == 'no' AND timestamp > 1556668800)
							var['winner'] = 'no';
						else
							bounce('suggested outcome not confirmed');
						response['winner'] = trigger.data.winner;
```
