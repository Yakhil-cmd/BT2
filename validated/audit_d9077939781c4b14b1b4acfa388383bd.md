This confirms the analog: `dataFeedExists` (and by extension the `in merkle` / `in data feed` conditions built on it) treats *any* historical data-feed row matching the given value as sufficient proof — it does not restrict matching to "the single currently-intended attestation" or bind the match to a specific claim window unless the address-definition author explicitly encodes `min_mci`/`max_mci` bounds themselves. The trust model is structurally identical to the Paladin bug: an oracle posts a claim (a Merkle root representing "these addresses did X"), and the definition/AA blindly treats inclusion in that root as proof that the underlying real-world fact (e.g. "this address voted for this gauge in this period") occurred, with no independent on-chain corroboration of the fact itself.

### Title
Merkle-root/data-feed reward conditions trust unverifiable off-chain oracle claims and allow stale-root replay across periods - (File: definition.js, data_feeds.js)

### Summary
Address definitions and AAs that gate fund release on `["in merkle", [oracles, feed_name, element, min_mci]]` (or the `data_feed`/`in data feed`/`is_valid_merkle_proof` formula primitives) rely entirely on an oracle-posted Merkle root as ground truth for an off-chain fact (e.g., "this address participated in period N"). ocore only verifies the cryptographic proof-to-root binding; it has no mechanism to verify the underlying real-world claim encoded in the tree, and `dataFeedExists`/`dataFeedByAddressExists` accept a match against *any* historical data-feed post by the oracle in the given `[min_mci, max_mci]` window rather than only the single most-recent/intended one.

### Finding Description
The `in merkle` case in `validateAuthentifiers` verifies a supplied Merkle proof against `element`, then checks that the computed `proof.root` was posted by the designated oracle addresses as a data feed value via `dataFeeds.dataFeedExists`. [1](#0-0) 
`dataFeedExists` in turn does a range/window search (`min_mci`..`max_mci`) over all data-feed posts and returns true on the first match found anywhere in that window — it is not restricted to a single, most-recent, per-period root. [2](#0-1) [3](#0-2) 

This mirrors the reported class of bug exactly: a reward/eligibility system is built by trusting a Merkle tree generated off-chain (here, by whichever address is designated an "oracle" in the definition), and the on-chain logic can only confirm "does this leaf belong to *a* root the oracle posted," not "did the underlying event (e.g., a vote) genuinely happen for this specific period." If an author reuses the same `feed_name` across multiple reward periods (a natural design choice to keep AA logic simple), any Merkle root ever posted for that feed and still within the address definition's `[min_mci, last_ball_mci]` window remains a valid target for proof verification. A user included in an old tree (for a period in which they legitimately qualified) can therefore replay that same proof against the AA's release condition indefinitely, as long as the stale root still falls inside the accepted mci window, and separately, any oracle mistake in tree construction (accidental or malicious) is accepted at face value with zero secondary verification of the underlying fact by ocore.

### Impact Explanation
An AA or shared address built on this primitive to distribute funds per period (an ocore-native analog of `MultiMerkleDistributor.sol`) can pay out to addresses that never performed the qualifying action for the targeted period, or allow the same qualifying leaf to be reused to drain funds across periods if the AA doesn't separately track per-period, per-leaf spent status keyed off the specific root (which the base `in merkle`/`dataFeedExists` primitives do not enforce). This is a direct path to unauthorized fund release / AA fund loss.

### Likelihood Explanation
Likelihood is medium: it requires either (a) an oracle mistake/malice in tree construction — exactly the scenario Paladin flagged as plausible — or (b) an AA author reusing `feed_name` across periods without independently namespacing/state-tracking claimed leaves per root. Given ocore's own primitive offers no built-in "consume once per proof/root" bookkeeping, this misuse pattern is easy to fall into for any reward-distribution AA that adopts the `in merkle` / `data_feed` idiom shown in ocore's own oscript grammar and tests. [4](#0-3) 

### Recommendation
- Document (and where possible, enforce in the AA-validation layer) that `in merkle` / `data_feed`-based eligibility checks must bind to the single specific root/unit expected for the current period (e.g., by comparing against a state-stored `current_root` rather than an open mci window), rather than accepting any historical match.
- Consider tightening `dataFeedExists`/`in merkle` semantics (or adding a stricter variant) that matches only the latest data-feed post for a given `(oracle, feed_name)`, mirroring the `ifseveral='last'` semantics already used elsewhere in `readDataFeedValue`, so stale roots cannot silently remain valid targets forever.
- Encourage/require AA authors to track spent leaves per-root (not just per-leaf) in state vars so that even correct roots cannot be replayed against a later period's fund pool.

### Proof of Concept
1. An address/AA definition includes: `["in merkle", [[oracle_address], "reward_tree", element, 0]]` (no `min_mci` restriction), used to gate a payment message releasing period rewards. [1](#0-0) 
2. In period 1, the oracle posts Merkle root `R1` (built from genuinely-qualifying addresses) via `data_feed` under `feed_name="reward_tree"`. A qualifying user submits their leaf+proof against `R1` and is paid.
3. In period 2, the oracle posts a new root `R2` (for period-2 qualifiers) under the *same* `feed_name`. Because `dataFeedExists` performs an unbounded historical search (bounded only by `max_mci = last_ball_mci`, with `min_mci` defaulting to 0 unless the author explicitly restricts it) and returns true on any match, the same user from step 2 can resubmit their original proof against `R1` again — `dataFeedExists([oracle], "reward_tree", "=", R1, 0, last_ball_mci, ...)` still finds `R1` in the historical data-feed stream and returns `true`. [5](#0-4) 
4. The AA/address pays out again for period 2 funds to a user who did not qualify in period 2, purely because the underlying "is this a genuine claim for the current period" fact was never independently verifiable by ocore — only "was this leaf ever included in a root the oracle posted."

### Citations

**File:** definition.js (L1004-1020)
```javascript
			case 'in merkle':
				// ['in merkle', [['BASE32'], 'data feed name', 'expected value']]
				if (!assocAuthentifiers[path])
					return cb2(false);
				arrUsedPaths.push(path);
				var arrAddresses = args[0];
				var feed_name = args[1];
				var element = args[2];
				var min_mci = args[3] || 0;
				var serialized_proof = assocAuthentifiers[path];
				var proof = merkle.deserializeMerkleProof(serialized_proof);
			//	console.error('merkle root '+proof.root);
				if (!merkle.verifyMerkleProof(element, proof)){
					fatal_error = "bad merkle proof at path "+path;
					return cb2(false);
				}
				dataFeeds.dataFeedExists(arrAddresses, feed_name, '=', proof.root, min_mci, objValidationState.last_ball_mci, false, cb2);
```

**File:** data_feeds.js (L13-107)
```javascript
function dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, max_mci, bAA, handleResult){
	var start_time = Date.now();
	var bLimitedPrecision = (max_mci < constants.aa2UpgradeMci);
	if (bAA) {
		var bFound = false;
		function relationSatisfied(v1, v2) {
			switch (relation) {
				case '<': return (v1 < v2);
				case '<=': return (v1 <= v2);
				case '>': return (v1 > v2);
				case '>=': return (v1 >= v2);
				default: throw Error("unknown relation: " + relation);
			}
		}
		function valueIsNumber() {
			if (typeof value === 'string') {
				const float = string_utils.toNumber(value, bLimitedPrecision);
				return float !== null;
			}
			return true;
		}
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
			storage.assocUnstableMessages[unit].forEach(function (message) {
				if (message.app !== 'data_feed')
					return;
				var payload = message.payload;
				if (!ValidationUtils.hasOwnProperty(payload, feed_name))
					return;
				var feed_value = payload[feed_name];
				if (relation === '=') {
					if (value === feed_value || value.toString() === feed_value.toString())
						bFound = true;
					return;
				}
				if (relation === '!=') {
					// search only within the same type, otherwise 'abc' != 123 but we don't want to say that they are not equal, because they are incomparable
					if (valueIsNumber()) {
						if (value.toString() !== feed_value.toString())
							bFound = true;
					}
					else {
						if (value !== feed_value)
							bFound = true;
					}
					return;
				}
				if (typeof value === 'number' && typeof feed_value === 'number') {
					if (relationSatisfied(feed_value, value))
						bFound = true;
					return;
				}
				var f_value = (typeof value === 'string') ? string_utils.toNumber(value, bLimitedPrecision) : value;
				var f_feed_value = (typeof feed_value === 'string') ? string_utils.toNumber(feed_value, bLimitedPrecision) : feed_value;
				if (f_value === null && f_feed_value === null) { // both are strings that don't look like numbers
					if (relationSatisfied(feed_value, value))
						bFound = true;
					return;
				}
				if (f_value !== null && f_feed_value !== null) { // both are either numbers or strings that look like numbers
					if (relationSatisfied(f_feed_value, f_value))
						bFound = true;
					return;
				}
				if (typeof value === 'string' && typeof feed_value === 'string') { // only one string looks like a number
					if (relationSatisfied(feed_value, value))
						bFound = true;
					return;
				}
				// else they are incomparable e.g. 'abc' > 123
			});
			if (bFound)
				break;
		}
		if (bFound)
			return handleResult(true);
	}
	async.eachSeries(
		arrAddresses,
		function(address, cb){
			dataFeedByAddressExists(address, feed_name, relation, value, min_mci, max_mci, cb);
		},
		function(bFound){
			console.log('data feed by '+arrAddresses+' '+feed_name+relation+value+': '+bFound+', df took '+(Date.now()-start_time)+'ms');
			handleResult(!!bFound);
		}
	);
```

**File:** data_feeds.js (L139-164)
```javascript
	var key_prefix = 'df\n'+address+'\n'+feed_name+'\n'+prefixed_value;
	var bFound = false;
	var options = {};
	switch (relation){
		case '=':
			options.gte = key_prefix+'\n'+strMaxMci;
			options.lte = key_prefix+'\n'+strMinMci;
			options.limit = 1;
			break;
		case '>=':
			options.gte = key_prefix;
			options.lt = 'df\n'+address+'\n'+feed_name+'\n'+type+'\r';  // \r is next after \n
			break;
		case '>':
			options.gt = key_prefix+'\nffffffff';
			options.lt = 'df\n'+address+'\n'+feed_name+'\n'+type+'\r';  // \r is next after \n
			break;
		case '<=':
			options.lte = key_prefix+'\nffffffff';
			options.gt = 'df\n'+address+'\n'+feed_name+'\n'+type+'\n';
			break;
		case '<':
			options.lt = key_prefix;
			options.gt = 'df\n'+address+'\n'+feed_name+'\n'+type+'\n';
			break;
	}
```

**File:** test/formula.test.js (L3123-3132)
```javascript
test('is_valid_merkle_proof obj', t => {

	var merkleSet = createMerkleSet();
	var trigger = { data: { proof: merkleSet.proof, element: merkleSet.element } };
	var stateVars = {};
	evalFormulaWithVars({ conn: null, formula: `is_valid_merkle_proof(trigger.data.element, trigger.data.proof)`, trigger: trigger, locals: {  }, stateVars: stateVars,  objValidationState: objValidationState, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU'}, (res, complexity, count_ops) => {
		t.deepEqual(res, true);
		t.deepEqual(complexity, 2);
	})
});
```
