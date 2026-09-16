### Title
Unbounded loop over all unstable in-memory data-feed messages in `dataFeedExists` reachable via AA `in_data_feed` oscript op - ([File: data_feeds.js])

### Summary
`in_data_feed` (used inside AA formulas via `["in data feed", ...]` / `in_data_feed[[...]]`) calls `dataFeeds.dataFeedExists()` with `bAA=true`. In that mode the function iterates `for (var unit in storage.assocUnstableMessages)` over **every currently-unstable unit held in memory**, and for each matching author does a `.forEach()` over all of that unit's messages, looking for `data_feed` messages that match the queried feed name. There is no cap on the number of unstable units/messages scanned, unlike the cosign bug where `FetchAttestations` looped unbounded over attacker-supplied attestations from a malicious registry. [1](#0-0) 

### Finding Description
`dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, max_mci, bAA, handleResult)` is called from AA formula evaluation whenever an `in_data_feed[[...]]` expression is evaluated with `bAA=true`: [2](#0-1) 

Inside, when `bAA` is true, the code walks the entire `storage.assocUnstableMessages` object — i.e., every unit that is currently unstable anywhere on the DAG, not scoped to the oracle address being queried — filtering only after the fact by `objUnit.author_addresses` intersection: [3](#0-2) 

Any unprivileged unit poster can grow the size of `storage.assocUnstableMessages` by posting many valid units containing `data_feed` messages (a message type explicitly permitted for any address) and keeping them from stabilizing (e.g., withholding witnessing/posting on many parallel non-witnessed branches, or simply posting a very large batch of units in a short window before witnesses catch up). Because AA evaluation of `in_data_feed`/`data_feed` happens for **every trigger unit whose AA definition references that oracle**, and the scan cost is proportional to the total number of unstable units/messages network-wide (not to the requested oracle), a burst of attacker-posted data-feed units inflates the cost of every subsequent AA evaluation that uses `in data feed`, for every node processing AA triggers.

This mirrors the cosign root cause exactly: an unbounded loop over an attacker-influenced, unbounded collection, executed synchronously and blocking further processing (there, `FetchAttestations` over registry-returned attestations; here, `dataFeedExists` over all unstable messages in the mempool-equivalent).

### Impact Explanation
Because `handleTrigger`/`evaluateAA` runs synchronously per trigger and this scan runs on the single JS event loop shared by unit validation, AA execution, and stabilization, inflating `storage.assocUnstableUnits`/`assocUnstableMessages` with attacker-posted `data_feed` messages degrades the responsiveness of AA processing for all triggers referencing `in data feed`/`data_feed` conditions across the network, and can delay stabilization of new units (nodes becoming unable to confirm new units in a timely manner) — matching the "network unable to confirm new units" impact bucket for a Medium-severity DoS-class analog.

### Likelihood Explanation
Any address can freely post `data_feed` messages (validated only for name/value length limits, not for total count network-wide), and AAs using `in data feed`/`in_data_feed` referencing a data feed as an oracle are a normal, allowed oscript pattern (`definition.js` `'in data feed'` case, `formula/evaluation.js` `in_data_feed` case), so the trigger path is easily reachable by an unprivileged AA trigger sender or unit poster without any special privilege, hub/proof-serving access, or peer compromise.

### Recommendation
Cap the number of unstable units/messages scanned per `in data feed`/`data_feed` evaluation (e.g., index `assocUnstableMessages` by author address and feed name so the scan is proportional to the actual oracle's unstable posts rather than the entire mempool), and/or impose a hard iteration limit with early abort once a configurable threshold is exceeded, similar to the fix applied upstream in cosign (limiting the number of attestations processed per verification call).

### Proof of Concept
1. From many different unprivileged addresses (or a single address across many units), repeatedly post valid units containing a `data_feed` message (`{app:'data_feed', payload:{name: value}}`), timed so they remain unstable (e.g., broadcast a large batch faster than witnessing/MC advancement can stabilize them).
2. Have an AA definition anywhere on the network reference `in data feed`/`in_data_feed` for any oracle address (a normal, legitimate AA pattern already present in the codebase, e.g. `test/aa.test.js` definition_template example using `['in data feed', ...]`).
3. Trigger that AA; `handleTrigger` → `evaluateAA` → oscript evaluation of `in_data_feed` calls `dataFeeds.dataFeedExists(..., bAA=true, ...)`, which iterates the full, attacker-inflated `storage.assocUnstableMessages` map on every such trigger evaluation, elongating processing time for that trigger and for all other pending AA triggers sharing the event loop.

### Citations

**File:** data_feeds.js (L34-94)
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
```

**File:** formula/evaluation.js (L726-745)
```javascript
						if (typeof evaluated_params.oracles.value !== 'string')
							return setFatalError('oracles is not a string', { arr }, false, cb);
						var arrAddresses = evaluated_params.oracles.value.split(':');
						if (!arrAddresses.every(ValidationUtils.isValidAddress)) // even if some addresses are ok
							return setFatalError('bad oracles', { arr }, false, cb);
						var feed_name = evaluated_params.feed_name.value;
						if (!feed_name || typeof feed_name !== 'string')
							return setFatalError('bad feed name', { arr }, false, cb);
						var value = evaluated_params.feed_value.value;
						var relation = evaluated_params.feed_value.operator;
						if (!isValidValue(value))
							return setFatalError("bad feed_value: "+value, { arr }, false, cb);
						var min_mci = 0;
						if (evaluated_params.min_mci){
							min_mci = evaluated_params.min_mci.value.toString();
							if (!(/^\d+$/.test(min_mci) && ValidationUtils.isNonnegativeInteger(parseInt(min_mci))))
								return setFatalError('bad min_mci', { arr }, false, cb);
							min_mci = parseInt(min_mci);
						}
						dataFeeds.dataFeedExists(arrAddresses, feed_name, relation, value, min_mci, mci, bAA, cb);
```
