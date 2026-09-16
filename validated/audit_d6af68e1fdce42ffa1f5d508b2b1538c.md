### Title
Uncaught throw inside `arrCandidates.sort()` comparator crashes node when resolving ambiguous unstable AA data feeds - ([File: data_feeds.js])

### Summary
`readDataFeedValue()` in `data_feeds.js` resolves ambiguous unstable AA data-feed candidates by sorting them, and its comparator function unconditionally `throw`s an `Error` when it cannot establish an order between two candidates. Because this `sort()` call executes synchronously inside the normal AA-trigger/formula-evaluation code path, the thrown exception is not passed through the usual `err`/`callback` error-handling convention used everywhere else in this file and in `aa_composer.js`, and can propagate up as an uncaught exception, crashing the node process — directly analogous to CVE-2018-10935, where a crafted server-side sort control caused an unhandled crash in the LDAP server.

### Finding Description
`readDataFeedValue()` builds `arrCandidates` from all AA-authored, unstable `data_feed` messages matching a requested `feed_name`/oracle set within an MCI window [1](#0-0) . When more than one candidate matches and the caller did not request `ifseveral === 'abort'`, the code sorts the candidates by `latest_included_mc_index` then by `level`, and if both are equal for two candidates it executes:

```js
arrCandidates.sort(function (a, b) {
    if (a.latest_included_mc_index < b.latest_included_mc_index) return -1;
    if (a.latest_included_mc_index > b.latest_included_mc_index) return 1;
    if (a.level < b.level) return -1;
    if (a.level > b.level) return 1;
    if (bIncludeAllUnstable) // still ambiguous, sort randomly (it's OK outside AAs)
        return 1;
    throw Error("can't sort candidates "+a+" and "+b);
});
``` [2](#0-1) 

`level` is a per-unit DAG property that is **not globally unique** — sibling units built on the same parent set (or units from different authors/oracles progressing in parallel) commonly end up with the same `level` value while both remain unstable and share the same `latest_included_mc_index`. Any address (including an ordinary user, not just a privileged oracle) can post a `data_feed` message from any of its own addresses; an AA merely needs to be configured (or an attacker needs to trigger an AA) to read a data feed from two or more addresses (`oracles` array in `readDataFeedValueByParams`, validated only for being non-empty and containing valid addresses, up to 10) with `unstable_opts` set and `ifseveral` left as the default `'last'` [3](#0-2) . By posting two units (from two different addresses referenced as oracles for that AA) at the same DAG level, each containing a `data_feed` message with the same `feed_name`, both units become “ambiguous unstable candidates,” and the comparator throws.

Because this `throw` occurs synchronously inside `Array.prototype.sort`, and `readDataFeedValue`/`readDataFeedValueByParams` are invoked synchronously from the oscript `data_feed` evaluator inside AA trigger handling (`formula/evaluation.js`, called from `aa_composer.js`'s `handleTrigger`/`evaluateAA` chain), there is no `try/catch` boundary converting this into a normal validation/bounce error the way other AA errors are handled (e.g., via `setFatalError`/`bounce`). This differs from virtually every other error path in this file, which passes errors through `handleResult`/`cb` callbacks instead of throwing.

### Impact Explanation
An uncaught exception thrown mid-way through AA trigger processing can abort the write-lock/db-transaction handling of `aa_composer.js`'s `handleTrigger`, and if not caught anywhere up the stack, crashes the Node.js process (unhandled exception). This is a network-availability impact: a node that crashes while processing an incoming unit/trigger becomes unable to continue validating and confirming new units, matching the “network unable to confirm new units” acceptance criterion. Because AA data feeds and their evaluation are deterministic consensus-critical code, this can be triggered on any node processing the same trigger, causing a chain-wide denial of service rather than a single node’s local failure.

### Likelihood Explanation
Likelihood is a function of how easy it is to make two data-feed-posting units land at the same `level` and same `latest_included_mc_index` while both remain unstable — this is a natural, frequently occurring DAG condition (many parallel units share levels), not a rare edge case. Any unprivileged unit poster who controls (or colludes with) two addresses referenced as `oracles` by a target AA, or an AA author who defines an AA that reads a data feed from multiple/untrusted oracle addresses, can deliberately engineer this collision. No special privileges, node compromise, or protocol-level malicious behavior is required — only crafting two ordinary units with a `data_feed` message.

### Recommendation
Replace the `throw` in the comparator with a call to `setFatalError`-style error propagation (or return the AA trigger's own bounce logic), and make `readDataFeedValue` communicate the ambiguity via its `handleResult`/`objResult` callback path (e.g., set `objResult.bAbortedBecauseOfSeveral = true`) instead of throwing synchronously. Additionally, wrap synchronous AA formula evaluation code paths in try/catch at the boundary where formulas invoke external state-reading functions like `data_feed`, so any unexpected exception is converted into a graceful bounce rather than a process crash.

### Proof of Concept
1. Deploy (or use an existing) AA whose oscript calls `data_feed[[oracles=$addrA,$addrB, feed_name='X', ifseveral='last']]` reading from at least two independent addresses, without `unstable_opts` disabled.
2. From two different wallets/addresses (`addrA`, `addrB`), post two ordinary units, each with a `data_feed` message `{X: <any value>}`, constructed on parent sets so that both units end up with the same DAG `level` (achievable by having both units use the same set of parent units) and remain unstable together (same `latest_included_mc_index` once included).
3. Send/trigger the AA so it evaluates the `data_feed` read while both units are still unstable.
4. `readDataFeedValue()` collects both units into `arrCandidates`, finds `latest_included_mc_index` and `level` equal for both, and the sort comparator throws `Error("can't sort candidates ...")` [4](#0-3) , propagating as an uncaught exception through the synchronous AA evaluation call stack in `aa_composer.js`.

### Citations

**File:** data_feeds.js (L211-240)
```javascript
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
```

**File:** data_feeds.js (L255-267)
```javascript
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

**File:** data_feeds.js (L342-372)
```javascript
function readDataFeedValueByParams(params, max_mci, unstable_opts, cb) {
	var oracles = params.oracles;
	if (!oracles)
		return cb("no oracles in readDataFeedValueByParams");
	if (!ValidationUtils.isNonemptyArray(oracles))
		return cb("oracles must be non-empty array");
	if (!oracles.every(ValidationUtils.isValidAddress))
		return cb("some oracle addresses are not valid");
	if (oracles.length > 10)
		return cb("too many oracles");
	var feed_name = params.feed_name;
	if (!feed_name || typeof feed_name !== 'string')
		return cb("empty feed_name or not a string");
	var value = null;
	if ('feed_value' in params) {
		value = params.feed_value;
		if (!isValidValue(value))
			return cb("bad feed_value: " + util.inspect(value, { depth: 5 }));
	}
	var min_mci = 0;
	if ('min_mci' in params) {
		min_mci = params.min_mci;
		if (!ValidationUtils.isNonnegativeInteger(min_mci))
			return cb("bad min_mci: " + util.inspect(min_mci, { depth: 5 }));
	}
	var ifseveral = 'last';
	if ('ifseveral' in params) {
		ifseveral = params.ifseveral;
		if (ifseveral !== 'abort' && ifseveral !== 'last')
			return cb("bad ifseveral: " + util.inspect(ifseveral, { depth: 5 }));
	}
```
