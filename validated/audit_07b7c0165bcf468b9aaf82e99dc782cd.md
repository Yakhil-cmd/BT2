### Title
User-chosen ID squatting in AA registries lets an attacker front-run resource registration and steal the victim's bounce/trigger fee - ([File: test/samples/things_registry_and_marketplace.oscript])

### Summary
The external report describes a "first writer wins" race on a user-chosen identifier (`accountId`): whoever's transaction reaches the contract first with that ID claims it, and any value the legitimate user attached to the losing transaction ends up effectively lost/misdirected to the party who won the race. The equivalent pattern exists in ocore's AA (Autonomous Agent) layer whenever an AA keys ownership/state off an attacker-observable, user-supplied `trigger.data` field instead of `trigger.address`. The reference registry/marketplace AA shipped with ocore is exactly such a design.

### Finding Description
In `test/samples/things_registry_and_marketplace.oscript`, ownership of a "thing" is stored under a state variable keyed purely by a caller-chosen identifier `$id = trigger.data.id` (not by the caller's address): [1](#0-0) 

The registration branch is a first-come-first-served claim:
```
if: `{trigger.data.register AND $id}`,
init: `{
    if (var['owner_' || $id])
        bounce('thing ' || $id || ' already registered');
    ...
}`
``` [2](#0-1) 

Because `$id` is arbitrary attacker/victim-chosen data carried in a plain `data` message of an ordinary unit, it is visible to any observer of the DAG before the triggering unit is included/stabilized by the AA trigger processor (`handlePrimaryAATrigger`, driven by `aa_triggers` ordered by `mci, level, unit`): [3](#0-2) 

An attacker who is watching for a specific `id` (e.g. a valuable name, or an id tied to a marketplace listing the victim intends to create) can post their own `register` trigger for the same `id` and get it included/committed ahead of the victim's unit, since inclusion order is not victim-controlled. When the victim's unit is subsequently processed, the `init` block's `bounce('thing ' || $id || ' already registered')` fires and the whole trigger response bounces.

This mirrors the root cause in the report: an identifier that is meant to be "created" by the legitimate submitter is instead squattable by anyone who can observe it in flight and race to claim it first, because the contract logic never binds the claim to the submitter's identity (e.g., `trigger.address`) or to a commitment/reveal scheme.

### Impact Explanation
When an AA response bounces, the AA refunds the trigger's payment to `trigger.address` **minus the AA's configured `bounce_fees`** (analogous to the gas fee in the report). If a user attaches bytes to their `register` trigger (a common and expected user behavior — many AAs, including this exact template's `buy` case, expect payment attached to `trigger.data`-driven calls), a successful front-run causes:
- The victim's registration attempt to fail with `bounce`.
- The victim to permanently lose the `bounce_fees` portion of their attached funds on every retry, exactly as described in the report ("theft of gas"/fee loss "every time a user attempts to create an account").
- The attacker to obtain the `id` (and, in the marketplace extension, the ability to set a price and later capture the base-asset payment via the `buy` branch), which is a stronger analog to "theft" than the base report even covers, since ocore's version can also result in loss of the underlying named resource itself, not just fees.

This satisfies the "AA fund loss" impact bar: unauthorized diversion of state ownership and fee/value loss reachable by any unprivileged unit poster, with no privileged role required.

### Likelihood Explanation
Likelihood is Medium:
- Exploitation requires only posting a normal `data` message unit — reachable by any unprivileged AA trigger sender.
- It requires the attacker to observe the victim's pending `id` claim before it is committed and to win the race for inclusion order, which is feasible for well-connected nodes/bots monitoring the network for specific high-value `id`s (names, listings), similar to mempool-sniffing bots in other DAG/blockchain ecosystems.
- The bug is a design pattern present in ocore's own official sample AA (used as a template/reference for real-world naming/marketplace/registry AAs), so any AA author who copies this common pattern inherits the vulnerability; it is not a one-off bug in engine code but a systemic risk in a widely-suggested contract idiom.

### Recommendation
- In any AA that lets a caller claim/register a resource keyed by caller-supplied data, bind the claim key to `trigger.address` (or a hash of `trigger.address || $id`) rather than the raw user-chosen `$id` alone, so squatting requires controlling the intended address, not just observing pending data.
- Alternatively, use a commit-reveal scheme: first submit `hash(id, secret)`, wait for stabilization, then reveal `id, secret` to finalize the claim, preventing front-runners from usefully copying an observed plaintext `id`.
- Document this front-running risk explicitly in the reference `things_registry_and_marketplace.oscript` sample (and any similar "first writer wins by arbitrary data key" templates) so downstream AA authors don't propagate the flaw into production registries/marketplaces/name services built on ocore.

### Proof of Concept
1. Alice wants to register the valuable id `"myname"` and, following the marketplace pattern, sends a `register` trigger unit with `trigger.data = {register: true, id: "myname", sell: true, price: 1000}` and attaches `2000` bytes beyond the AA's `bounce_fees` to safely cover fees.
2. Bob observes Alice's unit propagate through the network before it stabilizes/gets processed by `handlePrimaryAATrigger`.
3. Bob immediately posts his own trigger unit with `trigger.data = {register: true, id: "myname"}`.
4. If Bob's unit is ordered/included ahead of Alice's in the `aa_triggers` processing order (`mci, level, unit`) [4](#0-3) , the AA sets `var['owner_myname'] = Bob's address`.
5. Alice's unit is then processed: `if (var['owner_' || $id]) bounce('thing myname already registered')` fires [5](#0-4) , her response bounces, and she loses the AA's `bounce_fees` out of the funds she attached — repeatable on every retry for any id Bob (or any bot) chooses to squat.

### Citations

**File:** test/samples/things_registry_and_marketplace.oscript (L16-43)
```text
{
	init: `{
		$id = trigger.data.id;
	}`,
	messages: {
		cases: [
			{ // register a new thing and optionally put it on sale
				if: `{trigger.data.register AND $id}`,
				init: `{
					if (var['owner_' || $id])
						bounce('thing ' || $id || ' already registered');
					if (trigger.data.sell){
						$price = trigger.data.price;
						if (!$price || !($price > 0) || round($price) != $price)
							bounce('please set a positive integer price');
					}
				}`,
				messages: [
					{
						app: 'state',
						state: `{
							var['owner_' || $id] = trigger.address;
							if (trigger.data.sell AND trigger.data.price)
								var['price_' || $id] = trigger.data.price;
							response['message'] = 'registered' || (trigger.data.sell AND trigger.data.price ? ' and put on sale for ' || trigger.data.price : '');
						}`
					}
				]
```

**File:** aa_composer.js (L59-78)
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
```
