### Title
Front-runnable resource-ID squatting in AA state-var registries causes fund loss / griefing - ([File: test/samples/things_registry_and_marketplace.oscript])

### Summary
The reported bug is a "claim race" pattern: a user's intent to reserve a caller-chosen identifier is publicly observable before it is finalized, letting an attacker preemptively claim the same identifier and force the victim's transaction to fail with fees lost. The same pattern is directly reachable in Obyte's Autonomous Agent (AA) model whenever an AA stores a caller-supplied free-form `id` as a unique state-var key without binding it to the caller's own address. The `things_registry_and_marketplace.oscript` sample AA is the canonical (and documented) implementation of this exact pattern in this repo, and it is vulnerable to the same front-running/griefing bug class because AA trigger execution order is not "first submitted, first processed" but instead determined deterministically only after MC stabilization by `(level, unit, address)` — meaning any attacker who observes a pending (unstable, but already broadcast) trigger unit naming a desirable `id` can race a competing unit and win the registration, bouncing the legitimate user's unit.

### Finding Description
`test/samples/things_registry_and_marketplace.oscript` implements a registry where any user can register a "thing" under an arbitrary self-chosen `id`: [1](#0-0) 

```
init: `{ $id = trigger.data.id; }`
...
if: `{trigger.data.register AND $id}`,
init: `{
    if (var['owner_' || $id])
        bounce('thing ' || $id || ' already registered');
    ...
}`
```

`$id` is entirely attacker/user chosen (`trigger.data.id`), exactly like the `accountId` in the reported cross-chain bug, and the AA reserves it in `var['owner_' || $id]` for whoever's trigger unit is processed first [2](#0-1) .

Crucially, the "first" trigger is not the one submitted earliest in real time — a unit is visible on the network (as a free/unstable unit) well before it becomes part of a stable main-chain index, and only once its MCI is marked stable does the engine enqueue its AA trigger for execution, in an order determined purely by `(units.level, units.unit, address)`: [3](#0-2) 

and triggers are dequeued/executed in that same deterministic-but-not-submission-time order: [4](#0-3) 

Because the pending trigger unit (containing `trigger.data.id`) is broadcast and visible to peers before it stabilizes, an attacker monitoring the DAG can construct and broadcast a competing unit carrying the same `id`, targeting parents/levels that let it stabilize ahead of (or in the same MCI as, with a favorable level/unit hash) the victim's unit. This mirrors the report's core weakness: a free, user-chosen identifier whose reservation is decided by a race that an observer can win by watching pending transactions, rather than being cryptographically bound to the submitter (e.g., hashed with `trigger.address`).

### Impact Explanation
When the attacker wins the race and registers the `id` first, the victim's trigger unit executes the `bounce('thing ' || $id || ' already registered')` branch. Bouncing an AA trigger returns the sent amount minus the AA's `bounce_fees`/network fees, meaning the victim permanently loses the fees paid to post and process that transaction and cannot obtain the specific `id` they intended to register — a direct AA-fund-loss/griefing outcome, matching the "Griefing" and "AA fund loss" impact categories used in the original report. Any real dApp built on this common Obyte design pattern (naming registries, NFT-style ID claims, ENS-like services, etc.) inherits the same weakness.

### Likelihood Explanation
Exploitation requires no special privilege — any unprivileged unit poster/AA trigger sender can monitor the p2p-visible DAG for pending trigger units addressed to the vulnerable AA, extract the desired `id` from `trigger.data`, and post a competing trigger before the victim's unit stabilizes. Because trigger execution order depends on DAG level/unit hash rather than arrival time, timing this race is a realistic, low-cost attack once a target AA using this ID-squatting pattern is identified.

### Recommendation
AA authors should never store a caller-supplied identifier as a bare unique key. Instead, derive the registry key from a value bound to the caller (e.g., `var[trigger.address]['id']` or a key salted with `trigger.address`/`trigger.unit`), or require a commit-reveal scheme (hash-commit the id first, reveal/bind it only after the commit is stable) so that observing a pending unit does not reveal enough information to squat the same identifier. This should be documented/highlighted as a standard pitfall for AA authors implementing on-chain "registries" of user-chosen names/IDs.

### Proof of Concept
1. Deploy the `things_registry_and_marketplace.oscript` AA (or any AA using the same `var['owner_' || trigger.data.id]` pattern).
2. Victim broadcasts a trigger unit with `data: { register: true, id: "desired-name" }`.
3. Attacker observes this unit on the network before it is included in a stable MCI, and immediately broadcasts their own trigger unit with the same `data: { register: true, id: "desired-name" }`, choosing parents so their unit is favorably ordered by `(level, unit)` per `main_chain.js` `handleAATriggers` ordering.
4. When the MCI stabilizes, if the attacker's unit is processed first, `var['owner_desired-name']` is set to the attacker's address.
5. The victim's trigger, processed afterward, hits `bounce('thing desired-name already registered')`, losing the network/bounce fees and never obtaining the desired `id`.

### Citations

**File:** test/samples/things_registry_and_marketplace.oscript (L16-26)
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
```

**File:** test/samples/things_registry_and_marketplace.oscript (L33-43)
```text
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

**File:** aa_composer.js (L59-69)
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
```
