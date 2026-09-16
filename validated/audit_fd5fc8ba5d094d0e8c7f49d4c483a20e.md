## Analysis

The reported bug class is "first-come-first-served resource registration can be frontrun by watching pending transactions and racing to claim the same identifier before the legitimate owner." The closest reachable analog in `ocore` is the AA-based registry pattern shipped in the codebase, where an autonomous agent lets any trigger sender claim a caller-chosen identifier by simply checking that no state variable already exists for it, with no staking, commit-reveal, or ownership-binding to the original claimant's intent. [1](#0-0) 

AA trigger execution order is deterministic but driven by DAG unit inclusion (level/mci ordering), which an attacker can influence by getting their competing unit included earlier in the DAG: [2](#0-1) 

### Title
Registration of caller-chosen identifiers in AA state (e.g. things-registry pattern) can be frontrun, permanently denying the legitimate claimant - (File: test/samples/things_registry_and_marketplace.oscript)

### Summary
The `things_registry_and_marketplace.oscript` AA — a registry pattern shipped in the ocore codebase as a reference implementation for "register a unique ID and optionally sell it" — assigns ownership of an arbitrary, sender-chosen `id` to whichever trigger unit is processed first. There is no commit/reveal, no staking cost, and no binding of the claim to the original submitter's intent (e.g. no hash-based reservation). Because AA trigger processing order is determined by the underlying DAG structure (unit `level`, inclusion order, `main_chain_index`), an attacker who observes an honest user's pending `register` trigger for a given `id` can broadcast a competing trigger for the same `id` and, if their unit is admitted into the DAG earlier (better connectivity, more witnesses reachable, priority fees, etc.), register the `id` first. The honest user's later-processed trigger will then `bounce`.

### Finding Description
The registration case in the AA is:
```
{ // register a new thing and optionally put it on sale
    if: `{trigger.data.register AND $id}`,
    init: `{
        if (var['owner_' || $id])
            bounce('thing ' || $id || ' already registered');
        ...
    }`,
    messages: [ { app: 'state', state: `{ var['owner_' || $id] = trigger.address; ... }` } ]
}
``` [1](#0-0) 

The `$id` is fully attacker-controlled (`trigger.data.id`) and the only uniqueness check is `var['owner_' || $id]` being unset at the time the trigger is processed: [3](#0-2) 

AA triggers are queued into `aa_triggers` when their MCI stabilizes and executed in an order dictated by DAG inclusion (`units.level, units.unit, address`), not by wall-clock submission order visible to the user: [4](#0-3) 

Because units are gossiped through the peer-to-peer network before they stabilize, an adversary monitoring the network for a pending unit whose `data.register`/`data.id` fields reveal an intended registration can construct and broadcast their own trigger for the same `id`. If the attacker's unit ends up earlier in the DAG ordering that determines AA-trigger execution sequence, `var['owner_' || $id]` gets set to the attacker's address first, and the honest user's registration subsequently bounces via `bounce('thing ' || $id || ' already registered')`.

### Impact Explanation
A successful frontrun permanently denies the honest party the specific identifier they intended to register (a name, NFT ID, physical-object ID, etc., per the AA's own documented use cases), and lets the attacker either extort the rightful claimant (list it "for sale" at an inflated price) or simply grief them. Because the AA has no staking/slashing or cost recovery mechanism as in the referenced report's fix, there is also no economic disincentive or accountability trail once the attacker owns the ID — they can hold it indefinitely for a one-time trigger fee. This is a concrete case of a single unprivileged trigger sender causing unauthorized loss of an on-chain claim/resource that another user rightfully attempted to acquire.

### Likelihood Explanation
Exploitation requires no special privileges — any address can send a trigger unit with `data.register` and any `id`. The only requirement is that the attacker's competing unit becomes included in the DAG (and thus processed by the AA) ahead of the victim's, which is achievable by a well-connected attacker monitoring gossiped units before they stabilize, similar to mempool-monitoring frontrunning in account-based chains. Given that AA definitions like this ship as the canonical registry/marketplace example in the codebase and are likely to be reused or adapted by developers, the pattern (register a caller-chosen key with a bare existence check and no commit/reveal) is broadly reproducible and reachable by any AA trigger sender.

### Recommendation
Adopt a commit/reveal scheme for identifier registration, analogous to the Audius fix referenced in the report: require the claimant to first submit a hash of `id` combined with a secret and their own address, wait a delay/lockup period, then reveal the actual `id` and secret to finalize the claim. Alternatively, bind the registerable `id` to a value that is intrinsically tied to the claimant (e.g., derive it from `trigger.address` plus a nonce) so that an attacker cannot preemptively claim an identifier chosen by someone else, or require an escrowable stake that can be forfeited/slashed if the claim is later proven to be a griefing frontrun.

### Proof of Concept
1. Alice wants to register `id = "myname"` via a trigger unit `{data: {register: true, id: "myname"}}` sent to the registry AA.
2. Alice broadcasts her unit into the network; it propagates before stabilizing.
3. Bob, monitoring the network, observes Alice's pending unit and immediately crafts and broadcasts his own trigger unit `{data: {register: true, id: "myname"}}` from his own address, using better connectivity/more witness reach to get it included earlier in the DAG (lower `level`/earlier inclusion for the relevant MCI).
4. Once stabilized, `aa_triggers` for that MCI are processed in `ORDER BY units.level, units.unit, address` — see `main_chain.js` lines 1691-1706 — so Bob's unit executes first: `var['owner_myname']` is set to Bob's address.
5. Alice's trigger is then processed and hits `if (var['owner_' || $id]) bounce('thing ' || $id || ' already registered');` in `test/samples/things_registry_and_marketplace.oscript` lines 24-26, permanently denying her the identifier she intended to claim.

### Citations

**File:** test/samples/things_registry_and_marketplace.oscript (L16-19)
```text
{
	init: `{
		$id = trigger.data.id;
	}`,
```

**File:** test/samples/things_registry_and_marketplace.oscript (L22-44)
```text
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
			},
```

**File:** main_chain.js (L1691-1721)
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
			function (rows) {
				count_aa_triggers = rows.length;
				if (rows.length === 0)
					return finishMarkMcIndexStable();
				var arrValues = rows.map(function (row) {
					return "("+mci+", "+conn.escape(row.unit)+", "+conn.escape(row.address)+")";
				});
				conn.query("INSERT INTO aa_triggers (mci, unit, address) VALUES " + arrValues.join(', '), function () {
					finishMarkMcIndexStable();
					// now calling handleAATriggers() from write.js
				//	process.nextTick(function(){ // don't call it synchronously with event emitter
				//		eventBus.emit("new_aa_triggers"); // they'll be handled after the current write finishes
				//	});
				});
			}
```
