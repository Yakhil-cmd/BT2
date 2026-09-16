## Title
Front-running griefing causes indefinite DoS on unique-ID registration functionality of state-var based Autonomous Agents - (File: `test/samples/things_registry_and_marketplace.oscript`, `aa_composer.js`, `main_chain.js`)

## Summary
The bug class described in the report — an attacker front-running a caller's transaction that claims a user-supplied unique identifier, causing the legitimate caller's transaction to permanently fail a "does this ID already exist" check — has a direct analog in ocore's Autonomous Agent (AA) framework. Any AA that stores ownership/registration state keyed by a value taken from `trigger.data` (exactly the pattern used in ocore's own bundled example AA) is vulnerable: because units are gossiped and visible in the DAG before they become stable, an attacker can observe a pending trigger unit, extract the same identifier, and race a competing trigger to the AA. Trigger processing order is deterministic (`level`, then `unit` hash) rather than submission time or fee, so an attacker only needs a trigger that resolves to an equal-or-earlier position in this order to permanently grief a specific ID and bounce the victim's unit.

## Finding Description
The reference AA `test/samples/things_registry_and_marketplace.oscript` implements exactly the vulnerable pattern from the report: registration uniqueness is enforced purely by checking a state variable keyed on attacker/user-controlled `trigger.data.id`: [1](#0-0) 

If `var['owner_' || $id]` is already set, the trigger bounces with `'thing ' || $id || ' already registered'`, permanently preventing the original submitter from ever registering that `$id` if someone else's trigger for the same `$id` gets processed first.

Because Obyte units are broadcast to the P2P network as soon as they are composed (well before their MCI stabilizes), a would-be registrant's pending unit — including its `trigger.data.id` payload — is publicly visible before it becomes final. Any observer can copy this `id`, build their own trigger unit for the same AA, and race it into the DAG.

Once both units are included, the order in which primary AA triggers are executed is deterministic but not first-submitted-first-processed: they are selected and queued when their MCI stabilizes by [2](#0-1) 
and then executed via [3](#0-2) 
Both orderings sort ties by `level` and then by `unit` (hash) — not by broadcast time, fee, or gas price. An attacker can therefore win the race merely by ensuring their competing trigger stabilizes at an equal-or-earlier `level`/`unit` ordering, which is entirely feasible for an unprivileged, adversarial user simply reacting quickly to an observed pending unit.

## Impact Explanation
This enables a griefing/DoS attack against any AA-based registry, marketplace, naming, or ID-allocation contract built on this common and officially-demonstrated oscript pattern:
- The legitimate registrant's trigger unit bounces (loses the bounce fee paid to the AA) and permanently cannot claim the intended identifier, since the identifier is now irrevocably owned by the attacker.
- An attacker can systematically front-run all registrations for a given AA, making the "register new item under this ID" functionality effectively unusable — an indefinite DoS on that core AA feature, matching the severity of the original report (protocol feature rendered non-operational for affected users) and constituting fund loss for the victim (the wasted bounce fee) and freezing of the intended state (the ID can never be claimed by the rightful owner).

## Likelihood Explanation
Likelihood is high for any deployed AA using this idiom (which is explicitly shown as best-practice sample code in the repository and is a very common building block for name/asset/NFT registries on Obyte). Exploitation requires no special privilege — any AA trigger sender can observe pending units in the DAG and race a copy-cat trigger, and the deterministic level/unit-hash tie-break does not protect against a motivated attacker submitting promptly.

## Recommendation
- Avoid relying on user-supplied, guessable/copyable identifiers as the sole locking mechanism for state-changing operations in AAs; where possible, derive the identifier deterministically from data that cannot be copied by a third party (e.g., combine with `trigger.address` or `trigger.unit`), or use a state-var-based counter allocated atomically by the AA itself instead of a value chosen by the caller.
- Document this front-running/griefing risk prominently in the oscript documentation and in bundled sample AAs (including `things_registry_and_marketplace.oscript`) so that AA authors design commit-reveal or address-scoped identifier schemes for registries where uniqueness matters.
- Consider providing an oscript-level primitive (e.g., a "reserve-then-confirm" pattern) that lets AA authors defend against this class of attack without needing to reimplement anti-front-running logic themselves.

## Proof of Concept
1. Alice wants to register thing `id = "rare-name"` via the `things_registry_and_marketplace` AA (or any similarly-designed production AA) and broadcasts a trigger unit `U_A` with `data: {register: true, id: "rare-name"}`.
2. `U_A` is visible in the DAG/network immediately, prior to MCI stabilization, per ocore's normal unit propagation.
3. Mallory (an unprivileged, unrelated user) observes `U_A`'s `data.id` field, and quickly composes and broadcasts her own trigger unit `U_M` with the identical `data: {register: true, id: "rare-name"}`, targeting a `level`/unit ordering that resolves ahead of (or level-tied but hash-ordered before) `U_A` — cf. ordering logic in [4](#0-3) 
4. When the MCI stabilizes, `handleAATriggers` processes both triggers in `(mci, level, unit, address)` order; whichever trigger sorts first sets `var['owner_rare-name'] = <its author>` per [5](#0-4) 
5. If `U_M` sorts first, `U_A` (Alice's trigger, processed second) hits the check at [6](#0-5) 
and bounces with `'thing rare-name already registered'`, permanently denying Alice the identifier and consuming her bounce fee — reproducing the exact griefing/indefinite-DoS impact described in the source report, adapted to ocore's AA trigger model.

### Citations

**File:** test/samples/things_registry_and_marketplace.oscript (L22-32)
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

**File:** aa_composer.js (L59-68)
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
```
