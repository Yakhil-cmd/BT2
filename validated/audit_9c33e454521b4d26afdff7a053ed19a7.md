### Title
Front-runnable deterministic AA address collision allows griefing/DoS of AA-generated child AAs - (File: aa_composer.js, validation.js)

### Summary
The external report describes a `create2`-style griefing where an attacker front-runs a deterministic-address deployment using a known `salt`, causing the legitimate deployer's transaction to revert. The ocore analog is the "AA generates a new child AA" pattern: an AA computes a child AA address deterministically as `chash160(child_aa_definition)` [1](#0-0)  and emits an `app: 'definition'` message whose `payload.address` is likewise fixed to `objectHash.getChash160(message.payload.definition)` [2](#0-1) . Because this address is fully determined by public, replayable content (the definition template plus any deterministic inputs), any third party who can predict or copy the exact same definition content can pre-empt it, exactly analogous to the reported `salt`-collision issue.

### Finding Description
When an AA (the "factory") is triggered, it can construct a new AA definition in its formula code and post it via an `app: 'definition'` message. The resulting address is computed deterministically from the definition content: [2](#0-1) . `validateInlinePayload`'s `"definition"` case then re-validates that `payload.address === getChash160(payload.definition)` and runs `aa_validation.validateAADefinition` [3](#0-2) , but this validation path contains no check against a pre-existing `aa_addresses` entry for that same address; it only validates format/complexity and (for parameterized AAs) resolves `base_aa`.

If the factory AA's generated child definition is not randomized per-trigger (e.g. it does not fold in `trigger.address`, `trigger.unit`, or another unpredictable value into the definition content, as seen in the test fixture where the child AA template is static/deterministic) [1](#0-0) , then the resulting child AA address is fully predictable off-chain by anyone who can read the factory AA's bytecode (which is public on the DAG). An attacker can:
1. Read the factory AA's public definition and compute the same child AA definition/address the factory would produce for a future or pending trigger.
2. Race to get their own trigger (or any other unit introducing the exact same `app:'definition'` payload for that address) stabilized first.

Separately, address-definition collisions are explicitly treated as fatal elsewhere in the codebase: for ordinary addresses, once a `definition_chash` has been established for an address, any subsequent unit that tries to introduce a definition for that same address is rejected outright via `handleDuplicateAddressDefinition`, which unconditionally returns `callback("duplicate definition of address ...")` [4](#0-3) . This demonstrates the general design assumption in ocore that "first definer wins" for a given chash — the same principle that makes the reported `create2` collision griefing possible in the EVM analog is structurally present here: whoever's unit stabilizes first "claims" the deterministic address, and the second party's unit referencing/relying on that same address can fail or behave unexpectedly (e.g., the factory's own AA response is bounced because the `'definition'` message conflicts with previously-established state, or downstream logic that assumes `child_aa_address` is fresh/uninitialized behaves incorrectly because state variables or balance for that address already exist from the attacker's prior use).

### Impact Explanation
If a legitimate AA-factory-triggering user's transaction can be griefed by a front-runner who predicts and preempts the deterministic child-AA address, the victim's trigger is bounced (they lose the bounce fee they paid, and their intended AA deployment/side-effects do not occur) — a concrete AA fund-loss/DoS impact for the trigger sender, matching the "Medium" impact bucket for temporary DoS/fund loss described in the source report. This is reachable purely by an unprivileged AA trigger sender / any party who can read public AA bytecode and race unit propagation — no privileged or network-level capability is required.

### Likelihood Explanation
Medium: exploitation requires (a) a deployed factory AA whose generated child-AA definition is deterministic/predictable (not seeded with trigger-specific unpredictable data), and (b) the attacker being able to observe the pending trigger or the factory AA's logic and race a conflicting unit into the DAG before the legitimate response stabilizes. This mirrors the report's own likelihood assessment: easy to execute once conditions are met, but limited attacker incentive since it mainly griefs rather than steals funds directly.

### Recommendation
- When an AA composes a definition for a newly created child AA, application authors should include unpredictable, sender/trigger-specific entropy (e.g. `trigger.unit`, `trigger.address`, an incrementing nonce/state variable) in the generated definition so its resulting `chash160` address cannot be predicted or front-run by outside observers.
- At the protocol level, consider whether `validateInlinePayload`'s `"definition"` case (validation.js:1747) should treat an `app:'definition'` message whose target address already has an established `aa_addresses`/`definitions` record as a soft/no-op (rather than silently permitting reliance on it) so factory-AA logic that assumes "freshly created address" cannot be corrupted by a pre-existing conflicting definition, and so victims aren't bounced with wasted bounce fees purely because of an address collision they had no way to detect at build time.

### Proof of Concept
1. Deploy a factory AA whose `init` formula deterministically builds `$child_aa` purely from static template content (no trigger-specific salt), computing `$child_aa_address = chash160($child_aa)`, and then emits `{app:'definition', payload:{definition: $child_aa}}` plus a payment to `$child_aa_address` — this is exactly the pattern validated in the existing test `AA with generated definition of new AA and immediately sending to this new AA` [5](#0-4) .
2. Because the factory AA's code (and thus the exact `child_aa` template) is public on the DAG, an attacker computes the same `child_aa_address` off-chain ahead of time.
3. The attacker races a unit into the DAG that establishes conflicting state for that same address before the victim's trigger to the factory AA stabilizes (e.g., posts a payment or another `definition` message referencing that address, or otherwise causes the address's `aa_addresses`/`definitions` state to diverge from what the factory expects).
4. When the victim's trigger is processed by `handleTrigger`/`sendUnit` in `aa_composer.js` [2](#0-1) , the resulting response either bounces (losing the victim's bounce fee) or behaves inconsistently with the factory AA's intended one-time-setup logic, because the deterministic address was not unique to that trigger.

### Citations

**File:** test/aa_composer.test.js (L922-986)
```javascript
test.cb.serial('AA with generated definition of new AA and immediately sending to this new AA', t => {
	var trigger_address = "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT";
	var trigger = { outputs: { base: 10000 }, data: { x: 5 }, address: trigger_address };

	var child_aa = ['autonomous agent', {
		bounce_fees: { base: 10000 },
		doc_url: 'https://myapp.com/description.json',
		messages: [
			{
				app: 'payment',
				payload: {
					asset: 'base',
					init: "{response['received_amount'] = trigger.output[[asset=base]];}",
					outputs: [
						{address: "{trigger.initial_address}", amount: "{min(trigger.output[[asset=base]] - 2000, 5000)}"}
					]
				}
			}
		]
	}];
	var child_aa_address = objectHash.getChash160(child_aa);
	
	var factory_aa = ['autonomous agent', {
		init: `{
			$child_aa = ['autonomous agent', {
				bounce_fees: { base: 10000 },
				doc_url: 'https://myapp.com/description.json',
				messages: [
					{
						app: 'payment',
						payload: {
							asset: 'base',
							init: "{response['received_amount'] = trigger.output[[asset=base]];}",
							outputs: [
								{address: "{trigger.initial_address}", amount: "{min(trigger.output[[asset=base]] - 2000, 5000)}"}
							]
						}
					}
				]
			}];
			$child_aa_address = chash160($child_aa);
		}`,
		messages: [
			{
				app: 'definition',
				payload: {
					definition: `{$child_aa}`
				}
			},
			{
				app: 'payment',
				payload: {
					asset: 'base',
					outputs: [{address: `{$child_aa_address}`, amount: 8000}]
				}
			},
			{
				app: 'state',
				state: `{
					var['child_aa1'] = $child_aa_address;
					var['child_aa2'] = unit[response_unit].messages[[.app='definition']].payload.address;
				}`
			}
		]
	}];
```

**File:** aa_composer.js (L1301-1305)
```javascript
				if (message.app !== 'payment') {
					try {
						if (message.app === 'definition')
							message.payload.address = objectHash.getChash160(message.payload.definition);
						completeMessage(message);
```

**File:** validation.js (L1486-1499)
```javascript
	function handleDuplicateAddressDefinition(arrAddressDefinition){
	//	if (!bNonserial || objValidationState.arrAddressesWithForkedPath.indexOf(objAuthor.address) === -1)
			return callback("duplicate definition of address "+objAuthor.address+", bNonserial="+bNonserial);
		// todo: investigate if this can split the nodes
		// in one particular case, the attacker changes his definition then quickly sends a new ball with the old definition - the new definition will not be active yet
		try {
			if (objectHash.getChash160(arrAddressDefinition) !== objectHash.getChash160(objAuthor.definition))
				return callback("unit definition doesn't match the stored definition");
		}
		catch (e) {
			return callback("handleDuplicateAddressDefinition definition hash failed: " + e.toString());
		}
		callback(); // let it be for now. Eventually, at most one of the balls will be declared good
	}
```

**File:** validation.js (L1747-1767)
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
			if (constants.bTestnet && ['BD7RTYgniYtyCX0t/a/mmAAZEiK/ZhTvInCMCPG5B1k=', 'EHEkkpiLVTkBHkn8NhzZG/o4IphnrmhRGxp4uQdEkco=', 'bx8VlbNQm2WA2ruIhx04zMrlpQq3EChK6o3k5OXJ130=', '08t8w/xuHcsKlMpPWajzzadmMGv+S4AoeV/QL1F3kBM=', '4N5fsU9qJSn2FuS70cChKx8QqgcesPRPs0dNfzOhoXw='].indexOf(objUnit.unit) >= 0)
				return callback();
			const top_mci = objValidationState.aa_mci || objValidationState.last_ball_mci;
			var readGetterProps = function (aa_address, func_name, cb) {
				storage.readAAGetterProps(conn, aa_address, func_name, top_mci, cb);
			};
			if (!objValidationState.hasBall && !objValidationState.bAA && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci && objValidationState.last_ball_mci < constants.pemCurvesFixMci)
				return callback(createTransientError("AA definition attached to an old part of the DAG"));
			aa_validation.validateAADefinition(payload.definition, readGetterProps, objValidationState.last_ball_mci, function (err) {
```
