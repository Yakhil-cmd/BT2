### Title
Front-running of hash-locked address spends via publicly revealed preimage - ([File: definition.js])

### Summary
Addresses whose definition uses a `['hash', {algo, hash}]` authentifier are unlocked purely by revealing a secret preimage — no signature is required for that authentifier. Once a unit spending such an address is broadcast (propagated but not yet stable), the plaintext secret is visible in the unit's `authentifiers` before finality. An attacker who observes the secret in the still-unstable unit can immediately craft a competing unit from the same address using the identical secret, redirecting the funds to himself, and race to win the DAG's serial-address conflict resolution. This is structurally the same bug class as the NodeRegistry `convict`/`revealConvict` front-running issue: a value that must eventually be revealed publicly to complete an action is exploitable by anyone who watches the network and races a copy of the reveal before/around the original sender's transaction is confirmed.

### Finding Description
An address can be defined with a `hash` authentifier: [1](#0-0) 

and it is verified purely by comparing the sha256 of whatever string the spender supplies as `assocAuthentifiers[path]` against the committed hash — no signature check is combined with it in this leaf: [2](#0-1) 

`extractAddressPathsFromDefinition` in the shared-address module explicitly labels such a leaf as `'secret'`, confirming that knowing the secret string is sufficient authorization: [3](#0-2) 

When the legitimate owner posts a unit that reveals the secret as an authentifier to spend from this address, that unit is broadcast to the network and relayed hub-to-hub while still unstable/unconfirmed. Any peer receiving this joint (before it is stable) can read the plaintext secret out of `objAuthor.authentifiers`, since it must be present in clear text for other nodes to validate the `hash` condition. An attacker can then immediately construct his own unit, spending from the very same address with the identical secret but with outputs directed to an address he controls.

Because in ocore's DAG two spends from the same address are not immediately mutually exclusive, the conflict is resolved lazily by the "serial address use" logic: [4](#0-3) 

and finally by main-chain stabilization, which explicitly says the smaller/earlier-selected unit on the same MCI wins and the other becomes `final-bad`: [5](#0-4) 

So the race is not merely about who reaches the network first — it is about who ends up positioned to be selected as `good` when the conflicting units are finally resolved, which an attacker who is fast and well-connected (able to get his competing unit included with the right timing/level) can win, exactly mirroring the "watch a pending on-chain reveal, then race your own transaction using the exposed secret" pattern described in the NodeRegistry report.

### Impact Explanation
Any funds protected solely (or partially, in an `or`/`weighted and` combined with `hash`) by a `hash` authentifier are vulnerable to theft: an attacker who is simply relaying/observing the network can extract the secret from the legitimate owner's not-yet-stable spending unit and craft a conflicting unit sending the same funds to himself. If his unit wins the serial-conflict resolution (smaller unit id at the same MCI, or better witnessed level/best-parent positioning), the legitimate spend becomes `final-bad`/`temp-bad` and the attacker's spend becomes `good`, resulting in concrete unauthorized spending of the victim's coins. This class of address (hash-only or hash-combined authentifier, used e.g. for atomic-swap/HTLC-style constructs) is directly reachable and usable by any wallet user or unprivileged unit poster.

### Likelihood Explanation
Exploitation only requires network-level visibility of propagating (unstable) units and the ability to post a competing unit — both available to any ordinary, unprivileged participant, not requiring any elevated/hub/node privilege. The attacker does not need to control a hub or a peer relationship with the victim; simply being connected to the network and watching relayed joints is enough to see the secret before stability. The main uncertainty is winning the race for "good" sequence, but this is a probabilistic/timing advantage attackers can optimize for (e.g., low-latency connections, choosing favorable parents), not something requiring privileged access.

### Recommendation
Avoid using `hash`-only authentifiers as the sole spending condition for addresses holding value, since the secret is necessarily exposed on the network before finality. If a commit/reveal-like primitive is required in oscript/definitions, bind the reveal to the same author/signature that also authorizes the destination (e.g., require `hash` AND `sig` in `and`, or commit to the destination address inside the hashed pre-image itself, e.g. `hash(secret || destination_address)`), so that a would-be front-runner who extracts the secret cannot repurpose it for an output address of his own choosing. Documentation/tooling that helps users construct `hash`-based definitions should warn about this front-running risk explicitly.

### Proof of Concept
1. Alice defines address `A` with definition `['hash', {algo: 'sha256', hash: H(secret)}]` (or combined via `or`) and funds it.
2. Alice creates and broadcasts a unit `U1` spending from `A` to her own address `A_out`, with `authentifiers.r = secret` in cleartext, per [2](#0-1) .
3. `U1` propagates through the network while unstable. Mallory, an ordinary connected peer, receives/relays `U1` and reads `secret` from its authentifiers before `U1` becomes stable.
4. Mallory immediately constructs and posts `U2`, also spending from `A` using the same `secret`, with output to `A_mallory`.
5. Both `U1` and `U2` pass validation as being from address `A` with a valid `hash` authentifier; per [4](#0-3) , they are flagged as conflicting (`temp-bad`) until stabilized.
6. On stabilization, per [5](#0-4) , only one of `U1`/`U2` becomes `good`; if `U2` wins (e.g., smaller unit hash on the same MCI, or Mallory manipulated timing/parents to his advantage), Mallory's spend to `A_mallory` succeeds and Alice's original spend `U1` becomes `final-bad`, resulting in Mallory stealing the funds that were meant for Alice.

### Citations

**File:** definition.js (L252-267)
```javascript
			case 'hash':
				if (bInNegation)
					return cb(op+" cannot be negated");
				if (bAssetCondition)
					return cb("asset condition cannot have "+op);
				if (!isNonemptyObject(args))
					return cb(op + " args must be a non-empty object");
				if (hasFieldsExcept(args, ["algo", "hash"]))
					return cb("unknown fields in "+op);
				if (args.algo === "sha256")
					return cb("default algo must not be explicitly specified");
				if ("algo" in args && args.algo !== "sha256")
					return cb("unsupported hash algo");
				if (!ValidationUtils.isValidBase64(args.hash, constants.HASH_LENGTH))
					return cb("wrong base64 hash");
				return cb();
```

**File:** definition.js (L756-772)
```javascript
			case 'hash':
				// ['hash', {algo: 'sha256', hash: 'base64'}]
				if (!assocAuthentifiers[path] || typeof assocAuthentifiers[path] !== 'string')
					return cb2(false);
				arrUsedPaths.push(path);
				var algo = args.algo || 'sha256';
				if (algo === 'sha256'){
					var res = (args.hash === crypto.createHash("sha256").update(assocAuthentifiers[path], "utf8").digest("base64"));
					if (!res)
						fatal_error = "bad hash at path "+path;
					cb2(res);
				}
				else {
					fatal_error = "unsupported hash algo at path "+path;
					return cb2(false);
				}
				break;
```

**File:** wallet_defined_by_addresses.js (L365-367)
```javascript
			case 'hash':
				result[path] = 'secret';
				break;
```

**File:** validation.js (L1304-1327)
```javascript
	function checkSerialAddressUse(){
		var next = (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci) ? validateDefinition : checkNoPendingChangeOfDefinitionChash;
		findConflictingUnits(function(arrConflictingUnitProps){
			if (arrConflictingUnitProps.length === 0){ // no conflicting units
				// we can have 2 authors. If the 1st author gave bad sequence but the 2nd is good then don't overwrite
				objValidationState.sequence = objValidationState.sequence || 'good';
				return next();
			}
			var arrConflictingUnits = arrConflictingUnitProps.map(function(objConflictingUnitProps){ return objConflictingUnitProps.unit; });
			breadcrumbs.add("========== found conflicting units "+arrConflictingUnits+" =========");
			breadcrumbs.add("========== will accept a conflicting unit "+objUnit.unit+" =========");
			objValidationState.arrAddressesWithForkedPath.push(objAuthor.address);
			objValidationState.arrConflictingUnits = (objValidationState.arrConflictingUnits || []).concat(arrConflictingUnits);
			bNonserial = true;
			var arrUnstableConflictingUnitProps = arrConflictingUnitProps.filter(function(objConflictingUnitProps){
				return (objConflictingUnitProps.is_stable === 0);
			});
			// findConflictingUnits() already excludes final-bad rows, so any stable row left here is a real, good competitor
			var bConflictsWithStableUnits = arrConflictingUnitProps.some(function(objConflictingUnitProps){
				return (objConflictingUnitProps.is_stable === 1);
			});
			if (objValidationState.sequence !== 'final-bad') // if it were already final-bad because of 1st author, it can't become temp-bad due to 2nd author
				objValidationState.sequence = bConflictsWithStableUnits ? 'final-bad' : 'temp-bad';
			var arrUnstableConflictingUnits = arrUnstableConflictingUnitProps.map(function(objConflictingUnitProps){ return objConflictingUnitProps.unit; });
```

**File:** main_chain.js (L1421-1450)
```javascript
	function findStableConflictingUnits(objUnitProps, handleConflictingUnits){
		// find potential competitors.
		// units come here sorted by original unit, so the smallest original on the same MCI comes first and will become good, all others will become final-bad
		/*
		Same query optimized for frequent addresses:
		SELECT competitor_units.*
		FROM unit_authors AS this_unit_authors 
		CROSS JOIN units AS this_unit USING(unit)
		CROSS JOIN units AS competitor_units 
			ON competitor_units.is_stable=1 
			AND +competitor_units.sequence='good' 
			AND (competitor_units.main_chain_index > this_unit.latest_included_mc_index)
			AND (competitor_units.main_chain_index <= this_unit.main_chain_index)
		CROSS JOIN unit_authors AS competitor_unit_authors 
			ON this_unit_authors.address=competitor_unit_authors.address 
			AND competitor_units.unit = competitor_unit_authors.unit 
		WHERE this_unit_authors.unit=?
		*/
		conn.query(
			"SELECT competitor_units.* \n\
			FROM unit_authors AS this_unit_authors \n\
			JOIN unit_authors AS competitor_unit_authors USING(address) \n\
			JOIN units AS competitor_units ON competitor_unit_authors.unit=competitor_units.unit \n\
			JOIN units AS this_unit ON this_unit_authors.unit=this_unit.unit \n\
			WHERE this_unit_authors.unit=? AND competitor_units.is_stable=1 AND +competitor_units.sequence='good' \n\
				-- if it were main_chain_index <= this_unit_limci, the competitor would've been included \n\
				AND (competitor_units.main_chain_index > this_unit.latest_included_mc_index) \n\
				AND (competitor_units.main_chain_index <= this_unit.main_chain_index)",
			// if on the same mci, the smallest unit wins becuse it got selected earlier and was assigned sequence=good
			[objUnitProps.unit],
```
