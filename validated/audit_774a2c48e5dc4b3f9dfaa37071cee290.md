## Title
`handleDuplicateAddressDefinition` unconditionally rejects a legitimate, content-identical re-disclosure of an address definition, permanently bouncing a valid unit - (File: validation.js)

### Summary
`validation.js`'s `validateAuthor()` / `validateDefinition()` path is Obyte's analog of ERC-6551's counterfactual, content-addressed deployment: an address is `chash160(definition)`, and the *first* unit from that address must carry the explicit `definition` so nodes can verify `chash(definition) === address` [1](#0-0) . Just like the reported Kimap bug where a second, structurally-identical `CREATE2` deployment reverts because the deterministic address was already "claimed" by an earlier caller, ocore's equivalent path — a second unit re-disclosing the *same, matching* definition for an address whose definition was already recorded — is **unconditionally rejected**, regardless of whether the content actually matches:

```js
function handleDuplicateAddressDefinition(arrAddressDefinition){
//	if (!bNonserial || objValidationState.arrAddressesWithForkedPath.indexOf(objAuthor.address) === -1)
		return callback("duplicate definition of address "+objAuthor.address+", bNonserial="+bNonserial);
	// ... unreachable equality check below
``` [2](#0-1) 

### Finding Description
When an author explicitly includes a `definition` field, `validateDefinition()` looks up the address's stored definition via `storage.readDefinitionByAddress()` [3](#0-2) :
- `ifDefinitionNotFound` (first use): verifies `chash(definition) === definition_chash` and accepts.
- `ifFound` (a stable definition for that address already exists): calls `handleDuplicateAddressDefinition`.

The intended logic (visible as a commented-out guard) was to only reject *nonserial forked-path* duplicates and otherwise fall through to an equality check that would accept a second unit whose attached definition hashes identically to the already-known one:
```js
//	if (!bNonserial || objValidationState.arrAddressesWithForkedPath.indexOf(objAuthor.address) === -1)
		return callback("duplicate definition of address "+objAuthor.address+", bNonserial="+bNonserial);
```
Because the `if` is commented out, the `return callback("duplicate definition...")` executes unconditionally, and the subsequent code that compares `objectHash.getChash160(arrAddressDefinition)` against `objectHash.getChash160(objAuthor.definition)` (lines 1491-1497) is dead code [4](#0-3) . Every unit that re-attaches a `definition` for an address whose definition already became stable is rejected outright — even when the definition is byte-for-byte identical to the one already on record.

This is reachable by any ordinary, unprivileged unit poster without needing an attacker at all: `composer.js`'s `composeAuthorsForAddresses()` decides whether to attach `definition` based on whether a *stable, good* prior disclosure is visible to the composing node [5](#0-4) . If a wallet composes and broadcasts two units from a brand-new address in quick succession (e.g., two payments from a freshly-generated HD address, or two devices sharing the same address), and the first unit stabilizes on the network before the second is validated, the second unit's local knowledge is stale and it will include `definition` again — triggering the `ifFound` branch and getting permanently rejected as "duplicate," even though the content matches exactly what's already recorded. The same dynamic applies to the "frontrun" scenario from the external report: any actor able to produce/rebroadcast a unit carrying the same address+definition first (e.g., a network echo/replay, or a legitimate co-signer racing another wallet instance for a shared/multisig address created via `wallet_defined_by_addresses.js`'s templated shared addresses [6](#0-5) ) causes the genuinely intended transaction to be bounced.

### Impact Explanation
The rejected unit cannot be included in the DAG, so the address's legitimate spend is denied — funds become effectively stuck/frozen for that unit until the wallet detects the definition is already known and resubmits without it. This matches the accepted impact class of "freezing" of otherwise valid spends reachable directly by an unprivileged unit poster, and does not require any privileged or malicious-node capability — a plain race between two ordinary broadcasts of the same address's own transactions is sufficient.

### Likelihood Explanation
The condition is trivially reachable: any address whose *first* disclosed definition takes time to stabilize while a second transaction from the same address is composed and broadcast (very plausible with wallets that pipeline transactions, multi-device wallets sharing signing material, or simple retries/resubmissions) hits this bug deterministically, since the guard that would allow a matching duplicate is permanently disabled.

### Recommendation
Restore (or reintroduce with correct semantics) the intended check in `handleDuplicateAddressDefinition`: allow a duplicate `definition` field through when `objectHash.getChash160(arrAddressDefinition) === objectHash.getChash160(objAuthor.definition)`, and only surface an error when the definitions actually differ (or, per the original design intent, only for non-serial forked-path conflicts).

### Proof of Concept
1. Generate a fresh address `A` with definition `D` (`chash160(D) === A`).
2. Compose unit `U1` from `A`, including `definition: D` (first use).
3. Before `U1`'s definition disclosure is seen as stable locally, compose unit `U2` from `A` as well, also including `definition: D` (because the composer's stability check hasn't caught up yet — see `composer.js:897-917`).
4. Broadcast `U1`; wait until it becomes stable network-wide.
5. Broadcast `U2`. On validation, `storage.readDefinitionByAddress()` now resolves via `ifFound` (since `U1`'s definition is stable), invoking `handleDuplicateAddressDefinition(D)` with the *same* `D` as `objAuthor.definition`. Despite the definitions being identical, the function unconditionally returns `callback("duplicate definition of address A, bNonserial=...")`, and `U2` is rejected — even though nothing malicious or inconsistent occurred.

### Citations

**File:** validation.js (L1464-1483)
```javascript
	function validateDefinition(){
		if (!("definition" in objAuthor))
			return callback();
		// the rest assumes that the definition is explicitly defined
		var arrAddressDefinition = objAuthor.definition;
		storage.readDefinitionByAddress(conn, objAuthor.address, objValidationState.last_ball_mci, {
			ifDefinitionNotFound: function(definition_chash){ // first use of the definition_chash (in particular, of the address, when definition_chash=address)
				try {
					if (objectHash.getChash160(arrAddressDefinition) !== definition_chash)
						return callback("wrong definition: " + objectHash.getChash160(arrAddressDefinition) + "!==" + definition_chash);
				}
				catch (e) {
					return callback("definition hash failed: " + e.toString());
				}
				callback();
			},
			ifFound: function(arrAddressDefinition2){ // arrAddressDefinition2 can be different
				handleDuplicateAddressDefinition(arrAddressDefinition2);
			}
		});
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

**File:** composer.js (L897-920)
```javascript
			var and_stable = (last_ball_mci < constants.unstableInitialDefinitionUpgradeMci || last_ball_mci >= constants.pemCurvesFixMci) ? "AND is_stable=1 AND main_chain_index<=" + parseInt(last_ball_mci) : "";
			conn.query(
				"SELECT 1 FROM unit_authors CROSS JOIN units USING(unit) \n\
				WHERE address=? AND sequence='good' " + and_stable + " \n\
				LIMIT 1", 
				[from_address], 
				function(rows){
					if (rows.length === 0) // first message from this address
						return setDefinition();
					// try to find last stable change of definition, then check if the definition was already disclosed
					conn.query(
						"SELECT definition \n\
						FROM address_definition_changes CROSS JOIN units USING(unit) LEFT JOIN definitions USING(definition_chash) \n\
						WHERE address=? AND is_stable=1 AND sequence='good' AND main_chain_index<=? \n\
						ORDER BY main_chain_index DESC, level DESC LIMIT 1", 
						[from_address, last_ball_mci],
						function(rows){
							if (rows.length === 0) // no definition changes at all
								return cb2();
							var row = rows[0];
							row.definition ? cb2() : setDefinition(); // if definition not found in the db, add it into the json
						}
					);
				}
```

**File:** wallet_defined_by_addresses.js (L417-437)
```javascript
function createNewSharedAddress(arrDefinition, assocSignersByPath, callbacks){
	if (!includesMyDeviceAddress(assocSignersByPath))
		return callbacks.ifError("my device address not mentioned");
	var address = objectHash.getChash160(arrDefinition);
	handleNewSharedAddress({address: address, definition: arrDefinition, signers: assocSignersByPath}, {
		ifError: callbacks.ifError,
		ifOk: function(){
			// share the new address with all cosigners
			var arrDeviceAddresses = [];
			for (var signing_path in assocSignersByPath){
				var signerInfo = assocSignersByPath[signing_path];
				if (signerInfo.device_address !== device.getMyDeviceAddress() && arrDeviceAddresses.indexOf(signerInfo.device_address) === -1)
					arrDeviceAddresses.push(signerInfo.device_address);
			}
			arrDeviceAddresses.forEach(function(device_address){
				sendNewSharedAddress(device_address, address, arrDefinition, assocSignersByPath);
			});
			callbacks.ifOk(address);
		}
	});
}
```
