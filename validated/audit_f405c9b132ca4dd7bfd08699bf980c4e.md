## Title
Unbounded Recursive Loop in `readAllControlAddresses` Enables Denial of Service via Crafted Shared-Address Chains - (File: wallet_defined_by_addresses.js)

### Summary
`readAllControlAddresses` in `wallet_defined_by_addresses.js` recursively walks the `shared_address_signing_paths` table to discover all "control addresses" of a shared address, but performs no cycle detection, no visited-set tracking, and no depth limit. A paired device (an unprivileged peer relative to this node's own trust boundary) can craft a chain of `new_shared_address` messages that causes two or more shared addresses to reference each other as member/control addresses, producing an unterminated recursive query loop — the same root-cause class as CVE-2018-8036 (loop with an unreachable exit condition, CWE-835), applied here to on-disk graph data instead of file-format tokens.

### Finding Description
`handleNewSharedAddress` [1](#0-0)  accepts a `definition` and a `signers` map from any correspondent device, validates that the computed c-hash matches, that signer addresses referenced in the definition are syntactically valid, and calls `Definition.validateDefinition`. That validation enforces `MAX_COMPLEXITY`/`MAX_OPS` on the definition's own expression tree [2](#0-1) , but it does **not** prevent two independently-created, individually-valid shared addresses from being linked into a cycle through the `shared_address_signing_paths` table (e.g., shared address A's `address` column contains a member address that is itself shared address B, and B's member address is A). Nothing in `handleNewSharedAddress`/`addNewSharedAddress` [3](#0-2)  checks for such a cross-reference at insertion time.

Once such a cyclic reference is persisted, calling `readAllControlAddresses` walks it forever: [4](#0-3) 
Each recursive call queries `shared_address_signing_paths` for the addresses just discovered and recurses on the result with no memo/visited set and no maximum depth, so if the address graph is cyclic, the function keeps calling itself indefinitely, growing the async call chain without bound until resource exhaustion (excessive DB queries, memory growth, or process crash) — precisely the "loop with unreachable exit condition" bug class from the report, since the only exit condition (`rows.length === 0`) can never be satisfied when the underlying data forms a cycle.

### Impact Explanation
This function is exported (`exports.readAllControlAddresses`) and used by `wallet.js` in wallet flows that operate over sets of shared/control addresses (e.g., determining balances/control addresses for cosigning and private-payment forwarding). Triggering the infinite recursion on a victim's node causes that node's wallet logic to hang or crash while processing legitimate operations that touch the affected shared address (balance checks, private-payment forwarding, cosigner discovery), i.e., a targeted denial of service against the wallet component of the node. It does not directly cause double-spend or consensus disagreement, since this code path is off the tx-validation critical path, but it does match a concrete "node unable to confirm/process" outcome scoped to the wallet layer reachable by a paired device.

### Likelihood Explanation
A paired device is explicitly an actor a background agent must consider under this scan's scope ("paired device can reach ... wallet and contract message handling"). Creating two shared addresses that reference each other only requires sending two `new_shared_address` messages (or one `create_new_shared_address`/`approve_new_shared_address` sequence) where each definition's `["address", ...]` leaf points at the address that will become the other shared address, both of which pass existing per-message validation individually. No cryptographic or consensus-level barrier prevents this cross-referencing, so likelihood of constructing the cycle is high once an attacker controls or colludes with the paired device sending these definitions.

### Recommendation
Add cycle/visited-set tracking (e.g., pass and check an accumulating `Set` of already-visited addresses) and/or a maximum recursion depth in `readAllControlAddresses`, returning early or with an error once an address is revisited or the depth limit is exceeded. Additionally, consider rejecting `new_shared_address`/`approve_new_shared_address` definitions whose member addresses, when resolved through `shared_address_signing_paths`, would introduce a cycle back to the address being created.

### Proof of Concept
1. Attacker-controlled paired device A sends `new_shared_address` for address `S1`, whose definition's `["address", ...]` leaf is set to `S2` (an address not yet known locally, which is acceptable since `handleNewSharedAddress` only checks internal consistency of the message, not whether `S2` exists yet).
2. The same or another paired device then sends `new_shared_address` for `S2`, whose definition references `S1` as a member address.
3. Both messages pass `handleNewSharedAddress` validation and get persisted into `shared_addresses`/`shared_address_signing_paths` via `addNewSharedAddress` [3](#0-2) .
4. Any subsequent call to `readAllControlAddresses(conn, [S1], ...)` (directly or via wallet.js flows using it) alternates between resolving `S1 → S2 → S1 → S2 → …` indefinitely [4](#0-3) , exhausting the DB connection pool / call stack and hanging or crashing the victim node's wallet processing.

Note: I was not able to trace the exact single call site in `wallet.js` that invokes `readAllControlAddresses` with attacker-influenced addresses (only the `exports` and one usage match were found in the index); confirming the precise trigger path in `wallet.js` would benefit from a full-repository review in a Devin session, since index size limits may have excluded some surrounding context in that file.

### Citations

**File:** wallet_defined_by_addresses.js (L239-268)
```javascript
function addNewSharedAddress(address, arrDefinition, assocSignersByPath, bForwarded, onDone){
//	network.addWatchedAddress(address);
	db.query(
		"INSERT "+db.getIgnore()+" INTO shared_addresses (shared_address, definition) VALUES (?,?)", 
		[address, JSON.stringify(arrDefinition)], 
		function(){
			var arrQueries = [];
			for (var signing_path in assocSignersByPath){
				var signerInfo = assocSignersByPath[signing_path];
				db.addQuery(arrQueries, 
					"INSERT "+db.getIgnore()+" INTO shared_address_signing_paths \n\
					(shared_address, address, signing_path, member_signing_path, device_address) VALUES (?,?,?,?,?)", 
					[address, signerInfo.address, signing_path, signerInfo.member_signing_path, signerInfo.device_address]);
			}
			async.series(arrQueries, function(){
				console.log('added new shared address '+address);
				eventBus.emit("new_address-"+address);
				eventBus.emit("new_address", address);

				if (conf.bLight){
					db.query("INSERT " + db.getIgnore() + " INTO unprocessed_addresses (address) VALUES (?)", [address], onDone);
				} else if (onDone)
					onDone();
				if (!bForwarded)
					forwardNewSharedAddressToCosignersOfMyMemberAddresses(address, arrDefinition, assocSignersByPath);
			
			});
		}
	);
}
```

**File:** wallet_defined_by_addresses.js (L378-415)
```javascript
function handleNewSharedAddress(body, callbacks){
	if (!ValidationUtils.isArrayOfLength(body.definition, 2))
		return callbacks.ifError("invalid definition");
	if (typeof body.signers !== "object" || Object.keys(body.signers).length === 0)
		return callbacks.ifError("invalid signers");
	try {
		var addr = objectHash.getChash160(body.definition);
	}
	catch (e) {
		return callbacks.ifError("invalid definition: " + e);
	}
	if (body.address !== addr)
		return callbacks.ifError("definition doesn't match its c-hash");
	for (var signing_path in body.signers){
		var signerInfo = body.signers[signing_path];
		if (signerInfo.address && signerInfo.address !== 'secret' && !ValidationUtils.isValidAddress(signerInfo.address))
			return callbacks.ifError("invalid member address: " + JSON.stringify(signerInfo.address));
	}
	const assocDefinitionAddresses = extractAddressPathsFromDefinition(body.definition);
	for (let signing_path in body.signers) {
		const signerInfo = body.signers[signing_path];
		if (assocDefinitionAddresses[signing_path] !== signerInfo.address)
			return callbacks.ifError("signer address at path " + signing_path + " doesn't match definition");
	}
	for (let def_path in assocDefinitionAddresses) {
		if (!body.signers[def_path])
			return callbacks.ifError("no signer for definition address at path " + def_path);
	}
	determineIfIncludesMeAndRewriteDeviceAddress(body.signers, function(err){
		if (err)
			return callbacks.ifError(err);
		validateAddressDefinition(body.definition, function(err){
			if (err)
				return callbacks.ifError(err);
			addNewSharedAddress(body.address, body.definition, body.signers, body.forwarded, callbacks.ifOk);
		});
	});
}
```

**File:** wallet_defined_by_addresses.js (L545-561)
```javascript
function readAllControlAddresses(conn, arrAddresses, handleLists){
	conn = conn || db;
	conn.query(
		"SELECT DISTINCT address, shared_address_signing_paths.device_address, (correspondent_devices.device_address IS NOT NULL) AS have_correspondent \n\
		FROM shared_address_signing_paths LEFT JOIN correspondent_devices USING(device_address) WHERE shared_address IN(?)", 
		[arrAddresses], 
		function(rows){
			if (rows.length === 0)
				return handleLists([], []);
			var arrControlAddresses = rows.map(function(row){ return row.address; });
			var arrControlDeviceAddresses = rows.filter(function(row){ return row.have_correspondent; }).map(function(row){ return row.device_address; });
			readAllControlAddresses(conn, arrControlAddresses, function(arrControlAddresses2, arrControlDeviceAddresses2){
				handleLists(_.union(arrControlAddresses, arrControlAddresses2), _.union(arrControlDeviceAddresses, arrControlDeviceAddresses2));
			});
		}
	);
}
```

**File:** definition.js (L616-638)
```javascript
			default:
				return cb("unknown op: "+op);
		}
	}
	
	var complexity = 0;
	var count_ops = 0;
	evaluate(arrDefinition, 'r', false, function(err, bHasSig){
		if (err)
			return handleResult(err);
		if (!bHasSig && !bAssetCondition)
			return handleResult("each branch must have a signature");
		if (complexity > constants.MAX_COMPLEXITY)
			return handleResult("complexity exceeded");
		if (count_ops > constants.MAX_OPS)
			return handleResult("number of ops exceeded");
		if (objValidationState.max_complexity) {
			objValidationState.complexity += complexity;
			if (objValidationState.complexity > objValidationState.max_complexity)
				return handleResult(`custom complexity limit ${objValidationState.max_complexity} exceeded`);
		}
		handleResult();
	});
```
