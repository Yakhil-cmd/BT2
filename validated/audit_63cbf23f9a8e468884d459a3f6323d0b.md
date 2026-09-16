Based on my research, I found a close analog in ocore's asset metadata handling.

### Title
Unvalidated `asset_metadata` name field allows control-character/format injection into wallet UI - (File: wallet.js)

### Summary
Similar to the Rocketpool `setTimezoneLocation`/`ValidateDAOMemberEmail` bug (arbitrary attacker-controlled strings accepted with only a length check and later trusted/displayed by consumer apps), ocore's asset metadata name field, published via a `data` message payload by any asset issuer, is stored and re-displayed to wallets with essentially no format/content validation.

### Finding Description
Any address can issue an asset and later post a `data` app message referencing that asset (`{asset: <own asset>, name: <...>, decimals: <...>}`). When another node's wallet fetches this metadata via `hub/get_asset_metadata` and then reads the joint containing the `data` message, `fetchAssetMetadata` only checks that `payload.name` is truthy — it never verifies that `payload.name` is a string, checks its length, or rejects control characters (`\n`, `\r`, ANSI escape sequences, etc.): [1](#0-0) 

The value is then stored directly in the `asset_metadata` table and surfaced as the asset's display `name`: [2](#0-1) 

This is structurally identical to the reported Rocketpool issue: a low-privilege actor (here, any asset issuer/registry for their own asset) submits a string that is stored via a DAG-recorded message and later consumed/displayed as trusted metadata (an asset's ticker/name) by wallets, exchanges, or other consuming applications, without the strict format enforcement that other message types in the same codebase apply. By contrast, other user-supplied strings that ocore does treat as untrusted output are explicitly sanitized against newlines and length overflow, e.g. data-feed names/values: [3](#0-2)  and poll questions/choices: [4](#0-3) 
No equivalent validation exists for `case "data"` payloads in general message validation (`validation.js`) or in `aa_validation.js`, which only requires it be a "non-empty object": [5](#0-4) 

### Impact Explanation
An attacker can define an asset and publish a `name` value containing newlines, carriage returns, ANSI/terminal control sequences, or text impersonating another asset/brand (e.g. a name string crafted to look like `"OBYTE (verified)\nBalance: 1000000"`), which will be inserted verbatim into local wallet databases and rendered in asset lists/pickers of consuming wallets and services (light wallets, exchanges, bots) with no sanitization at the point of storage or display. This can be used for spoofing/social-engineering attacks against users choosing which asset to send/receive, analogous to the Rocketpool timezone/email field being abused to display falsified "Balance"/"Status" strings. There is no direct fund-theft primitive purely from this bug, but it enables spoofing that can facilitate follow-on fraud (e.g., tricking a user into treating a scam asset as a trusted one), which is a Medium-severity issue in this ecosystem where wallets rely on asset metadata to disambiguate look-alike assets.

### Likelihood Explanation
Trivial to trigger: any user can issue a new asset (no special privilege required) and post a `data` message with a crafted `name` field referencing that asset; the metadata request/response and storage path (`hub/get_asset_metadata`, `fetchAssetMetadata`) will accept it as long as `payload.name` is truthy.

### Recommendation
Enforce a strict schema for the `data` app payload used for asset metadata (and for `asset_metadata`-consuming code in `wallet.js`): require `payload.name` to be a string, cap its length (mirroring `constants.MAX_DATA_FEED_NAME_LENGTH`-style limits), reject control characters (`\n`, `\r`, and other non-printables) the same way data-feed names/values are sanitized in `validation.js`, and sanitize/escape the value again at display time in any GUI/wallet code that renders `asset_metadata.name`.

### Proof of Concept
1. Issue a new asset unit `A` from address `X` (`asset` app message).
2. From `X`, post a `data` app message: `{asset: A, name: "Trusted\nBalance: 1000000", decimals: 2}`.
3. Any wallet that calls `readAssetMetadata`/`fetchAssetMetadata` for asset `A` will store and display the crafted `name` string without any sanitization, as shown in `wallet.js` lines 1464-1481.

### Citations

**File:** wallet.js (L1458-1474)
```javascript
					objJoint.unit.messages.forEach(function(message){
						if (message.app !== 'data')
							return;
						var payload = message.payload;
						if (payload.asset !== asset)
							return;
						if (!payload.name)
							return handleMetadata("no name in asset metadata "+metadata_unit);
						var decimals = (payload.decimals !== undefined) ? parseInt(payload.decimals) : undefined;
						if (decimals !== undefined && !ValidationUtils.isNonnegativeInteger(decimals))
							return handleMetadata("bad decimals in asset metadata "+metadata_unit);
						var verb = isUpdatableRegistry(registry_address) ? "REPLACE" : "INSERT " + db.getIgnore();
						db.query(
							verb + " INTO asset_metadata (asset, metadata_unit, registry_address, suffix, name, decimals) \n\
							VALUES (?,?,?, ?,?,?)",
							[asset, metadata_unit, registry_address, suffix, payload.name, decimals],
							function(){
```

**File:** wallet.js (L1475-1481)
```javascript
								var objMetadata = {
									metadata_unit: metadata_unit,
									suffix: suffix,
									decimals: decimals,
									name: payload.name
								};
								handleMetadata(null, objMetadata);
```

**File:** validation.js (L1792-1811)
```javascript
			if (typeof payload.question !== 'string')
				return callback("no question in poll");
			if (payload.question !== payload.question.trim())
				return callback("question must be trimmed");
			if (!isNonemptyArray(payload.choices))
				return callback("no choices in poll");
			if (payload.choices.length > constants.MAX_CHOICES_PER_POLL)
				return callback("too many choices in poll");
			let seenChoices = Object.create(null);
			for (var i=0; i<payload.choices.length; i++) {
				if (typeof payload.choices[i] !== 'string')
					return callback("all choices must be strings");
				if (payload.choices[i].trim().length === 0)
					return callback("all choices must be longer than 0 chars");
				if (payload.choices[i].length > constants.MAX_CHOICE_LENGTH)
					return callback("all choices must be "+ constants.MAX_CHOICE_LENGTH + " chars or less");
				if (seenChoices[payload.choices[i]])
					return callback("all choices must be different");
				seenChoices[payload.choices[i]] = true;
			}
```

**File:** validation.js (L1933-1944)
```javascript
			for (var feed_name in payload){
				if (feed_name.length > constants.MAX_DATA_FEED_NAME_LENGTH)
					return callback("feed name "+feed_name+" too long");
				if (feed_name.indexOf('\n') >=0 )
					return callback("feed name "+feed_name+" contains \\n");
				var value = payload[feed_name];
				if (typeof value === 'string'){
					if (value.length > constants.MAX_DATA_FEED_VALUE_LENGTH)
						return callback("data feed value too long: " + value);
					if (value.indexOf('\n') >=0 )
						return callback("value "+value+" of feed name "+feed_name+" contains \\n");
				}
```

**File:** aa_validation.js (L84-90)
```javascript
				case 'profile':
				case 'data':
				case 'temp_data':
					if (!isNonemptyObject(payload))
						return cb2('payload of app=' + message.app + ' must be non-empty object or formula: ' + JSON.stringify(payload));
					cb2();
					break;
```
