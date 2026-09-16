### Title
Sensitive Private Attestation Profile Data Logged to Console Regardless of Parse Outcome - (File: private_profile.js)

### Summary
`getPrivateProfileFromJsonBase64()` in `private_profile.js` decodes an externally-supplied base64 string into a JSON string and unconditionally writes the full decoded content to the console via `console.log(privateProfileJson)` *before* it attempts `JSON.parse()` and before any validation of the content occurs. [1](#0-0)  This mirrors the reported .NET bug class where an unparsed/unvalidated sensitive token (a JWT) was written to logs — here the analog is a private attestation profile (which contains personally identifying attested fields such as name, DOB, passport number, etc., per the field's own doc comment) being logged in cleartext regardless of whether parsing succeeds or fails.

### Finding Description
The function is explicitly documented to return `objPrivateProfile.src_profile`, an object of attested personal fields tied to a specific attestation unit. [2](#0-1)  Before any parsing or structural validation is performed, the raw decoded JSON (containing this private data) is dumped straight to console output: `console.log(privateProfileJson);` at line 21, immediately after the base64 decode and before the `try { JSON.parse(...) }` block. [1](#0-0)  Because this logging happens unconditionally — prior to any success/failure branch — it is even broader than the reported ASP.NET issue (which only logged on parse failure): here the private profile is logged on every single invocation, valid or malformed, successfully parsed or not.

This function is exported (`exports.getPrivateProfileFromJsonBase64`) for use by wallet/UI layers that consume externally supplied data — e.g., a profile payload embedded in an attestation URI or shared by a counterparty/attestor device — meaning the logged content originates from data an unprivileged peer or counterparty can construct and pass to a node/wallet process. [3](#0-2) 

### Impact Explanation
Console/log output in Node.js deployments is frequently persisted to disk (stdout redirection, PM2 logs, journald, log aggregation) or displayed on shared terminals. Logging the decoded private profile — which per the function's own documentation contains attested personal fields (`src_profile`) tied to a real-world identity/attestation — creates an information-disclosure vector: any process, log-collection pipeline, or person with read access to logs can recover private, attested personal data that was never meant to be persisted outside the encrypted wallet database. This matches CVE-2021-34532's disclosure class (sensitive payload written to logs) applied to identity-attestation data rather than a JWT.

### Likelihood Explanation
The logging is unconditional (not gated behind a debug flag or verbose-logging switch) and triggers on every call to `getPrivateProfileFromJsonBase64`, which processes attacker/counterparty-supplied base64 content before any validation. Any caller path that feeds a private-profile payload (e.g., from a scanned URI, a device chat message, or a shared attestation link) into this function will unconditionally leak the private fields to the log — no crafted malformed input is even required.

### Recommendation
Remove the `console.log(privateProfileJson)` statement at private_profile.js:21, or replace it with a redacted/structural-only debug log (e.g., logging only field names, not values) gated behind an explicit debug configuration flag that defaults to off. Any future diagnostic logging of this data should occur only after validation succeeds and should avoid printing raw attested field values.

### Proof of Concept
1. Construct a base64-encoded JSON string containing a `src_profile` object with sensitive personal fields (e.g., `{"unit":"...","payload_hash":"...","src_profile":{"passport_id":["1234567890","blindingvalue"]}}`).
2. Call `require('./private_profile.js').getPrivateProfileFromJsonBase64(payload_base64)` (reachable via any wallet/UI code path that decodes an attestation-profile URI or a peer-shared profile payload).
3. Observe that the decoded plaintext JSON, including the sensitive `src_profile` field values, is written to stdout/log via `console.log` at line 21 — before parsing and before any address/hash validation — regardless of whether the payload is ultimately valid.

### Citations

**File:** private_profile.js (L12-18)
```javascript
/*
returns objPrivateProfile {
	unit: "...", // attestation unit
	payload_hash: "...", // pointer to attestation payload in this unit
	src_profile: object // attested fields
}
*/
```

**File:** private_profile.js (L19-27)
```javascript
function getPrivateProfileFromJsonBase64(privateProfileJsonBase64){
	var privateProfileJson = Buffer.from(privateProfileJsonBase64, 'base64').toString('utf8');
	console.log(privateProfileJson);
	try{
		var objPrivateProfile = JSON.parse(privateProfileJson);
	}
	catch(e){
		return null;
	}
```

**File:** private_profile.js (L194-198)
```javascript
exports.getPrivateProfileFromJsonBase64 = getPrivateProfileFromJsonBase64;
exports.parseAndValidatePrivateProfile = parseAndValidatePrivateProfile;
exports.parseSrcProfile = parseSrcProfile;
exports.savePrivateProfile = savePrivateProfile;
exports.getFieldsForAddress = getFieldsForAddress;
```
