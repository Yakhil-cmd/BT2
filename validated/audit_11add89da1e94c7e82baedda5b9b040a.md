This confirms the code path: `getRepoPubKey`/`getOrgPublicKey` fetch `pk.Key` via `client.REST` from a host string that is either the authenticated host or `repo.RepoHost()`, and `pk.Key` is placed directly into `setSecret` without a length check before slicing.

### Title
Attacker-controlled short public key response causes panic (index out of range) in `setSecret` - ([File: pkg/cmd/secret/set/set.go])

### Summary
`setSecret` decodes `pk.Key` from base64 and immediately slices it as `decodedPubKey[0:32]` without validating that the decoded key is at least 32 bytes long. If the public key JSON returned by the API/enterprise host decodes to fewer than 32 bytes, this slicing expression panics because the upper bound exceeds the slice's capacity.

### Finding Description
The public key value comes from an HTTP response fetched by `getPubKey` in [1](#0-0)  which is called by `getOrgPublicKey`/`getRepoPubKey`/`getEnvPubKey`/`getUserPublicKey`, all of which pass through a `host` argument (`repo.RepoHost()` for repo/env, or the resolved `host` for org/user) into `client.REST`. This host is attacker-influenced whenever the CLI is pointed at a malicious GitHub Enterprise-style host, which the rules explicitly permit as an attacker capability. The returned `PubKey.Key` field is an unvalidated string from the JSON body.

In `setSecret`, the code does:
```go
decodedPubKey, err := base64.StdEncoding.DecodeString(pk.Key)
...
var peersPubKey [32]byte
copy(peersPubKey[:], decodedPubKey[0:32])
``` [2](#0-1) 

`decodedPubKey[0:32]` is a full slice expression whose upper bound is checked against `cap(decodedPubKey)`, not padded/truncated. If the attacker's host returns a `key` field that base64-decodes to fewer than 32 bytes (e.g., an empty string, a malformed key, or any short value), this line panics with "slice bounds out of range" before `copy` is ever reached. There is no length check anywhere between the base64 decode and the slice operation, and no `recover()` around `setSecret`, which runs in a goroutine per secret [3](#0-2) , so the panic crashes the whole `gh secret set` process.

Conversely, if `decodedPubKey` is longer than 32 bytes, only the first 32 bytes are used silently — this doesn't corrupt security since `box.SealAnonymous` requires exactly a 32-byte NaCl key, and truncating to the prefix of a longer key is not attacker-exploitable for key-recovery purposes (it doesn't produce a "weak known key"; it just changes which bytes are used, still requiring the attacker to control the whole key which they already do in this scenario).

### Impact Explanation
The concrete, provable impact is a **panic-based denial of service** of the `gh secret set` command when the target host (attacker-controlled or malicious enterprise server that the victim configured `gh` to talk to) returns a short/malformed public key. This does not lead to code execution, credential exfiltration, or file write; it is a crash of the local CLI process, which matches a low-severity DoS impact class rather than a verification-bypass or secret-exposure issue. The "weak key" data-exposure aspect described in the question is not substantiated in code — a longer key is simply truncated to its first 32 bytes, still fully attacker-chosen and not a security downgrade since the attacker already controls the whole key value in this threat model.

### Likelihood Explanation
Exploitability requires the victim to run `gh secret set` against a host controlled by the attacker (e.g., a malicious GHE-like host they've been pointed to, or a compromised enterprise server) and for that host to return a `public-key` response whose `key` field decodes to under 32 bytes. This is trivially reproducible by any server operator responding to the `GET .../secrets/public-key` endpoint, so likelihood is high once the precondition (victim targeting attacker's host) is met.

### Recommendation
Validate `len(decodedPubKey) == 32` immediately after the base64 decode in `setSecret` and return a graceful `res.err` (e.g., `fmt.Errorf("invalid public key length: expected 32 bytes, got %d", len(decodedPubKey))`) instead of slicing unconditionally.

### Proof of Concept
```go
func TestSetSecret_ShortPubKeyDoesNotPanic(t *testing.T) {
    // pk.Key decodes to fewer than 32 bytes, e.g. base64 of "short"
    pk := &PubKey{ID: "1", Key: base64.StdEncoding.EncodeToString([]byte("short"))}
    opts := &SetOptions{ /* minimal fields */ }
    defer func() {
        if r := recover(); r != nil {
            t.Fatalf("setSecret panicked instead of returning an error: %v", r)
        }
    }()
    res := setSecret(opts, pk, "github.com", nil /*client not reached before panic*/, nil, "MY_SECRET", []byte("val"), nil, shared.Actions, shared.Repository)
    require.Error(t, res.err)
}
```
Running this test against the current code will panic with `runtime error: slice bounds out of range [:32] with capacity 5` instead of returning an error, demonstrating the DoS.

### Citations

**File:** pkg/cmd/secret/set/http.go (L34-41)
```go
func getPubKey(client *api.Client, host string, path safeurl.SafeURL) (*PubKey, error) {
	pk := PubKey{}
	err := client.REST(host, "GET", path.String(), nil, &pk)
	if err != nil {
		return nil, err
	}
	return &pk, nil
}
```

**File:** pkg/cmd/secret/set/set.go (L289-296)
```go
	setc := make(chan setResult)
	for secretKey, secret := range secrets {
		key := secretKey
		value := secret
		go func() {
			setc <- setSecret(opts, pk, host, client, baseRepo, key, value, repositoryIDs, secretApp, secretEntity)
		}()
	}
```

**File:** pkg/cmd/secret/set/set.go (L335-341)
```go
	decodedPubKey, err := base64.StdEncoding.DecodeString(pk.Key)
	if err != nil {
		res.err = fmt.Errorf("failed to decode public key: %w", err)
		return
	}
	var peersPubKey [32]byte
	copy(peersPubKey[:], decodedPubKey[0:32])
```
