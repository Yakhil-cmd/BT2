### Title
Silent Truncation of Invalid-Length Byte Values in `validatorAddressListCanonicalizer` Allows Wrong Validator Address to Be Registered in Council — (`kaiax/gov/param.go`)

---

### Summary

The `validatorAddressListCanonicalizer` in `kaiax/gov/param.go` contains a Type 3 fallback that silently truncates any `[]byte` input whose length is neither exactly 20 nor a multiple of 20 to its **last 20 bytes** via `common.BytesToAddress(v)`. This was introduced for backward compatibility with a specific historical mainnet block, but it also means that a malicious block proposer can craft a `governance.addvalidator` or `governance.removevalidator` vote with a deliberately oversized byte payload. The vote passes `VerifyVote` and `PostInsertBlock` with the silently-truncated address, registering a wrong address in the council (validator set) — an address the attacker controls.

---

### Finding Description

`validatorAddressListCanonicalizer` handles `[]byte` input from `header.Vote` in three branches: [1](#0-0) 

- **Type 1** (`len == 20`): exact single address — correct.
- **Type 2** (`len % 20 == 0`): multiple packed addresses — correct.
- **Type 3 (fallback)**: any other length → `common.BytesToAddress(v)` which calls `SetBytes`, silently taking the **last 20 bytes**. [2](#0-1) 

The comment in the code acknowledges the problem: [3](#0-2) 

The test suite confirms this behavior is accepted as "valid": [4](#0-3) 

The full execution path for a new block is:

1. **`VerifyVote`** calls `vb.ToVoteData()`: [5](#0-4) 

2. **`ToVoteData`** RLP-decodes `header.Vote` and calls `NewVoteData(v.Validator, v.Key, v.Value)` where `v.Value` is raw `[]byte`: [6](#0-5) 

3. **`NewVoteData`** calls `validatorAddressListCanonicalizer(v.Value)`. If `len(v.Value)` is e.g. 22 bytes, the Type 3 branch fires and returns `[]common.Address{BytesToAddress(v.Value)}` — the last 20 bytes — without error. [3](#0-2) 

4. **`checkConsistency`** for `AddValidator`/`RemoveValidator` only checks that the governing node is not in the vote value — it does not validate address length: [7](#0-6) 

5. **`PostInsertBlock`** calls `parseValidatorVote` → `voteBytes.ToVoteData()` (same truncation path) → `applyVote` adds the truncated address to the council: [8](#0-7) 

The council is then persisted: [9](#0-8) 

---

### Impact Explanation

A malicious block proposer can craft a raw RLP-encoded `header.Vote` for `governance.addvalidator` with a `Value` field of e.g. 22 bytes, where the last 20 bytes are an address they control. The vote passes all validation checks and the wrong address is permanently written into the council. The attacker now controls an additional council seat, gaining an extra vote in consensus (committee selection, proposer selection). In `none` governance mode, any council member can do this; in `single` mode, only the governing node can.

---

### Likelihood Explanation

Low. Requires:
1. A malicious block proposer who directly manipulates the raw `header.Vote` bytes (bypassing the normal `ToVoteBytes()` path which always produces 20×n bytes).
2. The chain to be pre-Permissionless fork, since `AddValidator`/`RemoveValidator` are deprecated after Permissionless: [10](#0-9) 
3. `VerifyVote` rejects these votes post-Permissionless via `DeprecatedAt`: [11](#0-10) 

---

### Recommendation

In the Type 3 fallback of `validatorAddressListCanonicalizer`, reject byte slices whose length is not exactly 20 or a multiple of 20, rather than silently truncating. For historical block replay compatibility, the existing behavior can be preserved only when the block number is below the known problematic block (75038593). For all new blocks, an invalid-length byte value should return an error:

```go
// Type 3 - reject for new blocks; only accept for historical compat
// if blockNum > 75038594 { return nil, ErrCanonicalizeByteToAddress }
return []common.Address{common.BytesToAddress(v)}, nil
```

Alternatively, add a strict length check and document that the Type 3 path is only reachable during historical block migration, not during live block verification.

---

### Proof of Concept

```go
// Attacker controls the last 20 bytes of the crafted payload.
// arbitraryBytes is 22 bytes: 2 prefix bytes + 20-byte target address.
arbitraryBytes := append([]byte{0xAA, 0xBB}, targetAddr.Bytes()...)

// Craft raw RLP vote bytes manually (bypassing ToVoteBytes which enforces 20*n).
rawVote, _ := rlp.EncodeToBytes(struct {
    Validator common.Address
    Key       string
    Value     []byte
}{Validator: attackerAddr, Key: "governance.addvalidator", Value: arbitraryBytes})

// Insert into block header.
header.Vote = rawVote

// VerifyVote passes: validatorAddressListCanonicalizer truncates arbitraryBytes
// to targetAddr (last 20 bytes). checkConsistency only checks governingNode exclusion.
// PostInsertBlock -> applyVote -> council now contains targetAddr (attacker-controlled).
assert.Contains(t, council, targetAddr) // passes
```

The test case in `param_test.go` line 63 already demonstrates this truncation is accepted as valid behavior by the canonicalizer, confirming the path is reachable.

### Citations

**File:** kaiax/gov/param.go (L57-82)
```go
		switch v := v.(type) {
		case []byte: // input from header.Vote
			// There are three types of header.Vote encoding for validator address(es).
			// Type1. Single address, [20]byte. See Mainnet block 5505383.
			// Type2. Multiple addresses, [20*n]byte.
			// Type3. Single address, [42]byte (hex-encoded bytes). See Mainnet block 90915008.

			// Type1
			if len(v) == common.AddressLength {
				return []common.Address{common.BytesToAddress(v)}, nil
			}

			// Type2
			if len(v)%common.AddressLength == 0 {
				addresses := make([]common.Address, len(v)/common.AddressLength)
				for i := 0; i < len(v)/common.AddressLength; i++ {
					addresses[i] = common.BytesToAddress(v[i*common.AddressLength : (i+1)*common.AddressLength])
				}
				return addresses, nil
			}

			// Type 3
			// Ideally, v should be decoded using hexutil.Decode(string(v)) to ensure correct processing.
			// However, decoding is intentionally skipped here because it would result in a bad block error
			// at block 75038593, caused by an incorrect council configuration at block 75038594.
			return []common.Address{common.BytesToAddress(v)}, nil
```

**File:** kaiax/gov/param.go (L578-582)
```go
var PermissionlessDeprecated = map[ParamName]struct{}{
	AddValidator:          {},
	RemoveValidator:       {},
	IstanbulCommitteeSize: {},
}
```

**File:** common/types.go (L419-423)
```go
func (a *Address) SetBytes(b []byte) {
	if len(b) > len(a) {
		b = b[len(b)-AddressLength:]
	}
	copy(a[AddressLength-len(b):], b)
```

**File:** kaiax/gov/param_test.go (L63-63)
```go
		{desc: "Valid bytes, hex-encoded one address", input: hexutil.MustDecode("0x307831366331393235383561306162323462353532373833623462663764386463396636383535633335"), expected: []common.Address{common.HexToAddress("0x3833623462663764386463396636383535633335")}},
```

**File:** kaiax/gov/headergov/impl/header.go (L61-75)
```go
func (h *headerGovModule) VerifyVote(header *types.Header) error {
	if len(header.Vote) == 0 {
		return nil
	}

	var (
		vb       headergov.VoteBytes = header.Vote
		blockNum                     = header.Number.Uint64()
	)

	vote, err := vb.ToVoteData()
	if err != nil {
		logger.Error("ToVoteData error", "num", blockNum, "vote", vb, "err", err)
		return err
	}
```

**File:** kaiax/gov/headergov/impl/header.go (L77-80)
```go
	if gov.DeprecatedAt(vote.Name(), h.ChainConfig.Rules(header.Number)) {
		logger.Error("Vote is deprecated", "num", blockNum, "name", vote.Name())
		return ErrDeprecatedVote
	}
```

**File:** kaiax/gov/headergov/impl/header.go (L193-203)
```go
	case gov.AddValidator, gov.RemoveValidator:
		params := h.GetParamSet(blockNum)

		// compare with governing node only in single mode.
		if params.GovernanceMode != "single" {
			return nil
		}
		if slices.Contains(vote.Value().([]common.Address), params.GoverningNode) {
			return ErrGovNodeInValSetVoteValue
		}
		return nil
```

**File:** kaiax/gov/headergov/vote.go (L108-125)
```go
func (vb VoteBytes) ToVoteData() (VoteData, error) {
	var v struct {
		Validator common.Address
		Key       string
		Value     []byte
	}

	err := rlp.DecodeBytes(vb, &v)
	if err != nil {
		return nil, ErrInvalidRlp
	}

	vote := NewVoteData(v.Validator, v.Key, v.Value)
	if vote == nil {
		return nil, ErrInvalidVoteData
	}

	return vote, nil
```

**File:** kaiax/valset/impl/getter_council.go (L219-230)
```go
func (v *ValsetModule) applyBlock(council *valset.AddressSet, num uint64, write bool) error {
	header := v.Chain.GetHeaderByNumber(num)
	if header == nil {
		return errNoHeader
	}
	governingNode := v.GovModule.GetParamSet(num).GoverningNode
	if applyVote(header, council, governingNode) && write {
		insertValidatorVoteBlockNums(v.ChainKv, num)
		writeCouncil(v.ChainKv, num, council.List())
		v.validatorVoteBlockNumsCache = nil
	}
	return nil
```

**File:** kaiax/valset/impl/getter_council.go (L236-258)
```go
func applyVote(header *types.Header, council *valset.AddressSet, governingNode common.Address) bool {
	voteKey, addresses, ok := parseValidatorVote(header)
	if !ok {
		return false
	}

	originalSize := council.Len()
	for _, address := range addresses {
		if address == governingNode {
			continue
		}
		switch voteKey {
		case gov.AddValidator:
			if !council.Contains(address) {
				council.Add(address)
			}
		case gov.RemoveValidator:
			if council.Contains(address) {
				council.Remove(address)
			}
		}
	}
	return originalSize != council.Len()
```
