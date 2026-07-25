### Title
Validator Node Key Exposed as Plaintext CLI Argument in `kcn valops` — (`cmd/kcn/abv2.go`)

### Summary
The `kcn valops` command accepts the validator node private key as a plaintext hex string via the `--private-key` command-line flag. On Linux, any local user can read `/proc/<pid>/cmdline` to extract the key. Possession of the node key allows an attacker to submit authenticated transactions to the `AddressBookV2` system contract (`0x400`) to force the victim validator out of the active set, pause it, or offboard it — all protected validator-set state changes.

### Finding Description
`cmd/kcn/abv2.go` defines `abv2PrivateKeyFlag` as a plain `cli.StringFlag` named `"private-key"` that accepts a hex-encoded ECDSA private key directly on the command line. [1](#0-0) 

`loadKey` reads this value verbatim from the CLI context and converts it to an `*ecdsa.PrivateKey` with no additional protection: [2](#0-1) 

The README documents and encourages this usage pattern explicitly: [3](#0-2) 

The recovered key is then used to build a `bind.TransactOpts` that signs and submits transactions to `AddressBookV2` methods including `readyCandidate`, `readyValidator`, `unreadyValidator`, `pause`, `resume`, `exit`, and `offboard`: [4](#0-3) 

The README confirms that for node-operator commands, `msg.sender == node-id` — meaning the private key **is** the validator's identity key: [5](#0-4) 

### Impact Explanation
The stolen key is the validator's node identity key. With it, an attacker can call:
- `exit` — moves the validator to `ValExiting`, removing it from the active set at the next epoch transition
- `offboard` — removes the validator from `AddressBookV2` entirely
- `pause` — moves the validator to `ValPaused`, suspending its consensus participation and reward eligibility

These are all state-changing calls to the `AddressBookV2` system contract at `0x400`, which governs the canonical validator set used for block production and reward distribution. Forcing a validator out of `ValActive` directly reduces consensus participation and causes the victim to lose block rewards — a protected-asset impact (reward distribution) and a protected-state impact (validator set membership). [6](#0-5) 

### Likelihood Explanation
The trigger is unprivileged: any local user account on the machine running `kcn valops` can read `/proc/<pid>/cmdline` without elevated privileges on most Linux distributions (where `hidepid` is not set). Validator operators are explicitly guided by the README to pass `--private-key 0x1234...` on the command line. The key is present in the process argument list for the entire duration of the command.

### Recommendation
Remove the `--private-key` flag entirely. Instead, load the key exclusively from the default file path (`/var/kcnd/data/klay/nodekey`) or from an encrypted keystore (as already supported by `kcn account export`/`kcn account bls-export`). If an override is needed for automation, accept the key via an environment variable (which is not visible in `/proc/<pid>/cmdline`) or a file path flag pointing to a key file with restricted permissions (`0600`). [2](#0-1) 

### Proof of Concept
```bash
# On a multi-user Linux system, attacker runs in background:
watch -n 0.1 'cat /proc/*/cmdline 2>/dev/null | tr "\0" " " | grep private-key'

# Victim (validator operator) runs:
kcn valops ready-validator --private-key 0xDEADBEEF... --endpoint /var/kcnd/data/klay.ipc

# Attacker captures: --private-key 0xDEADBEEF...
# Attacker then forces the validator to exit:
kcn valops exit --private-key 0xDEADBEEF... --endpoint https://public-rpc.kaia.io
# Result: validator transitions to ValExiting → removed from active set at next epoch,
# losing block production rights and all associated KAIA block rewards.
```

### Citations

**File:** cmd/kcn/abv2.go (L72-75)
```go
	abv2PrivateKeyFlag = &cli.StringFlag{
		Name:  "private-key",
		Usage: "Hex-encoded private key (default: load from " + defaultNodeKeyPath + ")",
	}
```

**File:** cmd/kcn/abv2.go (L83-150)
```go
var ValOpsCommand = &cli.Command{
	Name:     "valops",
	Usage:    "Validator state transition and suspension commands",
	Category: "PERMISSIONLESS COMMANDS",
	Subcommands: []*cli.Command{
		{
			Name:   "suspend-validator",
			Usage:  "Suspend a validator (requires suspender role)",
			Flags:  abv2SuspenderFlags(),
			Action: abv2SuspenderAction(methodSuspendValidator, (*addressbookv2.AddressBookV2Transactor).SuspendValidator),
		},
		{
			Name:   "unsuspend-validator",
			Usage:  "Unsuspend a validator (requires suspender role)",
			Flags:  abv2SuspenderFlags(),
			Action: abv2SuspenderAction(methodUnsuspendValidator, (*addressbookv2.AddressBookV2Transactor).UnsuspendValidator),
		},
		{
			Name:   "ready-candidate",
			Usage:  "Transition node to CandReady state",
			Flags:  abv2Flags(),
			Action: abv2NodeOperatorAction(methodReadyCandidate, (*addressbookv2.AddressBookV2Transactor).ReadyCandidate),
		},
		{
			Name:   "unready-candidate",
			Usage:  "Transition node out of CandReady state",
			Flags:  abv2Flags(),
			Action: abv2NodeOperatorAction(methodUnreadyCandidate, (*addressbookv2.AddressBookV2Transactor).UnreadyCandidate),
		},
		{
			Name:   "ready-validator",
			Usage:  "Transition node to ValReady state",
			Flags:  abv2Flags(),
			Action: abv2NodeOperatorAction(methodReadyValidator, (*addressbookv2.AddressBookV2Transactor).ReadyValidator),
		},
		{
			Name:   "unready-validator",
			Usage:  "Transition node out of ValReady state",
			Flags:  abv2Flags(),
			Action: abv2NodeOperatorAction(methodUnreadyValidator, (*addressbookv2.AddressBookV2Transactor).UnreadyValidator),
		},
		{
			Name:   "pause",
			Usage:  "Pause the node",
			Flags:  abv2Flags(),
			Action: abv2NodeOperatorAction(methodPause, (*addressbookv2.AddressBookV2Transactor).Pause),
		},
		{
			Name:   "resume",
			Usage:  "Resume the node",
			Flags:  abv2Flags(),
			Action: abv2NodeOperatorAction(methodResume, (*addressbookv2.AddressBookV2Transactor).Resume),
		},
		{
			Name:   "exit",
			Usage:  "Exit the node from the validator set",
			Flags:  abv2Flags(),
			Action: abv2NodeOperatorAction(methodExit, (*addressbookv2.AddressBookV2Transactor).Exit),
		},
		{
			Name:   "offboard",
			Usage:  "Offboard the node",
			Flags:  abv2Flags(),
			Action: abv2NodeOperatorAction(methodOffboard, (*addressbookv2.AddressBookV2Transactor).Offboard),
		},
		GenerateKeysCommand,
	},
}
```

**File:** cmd/kcn/abv2.go (L160-165)
```go
func loadKey(ctx *cli.Context) (*ecdsa.PrivateKey, error) {
	if keyHex := ctx.String("private-key"); keyHex != "" {
		return crypto.HexToECDSA(strings.TrimPrefix(keyHex, "0x"))
	}
	return crypto.LoadECDSA(defaultNodeKeyPath)
}
```

**File:** cmd/kcn/abv2.go (L167-192)
```go
func abv2Run(ctx *cli.Context, method string, nodeIdFn func(*bind.TransactOpts) common.Address, fn abv2TxFn) error {
	key, err := loadKey(ctx)
	if err != nil {
		return fmt.Errorf("load key: %w (use --private-key to specify explicitly)", err)
	}
	ec, transactor, err := dialABv2(ctx.String("endpoint"))
	if err != nil {
		return fmt.Errorf("%w (use --endpoint to specify explicitly)", err)
	}
	defer ec.Close()

	opts := bind.NewKeyedTransactor(key)
	opts.GasLimit = params.UpperGasLimit
	nodeId := nodeIdFn(opts)

	// Pre-flight: fail fast on an inevitable revert (e.g. SlotsFull) without gas.
	if reason := abv2DryRun(ec, method, opts.From, nodeId, opts.GasLimit); reason != "" {
		return fmt.Errorf("pre-flight check reverted: %s (no transaction sent)", reason)
	}

	tx, err := fn(transactor, opts, nodeId)
	if err != nil {
		return err
	}
	return printAndWait(ec, tx, opts.From)
}
```

**File:** cmd/kcn/README.md (L39-54)
```markdown
### Node operator role

These commands require `msg.sender == node-id` (the private key **is** the node key).

```
kcn valops ready-candidate
kcn valops unready-candidate
kcn valops ready-validator
kcn valops unready-validator
kcn valops pause
kcn valops resume
kcn valops exit
kcn valops offboard
```

No extra arguments. The node-id is derived from the private key.
```

**File:** cmd/kcn/README.md (L102-112)
```markdown
# Suspend a validator (as suspender)
kcn valops suspend-validator --node-id 0xABCD... --private-key 0x1234...

# Use default IPC endpoint and nodekey file
kcn valops ready-candidate

# Specify a custom endpoint
kcn valops pause --endpoint http://localhost:8551

# Use a custom private key and endpoint
kcn valops ready-validator --private-key 0x1234... --endpoint /tmp/klay.ipc
```
