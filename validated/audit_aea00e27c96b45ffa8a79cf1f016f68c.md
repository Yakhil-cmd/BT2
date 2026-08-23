### Title
Argv injection into `scp` via unsanitized `dst` (remote SSH username) in `newSCPCommand` - ([File: internal/codespaces/ssh.go])

### Summary
`newSCPCommand` builds the local `scp` argv by concatenating the connection destination string (`dst`) with the caller-supplied "remote:"-prefixed path and appending it as a plain positional argv element, with no `--` separator ever inserted before the resulting file arguments. `dst` is constructed from `sshUser`, a value returned by the codespace-side RPC (`invoker.StartSSHServerWithOptions`), so a value beginning with `-` can be interpreted by the locally-spawned `scp` binary as an option instead of a filename/host spec.

### Finding Description
`Copy` → `newSCPCommand` ( [1](#0-0) ) parses user-CLI `scpArgs` into `cmdArgs`/`command`, appends the local port-forward connection flags (`connArgs`), and then appends each remaining `command` argument, replacing a `"remote:"` prefix with `dst + ":" + rest`: [2](#0-1) 

`dst` is `connectDestination`, computed in `pkg/cmd/codespace/ssh.go` as `fmt.Sprintf("%s@localhost", sshUser)`, where `sshUser` is returned to the client by `invoker.StartSSHServerWithOptions(ctx, startSSHOptions)`—a value originating from the codespace-side process over the RPC tunnel: [3](#0-2) 

Because the resulting argv element is `dst + ":" + rest` (e.g. `sshUser@localhost:path`), if `sshUser` itself begins with `-`, the concatenated string also begins with `-`, and since `cmdArgs` is passed straight to `exec.CommandContext(ctx, exe, cmdArgs...)` with no `--` end-of-options marker ever inserted between the connection flags and these file arguments, the local `scp` binary will parse it as an option (e.g., `-oProxyCommand=...`) rather than a target path. `parseArgs`/`parseSCPArgs` only validate the user-supplied local `scpArgs`, not the codespace-derived `dst` value, so this specific data flow is not covered by existing validation.

### Impact Explanation
If an attacker can influence the SSH username value returned by the codespace-side agent during `StartSSHServerWithOptions` (a value described as attacker-influenceable via "everything the codespace-side process sends back"), they can inject an `scp` option such as `-oProxyCommand=<arbitrary command>` into the argv of the locally-spawned `scp` process, achieving code execution on the victim's machine when running `gh codespace cp`. This matches GitHub's RCE-in-gh bounty class.

### Likelihood Explanation
Exploitation requires the victim to run `gh codespace cp` against a codespace whose SSH-server RPC response supplies a malicious `sshUser` value beginning with `-`. This is conditioned on the ability to control that RPC response field (e.g., a compromised or malicious codespace-side agent/container), which I was not able to fully verify in this session — I did not confirm the definition/validation of the `sshUser` field inside `internal/codespaces/rpc/invoker.go`, so the exact preconditions (whether the field is validated/allowlisted upstream) remain unverified.

### Recommendation
- Insert a literal `--` argv separator before any positional/file arguments passed to `scp` (and `ssh`) so that no attacker-influenced string can be parsed as an option.
- Validate/reject `sshUser` (and any other RPC-returned identifiers used to build `dst`) if they contain a leading `-` or otherwise fail a strict username character-class check, before using them to build `connectDestination`.

### Proof of Concept
Suggested table-driven Go test (to be added near `internal/codespaces/ssh_test.go` if present) stubbing `sshUser`/`dst` with a leading-dash value:
```go
func TestNewSCPCommand_DashPrefixedDestinationIsNotTerminated(t *testing.T) {
    dst := "-oProxyCommand=touch /tmp/pwn@localhost" // attacker-controlled sshUser embedded in dst
    cmd, err := newSCPCommand(context.Background(), 12345, dst, []string{"remote:foo", "local/dest"})
    if err != nil {
        t.Fatal(err)
    }
    args := cmd.Args
    // Assert: no argv element derived from dst is placed without a preceding "--",
    // and no such element begins with "-".
    for _, a := range args {
        if strings.HasPrefix(a, "-oProxyCommand") {
            t.Fatalf("argv injection: %v", args)
        }
    }
}
```
Expected (failing) result on current code: the offending `-oProxyCommand=...:foo` string appears in `cmd.Args` with no preceding `--`, confirming the injection path.

Note: I was unable to confirm, within this session, whether upstream code already sanitizes the `sshUser` RPC field before it reaches `connectDestination`/`dst` (this requires inspecting `internal/codespaces/rpc/invoker.go`, which I did not get to read). This should be verified before treating the finding as fully confirmed exploitable end-to-end.

### Citations

**File:** internal/codespaces/ssh.go (L104-128)
```go
// newSCPCommand populates an exec.Cmd to run an scp command for the files specified in cmdArgs.
// cmdArgs is parsed such that scp flags precede the files to copy in the command.
// For example: scp -F ./config local/file remote:file
func newSCPCommand(ctx context.Context, port int, dst string, cmdArgs []string) (*exec.Cmd, error) {
	connArgs := []string{
		"-P", strconv.Itoa(port),
		"-o", "NoHostAuthenticationForLocalhost=yes",
		"-o", "PasswordAuthentication=no",
		"-C", // compression
	}

	cmdArgs, command, err := parseSCPArgs(cmdArgs)
	if err != nil {
		return nil, err
	}

	cmdArgs = append(cmdArgs, connArgs...)

	for _, arg := range command {
		// Replace "remote:" prefix with (e.g.) "root@localhost:".
		if rest := strings.TrimPrefix(arg, "remote:"); rest != arg {
			arg = dst + ":" + rest
		}
		cmdArgs = append(cmdArgs, arg)
	}
```

**File:** pkg/cmd/codespace/ssh.go (L211-263)
```go
	err = a.RunWithProgress("Fetching SSH Details", func() (err error) {
		invoker, err = rpc.CreateInvoker(ctx, fwd)
		if err != nil {
			return
		}

		remoteSSHServerPort, sshUser, err = invoker.StartSSHServerWithOptions(ctx, startSSHOptions)
		return
	})
	if invoker != nil {
		defer safeClose(invoker, &err)
	}
	if err != nil {
		return fmt.Errorf("error getting ssh server details: %w", err)
	}

	if opts.stdio {
		stdio := &combinedReadWriteHalfCloser{os.Stdin, os.Stdout}
		opts := portforwarder.ForwardPortOpts{
			Port:      remoteSSHServerPort,
			Internal:  true,
			KeepAlive: true,
		}

		// Forward the port
		err = fwd.ForwardPort(ctx, opts)
		if err != nil {
			return fmt.Errorf("failed to forward port: %w", err)
		}

		// Connect to the forwarded port
		err = fwd.ConnectToForwardedPort(ctx, stdio, opts)
		if err != nil {
			return fmt.Errorf("failed to connect to forwarded port: %w", err)
		}

		return fmt.Errorf("tunnel closed: %w", err)
	}

	localSSHServerPort := opts.serverPort

	// Ensure local port is listening before client (Shell) connects.
	// Unless the user specifies a server port, localSSHServerPort is 0
	// and thus the client will pick a random port.
	listen, localSSHServerPort, err := codespaces.ListenTCP(localSSHServerPort, false)
	if err != nil {
		return err
	}
	defer listen.Close()

	connectDestination := opts.profile
	if connectDestination == "" {
		connectDestination = fmt.Sprintf("%s@localhost", sshUser)
```
