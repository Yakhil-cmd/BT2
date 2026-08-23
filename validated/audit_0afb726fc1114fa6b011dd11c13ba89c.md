### Title
Codespace SSH destination argument (`dst`) is passed to the `ssh` client without a `--` separator or leading-dash validation, allowing SSH option injection - (File: internal/codespaces/ssh.go)

### Finding Description
`newSSHCommand` builds the `ssh` argv as: connection args (`-p`, `-o NoHostAuthenticationForLocalhost=yes`, `-o PasswordAuthentication=no`), `-C`, then `dst`, then the trailing command [1](#0-0) . `dst` is never checked for a leading `-`, and no `--` end-of-options marker is inserted before it, even though `exec.CommandContext` passes each element as a distinct argv entry (so local shell metacharacters are irrelevant — the actual risk is how the `ssh` client's own getopt-style parser treats an argv element beginning with `-`).

`dst` originates in `pkg/cmd/codespace/ssh.go` as `connectDestination`, which is either the user-supplied `--profile` flag (not attacker controlled) or `fmt.Sprintf("%s@localhost", sshUser)` where `sshUser` is returned by `invoker.StartSSHServerWithOptions` — an RPC call to the daemon running inside the codespace container [2](#0-1) [3](#0-2) . The remote username reported by that daemon is influenced by the codespace's `devcontainer.json`/container configuration (e.g. `remoteUser`/`containerUser`), which is fully attacker-controlled content when the victim creates a codespace from an attacker-published repository. If that daemon ever reports a username that begins with `-` (bypassing normal `useradd` restrictions via a custom container image that writes `/etc/passwd` directly), `dst` becomes an argv element such as `-oProxyCommand=...@localhost`. Because `ssh` parses each positional argument independently and there is no `--` boundary in `cmdArgs`, `ssh` would interpret it as an additional `-o` option rather than as the destination, letting the attacker inject arbitrary `ssh_config` directives (e.g. `ProxyCommand`, `StrictHostKeyChecking=no`, `UserKnownHostsFile=/dev/null`).

Note: the component that ultimately produces `sshUser` (the codespace-side RPC daemon) lives outside this repository, so I cannot confirm from this codebase whether it enforces stricter username validation than the CLI does. What is confirmed in-repo is that `internal/codespaces/ssh.go` performs **no** validation or `--` insertion for `dst` before handing it to `ssh`.

### Impact Explanation
If triggered, this allows local `ssh` option injection on the victim's machine — e.g. weakening host-key verification (`StrictHostKeyChecking=no`, `UserKnownHostsFile=/dev/null`) or redirecting/hijacking the connection via an injected `ProxyCommand`, which can lead to local command execution on the victim's host. This maps to a "code execution on the victim host" / "wrong-host request routing" bounty impact class, contingent on the sshUser value being attacker-steerable.

### Likelihood Explanation
Feasibility is constrained: it requires the codespace-side daemon to return a `sshUser` string beginning with `-`, which normal OS user-creation tooling rejects, requiring the attacker to bypass `useradd` validation via a custom Dockerfile/`devcontainer.json` writing directly to `/etc/passwd`, and requires the codespaces backend RPC to pass that value through unfiltered. None of that server-side/agent behavior is present in this repository, so likelihood cannot be fully validated here — the CLI-side gap (missing `--`/leading-dash check) is confirmed, but end-to-end exploitability depends on components outside this codebase.

### Recommendation
In `newSSHCommand` (and `newSCPCommand`), insert a literal `"--"` before appending `dst`, and/or explicitly reject destination strings that begin with `-`, so `ssh`/`scp` cannot interpret the destination as an option regardless of its content.

### Proof of Concept
Fuzz/unit test plan for `internal/codespaces/ssh.go`:
```go
func TestNewSSHCommand_DestinationCannotBeMisparsedAsOption(t *testing.T) {
    cases := []string{
        "user@localhost",
        "-oProxyCommand=touch /tmp/pwned",
        "-oStrictHostKeyChecking=no@localhost",
        "--\nuser@localhost",
    }
    for _, dst := range cases {
        cmd, _, err := newSSHCommand(context.Background(), 2222, dst, nil, nil)
        if err != nil {
            t.Fatal(err)
        }
        args := cmd.Args
        // Assert a "--" precedes the destination, or that dst is rejected
        // when it has a leading '-', so ssh cannot treat it as an option.
        idx := indexOf(args, dst)
        if idx == -1 || args[idx-1] != "--" {
            t.Errorf("dst %q not protected by -- separator: args=%v", dst, args)
        }
    }
}
```
Currently this test fails because `newSSHCommand` never inserts `--`, confirming the gap; full remote exploitability additionally requires demonstrating that the codespaces RPC daemon (outside this repo) can be made to return a leading-`-` username, which is not verifiable here.

### Citations

**File:** internal/codespaces/ssh.go (L65-78)
```go
func newSSHCommand(ctx context.Context, port int, dst string, cmdArgs []string, command []string) (*exec.Cmd, []string, error) {
	connArgs := []string{
		"-p", strconv.Itoa(port),
		"-o", "NoHostAuthenticationForLocalhost=yes",
		"-o", "PasswordAuthentication=no",
	}

	cmdArgs = append(cmdArgs, connArgs...)
	cmdArgs = append(cmdArgs, "-C") // Compression
	cmdArgs = append(cmdArgs, dst)  // user@host

	if command != nil {
		cmdArgs = append(cmdArgs, command...)
	}
```

**File:** pkg/cmd/codespace/ssh.go (L211-219)
```go
	err = a.RunWithProgress("Fetching SSH Details", func() (err error) {
		invoker, err = rpc.CreateInvoker(ctx, fwd)
		if err != nil {
			return
		}

		remoteSSHServerPort, sshUser, err = invoker.StartSSHServerWithOptions(ctx, startSSHOptions)
		return
	})
```

**File:** pkg/cmd/codespace/ssh.go (L261-264)
```go
	connectDestination := opts.profile
	if connectDestination == "" {
		connectDestination = fmt.Sprintf("%s@localhost", sshUser)
	}
```
