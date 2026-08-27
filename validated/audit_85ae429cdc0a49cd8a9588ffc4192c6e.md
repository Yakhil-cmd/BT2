### Title
Unbounded memory allocation when capturing git command output from an untrusted remote - (File: pkg/cmd/cmd.go)

### Summary
The reported CVE-2021-29511 describes `evm_core::Memory::copy_large` over-allocating memory without limit when handling attacker-influenced EVM opcode operands, enabling a DoS. The closest reachable analog in `git-sync` is in the command runner used to execute all `git` subcommands against a remote repository: stdout/stderr are captured into unbounded, unthrottled `bytes.Buffer` instances sized entirely by however much data the git process emits, with no cap tied to the content of the (potentially attacker-controlled) remote repository.

### Finding Description
Every invocation of `git` in `git-sync` goes through `runWithStdin`, which buffers the entire stdout and stderr of the subprocess in memory with no size limit: [1](#0-0) 

This runner is used for operations whose output size is a direct function of remote-controlled data, e.g. dumping git config (`git config list -z`) and other git subcommands invoked throughout the sync flow: [2](#0-1) 

`git-sync`'s core purpose is fetching from a remote repository URL supplied via `--repo` and continuously syncing whatever ref/commit content that remote serves: [3](#0-2) 

If an attacker controls (or can influence, e.g. via a compromised/malicious upstream, or a MITM'd HTTP(S) remote without integrity issues being otherwise mitigated) the content served for the configured ref — for example returning an extremely large number of refs on `ls-remote`/`fetch` negotiation, a huge commit message, or bloated pack/log output that other `git` subcommands surface to stdout — the `bytes.Buffer` in `runWithStdin` will grow to match, with no throttling, chunking, or maximum-size enforcement.

### Impact Explanation
Because the buffering is fully unbounded and applies to essentially every git invocation in the sync loop, a hostile upstream can force `git-sync` to allocate memory proportional to attacker-chosen output size on each sync attempt. Repeated over-allocation during the periodic sync loop can exhaust the container's memory, causing the process to be OOM-killed and restarted — i.e., persistent sync denial, matching the CWE-770 "Allocation of Resources Without Limits or Throttling" classification in the underlying report.

### Likelihood Explanation
This requires the operator to point `git-sync` at a repository/remote that is attacker-influenced (e.g., a compromised upstream or an intentionally malicious source repo being synced), which is within `git-sync`'s normal threat model of syncing from a configured `--repo`. No special flags are required — this code path is exercised on every sync via `cmdRunner.Run`/`RunWithStdin`. However, exploitation depth is bounded by what git itself will output for a given command (e.g., truly enormous single commands are unlikely in typical git plumbing output), so likelihood is moderate rather than trivial.

### Recommendation
Bound the size of captured stdout/stderr in `pkg/cmd/cmd.go` (e.g., wrap `outbuf`/`errbuf` with an `io.LimitedWriter` or similar), and truncate/flag output that exceeds a configurable maximum, mirroring the resource-limiting fix applied for `evm_core::Memory::copy_large` (compute/validate size before allocating, and cap growth of the underlying buffer).

### Proof of Concept
1. Set up a git remote whose ref/config/log output is designed to be extremely large (e.g., a very large number of refs returned during `git config list -z` processing, or oversized commit metadata surfaced by a git subcommand invoked by `git-sync`).
2. Point `git-sync --repo=<malicious-remote>` at it.
3. Observe that `runWithStdin` in `pkg/cmd/cmd.go:74-83` buffers the entire output with no size cap, causing memory usage to scale with the attacker-controlled output size on each sync attempt, potentially triggering OOM and repeated crash/restart cycles (persistent sync denial).

Note: I could not fully verify, within the available indexed context, every specific git subcommand call site whose output size is most directly attacker-influenced (e.g., exact `ls-remote`/fetch negotiation code), since some call sites in `main.go` matched by search were only partially inspected. A full audit of all `cmdRunner.Run`/`git.Run` call sites would be needed to confirm the single most severe trigger path.

### Citations

**File:** pkg/cmd/cmd.go (L74-83)
```go
	outbuf := bytes.NewBuffer(nil)
	errbuf := bytes.NewBuffer(nil)
	cmd.Stdout = outbuf
	cmd.Stderr = errbuf
	cmd.Stdin = bytes.NewBufferString(stdin)

	start := time.Now()
	err := cmd.Run()
	wallTime := time.Since(start)
	stdout := strings.TrimSpace(outbuf.String())
```

**File:** main.go (L756-771)
```go
	git := &repoSync{
		cmd:          *flGitCmd,
		root:         absRoot,
		repo:         *flRepo,
		ref:          *flRef,
		depth:        *flDepth,
		filter:       *flFilter,
		submodules:   submodulesMode(*flSubmodules),
		gc:           gcMode(*flGitGC),
		link:         absLink,
		authURL:      *flAskPassURL,
		sparseFile:   *flSparseCheckoutFile,
		log:          log,
		run:          cmdRunner,
		staleTimeout: *flStaleWorktreeTimeout,
	}
```

**File:** main.go (L834-851)
```go
	if stdout, stderr, err := cmdRunner.Run(ctx, "", nil, *flGitCmd, "config", "list", "-z"); err != nil {
		log.Error(err, "can't list git config")
		os.Exit(1)
	} else if stderr != "" {
		log.V(0).Info("unexpected stderr reading git config", "stdout", stdout, "stderr", stderr)
		os.Exit(1)
	} else {
		cfgs := strings.Split(stdout, string(rune(0)))
		kvs := funcr.PseudoStruct{} // like a map but ordered
		for _, cfg := range cfgs {
			if cfg == "" {
				continue
			}
			parts := strings.SplitN(cfg, "\n", 2) // any additional newlines are part of the value
			kvs = append(kvs, parts[0], parts[1])
		}
		log.V(0).Info("git config", "configs", kvs)
	}
```
