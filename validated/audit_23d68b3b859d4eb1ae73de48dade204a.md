### Title
Case-sensitive extension name comparison in `checkValidExtension` allows installing a colliding/typosquatted extension - (File: pkg/cmd/extension/command.go)

### Summary
The `checkValidExtension` function in `pkg/cmd/extension/command.go` determines whether a new extension name collides with an already-installed extension by comparing derived command names with a case-sensitive `==` operator. This mirrors the reported analog bug class ("case sensitive check allows adding the same near-fungible token more than once"): the duplicate/collision check only catches exact-case matches, so an attacker-published extension whose name differs only in letter casing from an already-installed extension bypasses the "already installed" / "name collision" guard.

### Finding Description
When a user runs `gh extension install <repository>`, the command derives `commandName` from the target extension name (stripping the `gh-` prefix) and iterates over already-installed extensions to detect collisions: [1](#0-0) 

The comparison `ext.Name() == commandName` is case-sensitive. Extension names are typically derived from GitHub repository names (e.g., `gh-existing-ext`), and GitHub repository names/paths are case-insensitive-ish in practice (or at least attacker-controllable in casing on hosts other than github.com, e.g., GHES). An attacker can publish a competing extension repository such as `owner2/gh-Existing-Ext` (differing only in case from a user's already-installed `owner/gh-existing-ext`). Because `"existing-ext" != "Existing-Ext"` in Go's `==` string comparison, `checkValidExtension` will not detect this as a name collision or as "already installed," and the install proceeds normally, invoking `m.Install(repo, pinFlag)`: [2](#0-1) 

This is analogous to the reported NEAR fungible token bug: a case-sensitive uniqueness/collision check is trivially bypassed by an attacker who controls the name/casing of the artifact being registered (there, a token symbol; here, a `gh` extension repository name), leading to two logically-identical-looking entries coexisting where only one was intended.

### Impact Explanation
`gh extension install` explicitly executes arbitrary code from the installed repository whenever the extension's command is invoked — that is the entire purpose of extensions. Because the collision check is bypassed by casing, a user can be misled into installing an attacker's extension believing it "collides" with (or is a variant of) a trusted extension they already have, when in fact it silently installs alongside as a distinct, unguarded extension. This does not itself guarantee dispatch confusion (Cobra command lookup / manager dispatch behavior was not fully verified for case sensitivity in the available context), so the concrete blast radius is: bypass of the "already installed" / "extension name collision" protection that is supposed to prevent users from unknowingly running two same-named extensions from different, untrusted sources. This is a lower-severity issue than the original token-duplication report because it does not, by itself, prove forced code execution of the attacker's binary over the legitimate one — that would depend on command-resolution behavior in `pkg/cmd/root/root.go` and `pkg/cmd/extension/manager.go`, which I was not able to fully confirm is case-sensitive or case-insensitive in the time available.

### Likelihood Explanation
Likelihood is limited: it requires the attacker to control an extension repository whose full name matches an existing, trusted extension except for character casing, and requires the victim to actively choose to run `gh extension install owner2/gh-Existing-Ext` (typosquatting/social-engineering vector) rather than a MITM or automatic action. This fits the "unprivileged remote-attacker" analog for extension install/execution, but the actual exploitation path depends on unverified downstream dispatch behavior.

### Recommendation
Normalize extension/command names (e.g., `strings.ToLower`) before comparison in `checkValidExtension` (`pkg/cmd/extension/command.go:694-713`), consistent with how `gh auth login` already normalizes hostnames to lowercase to avoid case-based bypass, as documented at: [3](#0-2) 

### Proof of Concept
1. User has extension `owner/gh-existing-ext` installed.
2. Attacker publishes `owner2/gh-Existing-Ext` (same name, different case) on a host reachable to `gh` (github.com or a configured GHES/tenant host).
3. Victim runs `gh extension install owner2/gh-Existing-Ext`.
4. `checkValidExtension` computes `commandName = "Existing-Ext"` and compares it against the installed extension's `ext.Name() == "existing-ext"`; the case-sensitive `==` fails to detect the collision, so no "already installed" warning is shown and no `--force` is required.
5. `m.Install(repo, pinFlag)` proceeds, installing the attacker's extension without the collision safeguard the tool is designed to provide. [4](#0-3)

### Citations

**File:** pkg/cmd/extension/command.go (L372-418)
```go
					repo, err := ghrepo.FromFullName(args[0])
					if err != nil {
						return err
					}

					cs := io.ColorScheme()

					if ext, err := checkValidExtension(cmd.Root(), m, repo.RepoName(), repo.RepoOwner()); err != nil {
						// If an existing extension was found and --force was specified, attempt to upgrade.
						if forceFlag && ext != nil {
							return upgradeFunc(ext.Name(), forceFlag)
						}

						if errors.Is(err, alreadyInstalledError) {
							fmt.Fprintf(io.ErrOut, "%s Extension %s is already installed\n", cs.WarningIcon(), ghrepo.FullName(repo))
							return nil
						}

						return err
					}

					io.StartProgressIndicator()
					err = m.Install(repo, pinFlag)
					io.StopProgressIndicator()

					if err != nil {
						if errors.Is(err, releaseNotFoundErr) {
							return fmt.Errorf("%s Could not find a release of %s for %s",
								cs.FailureIcon(), args[0], cs.Cyan(pinFlag))
						} else if errors.Is(err, commitNotFoundErr) {
							return fmt.Errorf("%s %s does not exist in %s",
								cs.FailureIcon(), cs.Cyan(pinFlag), args[0])
						} else if errors.Is(err, repositoryNotFoundErr) {
							return fmt.Errorf("%s Could not find extension '%s' on host %s",
								cs.FailureIcon(), args[0], repo.RepoHost())
						}
						return err
					}

					if io.IsStdoutTTY() {
						fmt.Fprintf(io.Out, "%s Installed extension %s\n", cs.SuccessIcon(), args[0])
						if pinFlag != "" {
							fmt.Fprintf(io.Out, "%s Pinned extension at %s\n", cs.SuccessIcon(), cs.Cyan(pinFlag))
						}
					}
					return nil
				},
```

**File:** pkg/cmd/extension/command.go (L694-713)
```go
func checkValidExtension(rootCmd *cobra.Command, m extensions.ExtensionManager, extName, extOwner string) (extensions.Extension, error) {
	if !strings.HasPrefix(extName, "gh-") {
		return nil, errors.New("extension name must start with `gh-`")
	}

	commandName := strings.TrimPrefix(extName, "gh-")
	if c, _, _ := rootCmd.Find([]string{commandName}); c != rootCmd && c.GroupID != "extension" {
		return nil, fmt.Errorf("%q matches the name of a built-in command or alias", commandName)
	}

	for _, ext := range m.List() {
		if ext.Name() == commandName {
			if extOwner != "" && ext.Owner() == extOwner {
				return ext, alreadyInstalledError
			}
			return ext, fmt.Errorf("there is already an installed extension that provides the %q command", commandName)
		}
	}

	return nil, nil
```

**File:** pkg/cmd/auth/login/login.go (L184-187)
```go
	// The go-gh Config object currently does not support case-insensitive lookups for host names,
	// so normalize the host name case here before performing any lookups with it or persisting it.
	// https://github.com/cli/go-gh/pull/105
	hostname = strings.ToLower(hostname)
```
