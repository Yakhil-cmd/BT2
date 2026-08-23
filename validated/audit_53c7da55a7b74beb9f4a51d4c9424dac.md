### Title
Alias argument injection via shell-metacharacter smuggling in `expandAlias` - ([File: pkg/cmd/root/alias.go])

### Summary
`expandAlias` substitutes positional argument values into the alias expansion string with a plain `strings.ReplaceAll` **before** running `shlex.Split` on the whole string. If an attacker-controlled value (e.g. copy-pasted from a malicious issue/PR/gist body) is passed as `$1`/`$2`/etc. to a locally-configured alias that quotes the placeholder (a documented, common alias pattern such as `--author="$1"`), the attacker can embed a `"` character to break out of the intended quoting and inject additional shell-lexed tokens (extra flags/arguments) into the final `gh` invocation.

### Finding Description
`expandAlias` (`pkg/cmd/root/alias.go:79-102`) does: [1](#0-0) 
1. For each positional CLI arg `a`, it replaces the literal token `$N` inside the `expansion` string with the raw arg text via `strings.ReplaceAll` — no escaping or quoting is applied.
2. After all substitutions, the *entire resulting string* is tokenized with `shlex.Split`, which understands quotes and whitespace as token delimiters.

Because substitution happens on the raw expansion text (a plain string) prior to shell-style tokenization, any quote/whitespace characters contained in the attacker-controlled argument value are interpreted by `shlex.Split` as part of the alias's quoting/argument structure rather than as literal data. This is confirmed by the existing test cases, which show `$1`/`$2` being substituted inside quoted flag values like `--author="$1"` and `--label="$2"`, then split by shlex: [2](#0-1) 

Exploit flow:
1. Victim locally configures an alias that embeds `$N` inside a quoted flag value, e.g. `gh alias set co 'pr checkout --repo="$1"'` (a pattern the project's own tests demonstrate as normal/expected usage).
2. Attacker publishes content (issue body, gist, PR description) containing a value such as: `foo" --repo="attacker/evil`.
3. Victim copies that value and runs `gh co 'foo" --repo="attacker/evil'` — the shell delivers it as a single positional arg (`args[0]`) to `expandAlias`.
4. `strings.ReplaceAll(expansion, "$1", a)` yields `pr checkout --repo="foo" --repo="attacker/evil"`.
5. `shlex.Split` tokenizes this into `["pr","checkout","--repo=foo","--repo=attacker/evil"]`, silently overriding the intended `--repo` value and routing the command to an attacker-controlled repository — this is not sandboxed by any host/repo allowlist since it happens before `ghrepo`/`ghinstance` validation and looks like a normal, victim-issued flag.

No escaping, quoting, or allowlist check exists between the raw substitution and the tokenization step, so nothing in this function (or its callers in `pkg/cmd/root/alias.go:54-76`) prevents the injection.

### Impact Explanation
This enables argument injection into any locally-defined alias whose expansion quotes a positional placeholder — a documented, encouraged alias-authoring pattern in this same file's tests. Concrete impact depends on the specific alias content but can include: wrong-repo/wrong-host request routing (e.g., forcing `--repo`, `-R`, or `--hostname` to an attacker-controlled destination), injection of additional flags into `gh api`/`gh issue`/`gh pr` subcommands (e.g., adding `-f`, `--jq`, or output-redirecting flags), or appending extra positional arguments the alias author didn't intend. This maps to the "wrong-host or wrong-account request routing" and, depending on the specific downstream command flags available (e.g., `gh api` accepting `--input`/custom headers), potentially to credential/token disclosure to an attacker-controlled host if the injected flags can redirect an authenticated request.

### Likelihood Explanation
Requires: (1) the victim to have configured an alias whose `$N` placeholder is embedded inside quotes in the expansion string (a pattern the codebase's own tests treat as normal), and (2) the victim to paste attacker-supplied text verbatim as a single alias argument without noticing embedded quote characters. This is a realistic "copy alias command from doc/issue, paste value" workflow, but it is conditioned on the specific quoting style of the user's alias and on the victim not visually inspecting the pasted value — so likelihood is moderate/context-dependent rather than trivially always exploitable.

### Recommendation
Do not perform raw string substitution followed by shell-style re-tokenization. Instead, tokenize the static parts of the expansion first (or shlex.Split the expansion before substitution) and substitute `$N` as a single opaque token/argument rather than as inline text subject to further lexing. Alternatively, quote-escape argument values before substitution so embedded `"`/`\`/whitespace cannot alter token boundaries recognized by `shlex.Split`.

### Proof of Concept
```go
func TestExpandAlias_ArgumentInjection(t *testing.T) {
    expansion := `pr checkout --repo="$1"`
    args := []string{`foo" --repo="attacker/evil`}
    got, err := expandAlias(expansion, args)
    assert.NoError(t, err)
    // Demonstrates injected extra --repo flag overriding the intended one
    assert.Equal(t, []string{"pr", "checkout", "--repo=foo", "--repo=attacker/evil"}, got)
}
```
Expected (buggy) result: `shlex.Split` produces two `--repo=` tokens, with the attacker-controlled repo silently taking precedence in downstream flag parsing — confirming the injection reaches the command dispatched to `root.Execute()` in `pkg/cmd/root/alias.go:63-65`. [3](#0-2)

### Citations

**File:** pkg/cmd/root/alias.go (L58-66)
```go
		RunE: func(c *cobra.Command, args []string) error {
			expandedArgs, err := expandAlias(aliasValue, args)
			if err != nil {
				return err
			}
			root := c.Root()
			root.SetArgs(expandedArgs)
			return root.Execute()
		},
```

**File:** pkg/cmd/root/alias.go (L79-97)
```go
func expandAlias(expansion string, args []string) ([]string, error) {
	extraArgs := []string{}
	for i, a := range args {
		if !strings.Contains(expansion, "$") {
			extraArgs = append(extraArgs, a)
		} else {
			expansion = strings.ReplaceAll(expansion, fmt.Sprintf("$%d", i+1), a)
		}
	}

	lingeringRE := regexp.MustCompile(`\$\d`)
	if lingeringRE.MatchString(expansion) {
		return nil, fmt.Errorf("not enough arguments for alias: %s", expansion)
	}

	newArgs, err := shlex.Split(expansion)
	if err != nil {
		return nil, err
	}
```

**File:** pkg/cmd/root/alias_test.go (L43-53)
```go
			name:         "satisfy expansion arguments",
			expansion:    `issue list --author="$1" --label="$2"`,
			args:         []string{"vilmibm", "help wanted"},
			wantExpanded: []string{"issue", "list", "--author=vilmibm", "--label=help wanted"},
		},
		{
			name:         "mixed positional and non-positional arguments",
			expansion:    `issue list --author="$1" --label="$2"`,
			args:         []string{"vilmibm", "epic", "-R", "monalisa/testing"},
			wantExpanded: []string{"issue", "list", "--author=vilmibm", "--label=epic", "-R", "monalisa/testing"},
		},
```
