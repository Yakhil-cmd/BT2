Confirmed: `Stack#branch` has only a `presence` validation (`app/models/shipit/stack.rb:102`), with no character/format restriction, so an attacker-controlled PR `head.ref` such as `$GITHUB_TOKEN` or a value containing shell metacharacters flows unmodified into `branch:` in `ReviewStackAdapter#stack_attributes` (`app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb:87-94`) and is persisted via `create!` (lines 72-85). `StackCommands#fetch`/`#fetch_commit`/`git_clone` then pass `@stack.branch` verbatim as the `--branch` argument to `Command.new('git', ...)` (`lib/shipit/stack_commands.rb:20,23,30,33,112-114`), and `Command#start` calls `interpolated_arguments`, which runs every argument through `EnvironmentVariables#interpolate` (`lib/shipit/command.rb:81-83,51-55`, `lib/shipit/environment_variables.rb:20-27`). `StackCommands#env` merges `Commands#base_env`, which explicitly sets `'GITHUB_TOKEN' => github.token` (`lib/shipit/commands.rb:37-49`), into the `env:` hash passed to `Command.new`. `interpolate` substitutes any `$VARNAME` substring in an argument using `@env.fetch(variable) { ENV[variable] }`, so a branch value of `$GITHUB_TOKEN` is replaced with the live GitHub token before being shelled out via `PTY.spawn` (`lib/shipit/command.rb:92`).

### Title
Review-stack `branch` from unsanitized PR `head.ref` is substituted with `GITHUB_TOKEN` via `EnvironmentVariables#interpolate` before reaching `PTY.spawn` - (File: `app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb`, `lib/shipit/stack_commands.rb`, `lib/shipit/command.rb`, `lib/shipit/environment_variables.rb`)

### Summary
`ReviewStackAdapter#stack_attributes` writes `params.pull_request.head.ref` directly into `Stack#branch` with no sanitization beyond `presence` validation. That branch value is later used as the `--branch` argument to `git clone`/`git fetch` inside `StackCommands`, and `Command#interpolated_arguments` performs `$VARNAME`→value substitution against the command's `env` hash — which includes the live `GITHUB_TOKEN` — before the argument list is handed to `PTY.spawn`.

### Finding Description
The broken binding is: `Stack#branch == params.pull_request.head.ref` (attacker-controlled, unauthenticated by any maintainer review) `== --branch argument to git clone/fetch == input to EnvironmentVariables#interpolate against env['GITHUB_TOKEN']`.

Path:
1. Attacker opens a PR from a fork with `head.ref` (Git allows fairly permissive branch names, e.g. `$GITHUB_TOKEN` is a valid ref, and refs containing spaces/`;`/backticks are blocked by git itself but `$VARNAME`-style substrings are valid and are the crux of this finding).
2. `OpenedHandler` (in the `PullRequest` webhook handler family) invokes `ReviewStackAdapter#find_or_create!` → `#create!`, which builds `stack_attributes` with `branch: params.pull_request.head.ref` (`review_stack_adapter.rb:87-94`) and persists it via `scope.create!(stack_attributes)` (line 74). `Stack` only validates `branch` for `presence` (`app/models/shipit/stack.rb:102`) — no character whitelist.
3. `Shipit::ReviewStackProvisioningQueue.add(stack)` schedules provisioning, which eventually calls `StackCommands#fetch`/`#fetch_commit`, both of which call `git_clone(@stack.repo_git_url, @stack.git_path, branch: @stack.branch, env:, ...)` (`stack_commands.rb:20-35`), and `git_clone` builds `git('clone', ..., '--branch', branch, url, path, **kwargs)` (`stack_commands.rb:112-114`).
4. `StackCommands#env` merges `Commands#base_env`, which sets `'GITHUB_TOKEN' => github.token` (`commands.rb:37-49`), into the env hash passed to `Command.new`.
5. `Command#start` calls `PTY.spawn(unbundled_env, *interpolated_arguments, ...)` (`command.rb:92`), and `interpolated_arguments` maps every argument through `EnvironmentVariables#interpolate` (`command.rb:81-83`), which does `argument.gsub(/(\$\w+)/) { @env.fetch(variable) { ENV[variable] } }` (`environment_variables.rb:20-27`).
6. Because `branch` is one of the interpolated arguments and equals `$GITHUB_TOKEN`, the git command actually executed contains the literal token value in its argument list, e.g. `git clone ... --branch ghp_xxxxxxxx ...`.

No existing guard prevents this: `verify_signature`/webhook auth only confirms the payload came from GitHub for that repo, not that the PR author is trusted; `ExplicitParameters` schema only validates payload shape, not ref content; `Stack` validations don't restrict `branch` format; `EnvironmentVariables#permit` (the whitelist-based sanitizer) is not used here — only `#interpolate` is used, which has no whitelist and performs blind substitution keyed by whatever name appears in the string.

### Impact Explanation
An attacker who can merely open a pull request against a repository with `review_stacks_enabled` and `provisioning_behavior_allow_all` (no maintainer approval, no merge required — provisioning happens on `opened`) can cause the deploy host to run a `git clone`/`git fetch` command whose argument list contains the live `GITHUB_TOKEN` used by Shipit to authenticate to GitHub for that stack's organization. This is a credential exfiltration primitive: the token appears in the process argument list handed to `PTY.spawn`, which is generally visible via process listing (`ps`), and/or in command output/logs if the command's stdout is captured or streamed (Shipit streams command output to task/deploy logs consumed elsewhere). This matches the "Critical — exfiltration of `GITHUB_TOKEN` / deploy-time secrets" category. It is repeatable per PR/per repository configured for auto-provisioning, and the token in question is the GitHub App/organization token used broadly by Shipit for that org, so its exposure has cross-tenant blast radius within that GitHub App installation.

### Likelihood Explanation
Requires the target repository to have `review_stacks_enabled` with `provisioning_behavior_allow_all` (auto-provision without maintainer approval) — a documented, supported configuration. Given that, the attacker's cost is trivial: fork the repo, push a branch literally named `$GITHUB_TOKEN`, open a PR. Git permits `$` in ref names. No Shipit session, token, or team membership is needed. This is easily repeatable against any similarly configured repository.

### Recommendation
- Validate/sanitize `Stack#branch` against a strict allowed-character format (e.g., disallow `$`, backticks, `;`, and other shell/interpolation-significant characters) at the model level, independent of trusting PR authorship.
- Do not run attacker-controlled ref strings through `EnvironmentVariables#interpolate`; interpolation should only apply to operator-authored deploy-spec commands, not to values sourced from PR payloads.
- If branch values must support `$`, use `Shellwords.escape` defensively and/or pass `--branch` values through argv without interpolation (interpolation should be opt-in per-argument, not applied uniformly to `@args`).

### Proof of Concept
Minitest plan (`test/unit/command_test.rb` style, or a new test near `review_stack_adapter_test.rb`):
```ruby
test "branch value containing $GITHUB_TOKEN is substituted with the live token in interpolated_arguments" do
  env = { 'GITHUB_TOKEN' => 'ghp_supersecrettoken' }
  command = Shipit::Command.new('git', 'clone', '--branch', '$GITHUB_TOKEN', 'https://example.com/repo.git', 'path', env: env, chdir: Dir.tmpdir)

  refute_includes command.args, 'ghp_supersecrettoken'          # left side: raw args do not contain the secret
  assert_includes command.interpolated_arguments, 'ghp_supersecrettoken' # right side: interpolated args do
end
```
And to demonstrate the full path from the webhook handler:
```ruby
test "PR head.ref containing $GITHUB_TOKEN becomes Stack#branch and reaches git --branch argument" do
  stack = shipit_stacks(:shipit)
  stack.update!(branch: '$GITHUB_TOKEN')
  commands = Shipit::StackCommands.new(stack)
  git_clone_command = commands.git_clone(stack.repo_git_url, stack.git_path, branch: stack.branch, env: commands.env, chdir: Dir.tmpdir)

  assert_includes git_clone_command.args, '$GITHUB_TOKEN'
  assert_includes git_clone_command.interpolated_arguments, commands.env['GITHUB_TOKEN']
end
```