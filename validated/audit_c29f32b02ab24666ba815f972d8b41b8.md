### Title
Unfiltered GitHub PR label names become arbitrary environment variable names injected into deploy/task subprocess env (`GEM_PATH` example) - (File: `app/models/shipit/review_stack.rb`)

### Summary
`Shipit::ReviewStack#env` converts every pull-request label name directly into an environment-variable key (`label_name.upcase => "true"`) with zero denylist/allowlist, and `LabelCapturingHandler#capture_labels` persists attacker-supplied label names from an unauthenticated-looking `pull_request` webhook onto the stack's `PullRequest#labels` the moment a review stack is created. That value flows unfiltered through `TaskCommands#env`/`DeployCommands#env` into `Command#unbundled_env` and ultimately `PTY.spawn`, so a PR author can inject an env var of their choosing (e.g. `GEM_PATH=true`) into the very first `install_dependencies`/`perform` invocation of a brand-new stack.

### Finding Description
Broken binding: the audit assumes `keys(Command#unbundled_env at first deploy) == keys(deploy_spec.machine_env)`. This is false: `Shipit::TaskCommands#env` (`lib/shipit/task_commands.rb:33-48`) does `super.merge(@stack.env).merge({...}).merge(deploy_spec.machine_env).merge(@task.env)`, and `@stack.env` for a `ReviewStack` (`app/models/shipit/review_stack.rb:84-93`) injects `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` — a set of keys entirely independent of, and not declared by, `deploy_spec.machine_env`. This is directly confirmed by existing tests: `test/models/shipit/review_stack_test.rb:59-65`, `test/lib/shipit/task_commands_test.rb`, and `test/lib/shipit/deploy_commands_test.rb`, which assert labels named `wip`/`bug` become `env["WIP"]="true"`/`env["BUG"]="true"`.

Path: `LabelCapturingHandler#process` (`app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:41-47`) → `capture_labels?` true via `opened_active_stack?` (line 58-60, requires only `provisioning_behavior_allow_all` so `stack.present?` after opening) → `capture_labels` (line 98-102) persists `params.pull_request.labels.map(&:name)` verbatim onto `PullRequest#labels`, whose only schema constraint is `requires :name, String` (lines 29-31) — no charset/format/length/denylist check. On the stack's first task run, `TaskCommands#env`/`DeployCommands#env` merges `@stack.env` (labels-derived) into the final env hash, which is passed unchanged into `Command#unbundled_env` (`lib/shipit/command.rb:103-105`) and then `PTY.spawn(unbundled_env, *interpolated_arguments, ...)` (line 92). No code path filters variable *names*; `EnvironmentVariables#permit` (`lib/shipit/environment_variables.rb`) is only invoked for the API-exposed deploy `variables` feature, not for label-derived stack env.

Attacker request: a GitHub PR opened by any user against a repository configured with `provisioning_behavior_allow_all`, with a label named `GEM_PATH` (or any other sensitive variable name) attached to the PR at open time.

Why existing guards don't stop it: `verify_signature`/webhook auth only proves the payload came from GitHub for that repo, not that its *content* is safe; the `ExplicitParameters` schema only enforces `String` typing on label names; `Repository`/`Stack` format validators do not apply to PR label content; nothing in `ReviewStack#env` or `TaskCommands#env` restricts variable names.

The one part of the described chain that is **not verifiable from this codebase alone** is the final RubyGems/Bundler exploitation step — whether a directory literally named `true` placed in the PR's own checkout, containing a spoofed gem matching a real dependency, is actually resolved and `require`d ahead of the legitimately bundled gem given that `BUNDLE_PATH` is separately pinned to `Rails.root.join('data','bundler')` in `TaskCommands#env` (line 39). That final leap depends on RubyGems/Bundler internals (load order of `Gem.path`, whether `bundle install`'s own gem activation consults `GEM_PATH` before `BUNDLE_PATH`), which cannot be confirmed from the engine's source and is not demonstrated in this repo's test suite. What *is* fully confirmed in-repo is the injection primitive itself: unauthenticated (from Shipit's perspective — just a normal GitHub PR label) control over an arbitrary environment-variable name and the fixed value `"true"` reaching the subprocess environment passed to `PTY.spawn`.

### Impact Explanation
Confirmed impact: an attacker who can open a PR (and label it, since they own the label on their own PR/fork) can inject arbitrary-named environment variables (value always `"true"`) into every task run on that stack, starting with the very first deploy, with no operator review required (`provisioning_behavior_allow_all`). This is a real, reproducible primitive against the attacker's own review stack (each attacker only affects the stack derived from their own PR/repository — this is not shown to cross repository/tenant boundaries). Whether this specific primitive escalates to Critical RCE via the `GEM_PATH`/RubyGems path described in the question is plausible but unconfirmed by this codebase; it depends on external RubyGems/Bundler behavior not evidenced in these files or tests.

### Likelihood Explanation
Precondition: `repository.provisioning_behavior_allow_all` (an explicit repository configuration choice) so that `opened_active_stack?` fires on PR open without needing a separate label event. Attacker cost is minimal — opening a PR from a fork with a chosen label is unauthenticated relative to Shipit and requires no secrets. The env-injection primitive itself is trivially and repeatedly reproducible. The GEM_PATH-specific RCE outcome's likelihood cannot be assessed with confidence without live testing of RubyGems' gem-activation search order under a relative `GEM_PATH` value while `BUNDLE_PATH` is separately fixed.

### Recommendation
In `Shipit::ReviewStack#env`, allowlist/denylist label-derived environment variable names (e.g. reject names matching known-sensitive variables such as `GEM_PATH`, `GEM_HOME`, `RUBYOPT`, `BUNDLE_GEMFILE`, `LD_PRELOAD`, `PATH`, `RUBYLIB`, or restrict to a configurable prefix/allowlist), or route label-to-env conversion through `EnvironmentVariables#permit` with an explicit whitelist the same way `deploy`/`rollback` variables are handled.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (extension)
test "#env does not allow labels to set sensitive env var names" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["GEM_PATH"]

  refute_equal "true", stack.env["GEM_PATH"], "PR labels must not be able to set arbitrary env var names such as GEM_PATH"
end
```
```ruby
# test/models/shipit/webhooks/handlers/pull_request/label_capturing_handler_test.rb (extension)
test "captures GEM_PATH label into first deploy env of a brand-new stack" do
  payload = payload_parsed(:pull_request_opened)
  payload['pull_request']['labels'] = [{ 'name' => 'GEM_PATH' }]
  stack = create_stack # provisioning_behavior_allow_all, no label event needed

  task = stack.tasks.last
  env = Shipit::TaskCommands.new(task).install_dependencies.first.env

  assert_equal 'true', env['GEM_PATH'] # demonstrates the injection primitive is live on first deploy
end
```
Note: this PoC demonstrates and asserts the confirmed injection primitive (arbitrary env var name/value reaching `Command#env`). It does **not** demonstrate the further RubyGems-load hijack into actual code execution, which would require a live filesystem/RubyGems environment outside what this static/indexed review can validate.