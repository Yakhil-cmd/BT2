### Title
Attacker-controlled PR labels are injected verbatim into the deploy environment via `ReviewStack#env`, allowing arbitrary env var injection (e.g. `PERL5LIB`) into `Command#unbundled_env` / `PTY.spawn` - ([File: app/models/shipit/review_stack.rb])

### Summary
`ReviewStack#env` merges every PR label name (upcased, value `"true"`) directly into the review stack's environment hash with no allowlist, filter, or sanitization. That hash flows unmodified through `TaskCommands#env` → `Command.new(env:)` → `Command#unbundled_env` → `PTY.spawn`, so an attacker who can label their own PR (e.g. `perl5lib`) can set arbitrary environment variables, including loader/interpreter search-path variables, in every command executed for that deploy.

### Finding Description
The claimed binding is: the final env hash produced by `Command#unbundled_env` should equal `{BASE_ENV keys, PATH, keys explicitly set by Shipit.env / deploy_spec.machine_env / @task.env}`. This equality is **violated**.

Trace:
- `ReviewStack#env` (`app/models/shipit/review_stack.rb:84-93`) does:
```ruby
def env
  return super unless pull_request.present?
  super.merge(
    pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }
  )
end
```
This takes `pull_request.labels` (populated verbatim from GitHub PR label names by `LabelCapturingHandler#capture_labels`, `app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:98-102`) and merges `LABEL_NAME.upcase => "true"` into the stack env with **no allowlist, denylist, or key filtering**.
- `TaskCommands#env` (`lib/shipit/task_commands.rb:33-48`) merges `@stack.env` (which includes the above for review stacks) alongside the explicit Shipit-controlled keys (`SHIPIT_USER`, `EMAIL`, etc.), `deploy_spec.machine_env`, and `@task.env`.
- `Command.new(command_line, env:, chdir:)` stores this merged hash as `@env` (`lib/shipit/command.rb:31-34`).
- `Command#unbundled_env` (`lib/shipit/command.rb:103-105`) merges `BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)` — the label-derived keys pass straight through this final merge because they are already inside `@env`.
- `Command#start` (`lib/shipit/command.rb:85-101`) passes this hash directly to `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`.

If a PR is labeled `perl5lib`, the resulting env will contain `PERL5LIB=true`. If any deploy/CI step invokes a perl interpreter (perl-based git hook, lint script, etc.) within `@chdir` (the checkout tree, which the attacker controls the contents of via their own PR/branch), `PERL5LIB` alters perl's `@INC` module search path, enabling module-injection RCE if the attacker can also plant a module file reachable via that path inside the checkout (which they can, since it's their own branch).

No existing guard prevents this: `EnvironmentVariables#permit` is not applied to `ReviewStack#env`'s label-derived keys; `deploy_spec.machine_env`/`filter_task_envs`/`filter_deploy_envs` are Shipit-config-driven allowlists that apply to `@task.env`, not to `Stack#env`/`ReviewStack#env`; there is no repository/stack-level validation restricting label names or the derived env key set. The webhook signature check (`GitHubApp#verify_webhook_signature`) only ensures the label event genuinely came from GitHub for that repository — it does not restrict which label names are allowed, and an attacker who owns/administers the repository hosting the review stack (or who has label/triage permission on it) can legitimately apply arbitrary labels through the ordinary GitHub UI/API, producing a fully-authentic, signed webhook.

### Impact Explanation
Any deploy/CI/task step that shells out to a perl script (or any other interpreter whose behavior is influenced by an attacker-choosable environment variable name, e.g. `RUBYOPT`, `PYTHONPATH`, `LD_PRELOAD`-style vectors depending on the deploy pipeline) executed by `Command#start` inherits attacker-controlled environment content. Combined with attacker control over the checked-out tree (their own PR branch), this is a path to arbitrary code execution on the Shipit deploy host — Critical severity, matching "RCE on the deploy host via `Command`/`PTY.spawn`". The blast radius is scoped to the specific repository/stack the PR belongs to (an attacker cannot inject into another tenant's stack), but it is fully repeatable: any label change (`labeled`/`unlabeled` action) on an open, non-archived review-stack PR re-triggers `capture_labels` and the poisoned env persists for every subsequent task/deploy on that stack until the label is removed.

### Likelihood Explanation
Preconditions: the target repository must have Shipit review-stacks enabled for PRs, and the attacker must be able to add a label to a PR in that repository (this requires GitHub write/triage permission on the repository — which the attacker has by definition if it is a repository they own/administer, as explicitly permitted by the threat model's "label their own PR" and "repository they own" clauses). No Shipit secrets, sessions, or API tokens are required — the entire exploit rides on a legitimate, correctly-signed GitHub webhook. Cost is minimal (add one label via GitHub UI/API); it is fully repeatable and deterministic.

### Recommendation
Remove or strictly allowlist the label-to-env mapping in `ReviewStack#env`. At minimum:
- Require deploy-spec-defined allowed label names/prefixes (e.g. a `review_labels:` allowlist in the `.shipit.yml`/deploy spec) before promoting a label to an env var.
- Reject or namespace label-derived keys so they cannot collide with security-sensitive variable names (`PERL5LIB`, `LD_PRELOAD`, `PATH`, `RUBYOPT`, `PYTHONPATH`, `NODE_OPTIONS`, etc.), e.g. by prefixing with `SHIPIT_LABEL_` instead of using the raw upcased label name.
- Apply the same `EnvironmentVariables#permit`/filtering discipline used for `@task.env` to the label-derived keys before merging them into `Stack#env`.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (or task_commands_test.rb)
test "PR label 'perl5lib' injects PERL5LIB into the command env reaching PTY.spawn" do
  stack = shipit_stacks(:review_stack) # or a factory-built ReviewStack
  pull_request = stack.pull_request || stack.create_pull_request!(number: 1)
  pull_request.update!(labels: ["perl5lib"])

  task = create_deploy(stack) # or similarly build a Task/Deploy for stack
  commands = Shipit::TaskCommands.new(task)

  env = commands.env
  assert_equal "true", env["PERL5LIB"], "attacker-controlled label leaked into task env"

  command = Shipit::Command.new("perl -e 1", env:, chdir: task.working_directory)

  captured_env = nil
  PTY.stubs(:spawn).with do |spawn_env, *_args, **_kwargs|
    captured_env = spawn_env
    true
  end.returns([StringIO.new, StringIO.new, 123])

  command.start

  assert_equal "true", captured_env["PERL5LIB"],
    "PERL5LIB reached PTY.spawn's env despite not being part of BASE_ENV/PATH/Shipit.env/machine_env/@task.env"
end
```
Both sides of the equality: expected env keys = `BASE_ENV.keys + ['PATH'] + explicit_task_keys` (no `PERL5LIB`); actual env keys passed to `PTY.spawn` include `PERL5LIB` sourced solely from the PR label — the assertion demonstrates the divergence.