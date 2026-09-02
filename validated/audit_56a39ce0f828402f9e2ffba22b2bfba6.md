### Title
Unsanitized PR labels merged into deploy environment allow attacker-controlled `RUBYOPT` (and any env var) injection - (File: app/models/shipit/review_stack.rb)

### Summary
`Shipit::ReviewStack#env` merges every GitHub PR label name (uppercased) into the deploy environment hash with no allow-list check against `deploy_spec.machine_env` or `VariableDefinition`. Since PR labels are attacker-controlled (any user who can label their own PR), an attacker can inject arbitrary environment variable names — including `RUBYOPT` — into every subsequent `Command`/`PTY.spawn` invocation for that review stack's deploy.

### Finding Description
The broken binding: the set of environment variable keys that reach the spawned Ruby/shell process for a deploy (`Command#unbundled_env`, which merges `@env` unchanged into `PTY.spawn`) should equal the set explicitly declared/permitted via `deploy_spec.machine_env` / `VariableDefinition`. In reality it does not.

Trace:
1. `LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` verbatim into `pull_request.labels` with no filtering, allow-list, or format validation: [1](#0-0) . `PullRequest#labels` is a plain serialized array column with no validation: [2](#0-1) .
2. `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` directly into the stack's env hash: [3](#0-2) .
3. `TaskCommands#env` merges `@stack.env` into the final deploy environment, after which `deploy_spec.machine_env` and `@task.env` are merged on top — but `deploy_spec.machine_env`/declared `VariableDefinition`s only add allowed keys, they never subtract or filter out unexpected keys already present in the hash from `@stack.env`: [4](#0-3) .
4. `Command#unbundled_env` merges `@env.stringify_keys` unchanged into the base environment: [5](#0-4) , which is passed directly to `PTY.spawn`: [6](#0-5) .

Attacker request: open or own a PR against a repository with review stacks enabled, then apply a label literally named `rubyopt` (case-insensitive, becomes `RUBYOPT` after `.upcase`) via the GitHub UI/API on their own PR — this triggers a `labeled` webhook that `LabelCapturingHandler` processes without any authorization beyond identifying the repository/stack, which is by design (webhooks are the intended untrusted ingress and are not gated by user permission checks, only by the webhook's own signature verification which authenticates that the payload came from GitHub for that repo, not that its *content* is safe).

Because `RUBYOPT` is never declared in `deploy_spec.machine_env` / `VariableDefinition` anywhere in the engine, there is no code path that strips or rejects it — the "permitted set" the audit describes doesn't actually exist as an enforcement mechanism on `Stack#env`/`ReviewStack#env` at all. Any label name an attacker chooses becomes an env var name with value `"true"` for every command run in that review stack's deploy/task, including install/dependency and custom deploy steps that invoke `ruby`, `bundle`, or `rake`.

### Impact Explanation
`RUBYOPT=true` set for a spawned Ruby process is interpreted by the Ruby interpreter as a string of additional command-line flags/require directives to load before running the target script (e.g. `RUBYOPT="-e$(...)"` or `RUBYOPT="-radd_something"`-style injection is the concerning class of attack; even `RUBYOPT=true` alone is benign, but the underlying primitive is a fully attacker-chosen environment key). Since only the label *name* is used as the key (value is hardcoded `"true"`), the practical exploitation is limited to setting arbitrary env var **names** to the fixed string `"true"` — the attacker cannot control the *value*, only which variable key gets set to `"true"`. This is Critical-relevant if a review stack's deploy steps or dependency installation are sensitive to that variable being present/truthy (e.g. flags that skip bundler frozen checks, disable safety flags, or enable debug/verbose modes that could leak secrets in logs), but it is not full RCE by itself since the attacker cannot inject arbitrary shell content or Ruby flags through this label mechanism — only fixed `"true"` values for attacker-chosen keys. This is a real but constrained env-injection primitive scoped to the attacker's own review stack (labels only affect that PR's own `ReviewStack`, not other repositories' stacks), so cross-tenant impact is not present.

### Likelihood Explanation
Precondition: the repository must have review stacks configured (`ReviewStack` is only used for PR-based ephemeral stacks). The attacker needs only to open/label a PR on their own fork/branch against a repo with review stacks enabled — no Shipit session, token, or team membership required. Cost is trivial (one GitHub label). It is repeatable per PR/label at will, but scope is limited to the review stack belonging to that specific PR/attacker-controlled branch.

### Recommendation
In `Shipit::ReviewStack#env` (app/models/shipit/review_stack.rb:84-93), do not merge raw label names into the process environment. Either drop this feature, or restrict merged keys to an explicit allow-list validated against `deploy_spec.machine_env`/`VariableDefinition`-declared variables, and reject/ignore any label whose uppercased name collides with security-sensitive interpreter/runtime variables (`RUBYOPT`, `RUBYLIB`, `BUNDLE_*`, `LD_PRELOAD`, `PATH`, etc.). At minimum, filter against a fixed deny-list of interpreter-affecting variable names before merging.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (conceptual, minitest, no live GitHub)
test "labeling a PR with RUBYOPT injects it into the review stack env" do
  stack = shipit_review_stacks(:review_stack) # fixture ReviewStack
  pull_request = stack.pull_request
  pull_request.update!(labels: ['rubyopt'])

  assert_equal 'true', stack.env['RUBYOPT']

  task = shipit_tasks(:task_on_review_stack) # associated task
  task_commands = Shipit::TaskCommands.new(task)

  assert_equal 'true', task_commands.env['RUBYOPT']
  deploy_spec = task_commands.deploy_spec
  refute deploy_spec.machine_env.key?('RUBYOPT'), "RUBYOPT should not be a declared machine_env variable"
end
```
This demonstrates: (1) `PullRequest#labels` accepts and persists an arbitrary label name with no filtering, (2) `ReviewStack#env` surfaces it unchanged as an environment key, (3) `TaskCommands#env` (and therefore the `Command`/`PTY.spawn` chain) inherits it, while (4) it is absent from the declared/allowed `deploy_spec.machine_env` set — confirming the binding violation, constrained to the fixed value `"true"` rather than arbitrary attacker-controlled content.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/pull_request.rb (L14-14)
```ruby
    serialize :labels, coder: Shipit.serialized_column(:labels, type: Array)
```

**File:** app/models/shipit/review_stack.rb (L84-93)
```ruby
    def env
      return super unless pull_request.present?

      super
        .merge(
          pull_request
            .labels
            .each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }
        )
    end
```

**File:** lib/shipit/task_commands.rb (L33-48)
```ruby
    def env
      super
        .merge(@stack.env)
        .merge(
          'SHIPIT_USER' => "#{@task.author.login} (#{normalized_author_name}) via Shipit",
          'EMAIL' => @task.author.email,
          'BUNDLE_PATH' => Rails.root.join('data', 'bundler').to_s,
          'SHIPIT_LINK' => @task.permalink,
          'TASK_ID' => @task.id.to_s,
          'IGNORED_SAFETIES' => @task.ignored_safeties? ? '1' : '0',
          'GIT_COMMITTER_NAME' => @task.user&.name || Shipit.committer_name,
          'GIT_COMMITTER_EMAIL' => @task.user&.email || Shipit.committer_email
        )
        .merge(deploy_spec.machine_env)
        .merge(@task.env)
    end
```

**File:** lib/shipit/command.rb (L92-92)
```ruby
        @out, child_in, @pid = PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)
```

**File:** lib/shipit/command.rb (L103-105)
```ruby
    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
    end
```
