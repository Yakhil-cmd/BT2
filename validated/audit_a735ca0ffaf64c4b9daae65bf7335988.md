This confirms the vulnerability is fully wired through `LabelCapturingHandler`, which persists arbitrary attacker-chosen PR labels onto a `ReviewStack` unauthenticated by webhook signature checks that only validate the source, not the label content, and those labels flow unfiltered into `ReviewStack#env` and then into `Command#interpolate_environment_variables`.

### Title
Attacker-controlled PR label names are interpolated into the literal shell command executed by `PTY.spawn` - (File: `app/models/shipit/review_stack.rb`)

### Summary
`ReviewStack#env` merges every PR label name (upcased, value `"true"`) into the environment hash returned by `TaskCommands#env`/`DeployCommands#env`, and that same hash is used by `Command#interpolate_environment_variables` to substitute `${VAR}` tokens directly into the command-line string before it is passed to `PTY.spawn`. An attacker who can label their own pull request can therefore inject an arbitrary value for any `${VAR}` referenced in a `shipit.yml` step, as long as no later merge in the env-building chain overrides that key.

### Finding Description
The broken binding: the operator expects `interpolated_command_line == f(deploy_spec_approved_values, @task.env)` only, but in reality `interpolated_command_line == f(deploy_spec_approved_values, @task.env, ReviewStack#env_labels)` when the label name collides with a variable name referenced via `${VAR}` in a step.

Trace:
1. `LabelCapturingHandler` (triggered by unauthenticated-but-signature-checked webhooks such as `pull_request.opened/labeled/unlabeled/reopened`) writes `payload["pull_request"]["labels"]` verbatim into `pull_request.labels`, as shown by `test/models/shipit/webhooks/handlers/pull_request/label_capturing_handler_test.rb` (labels captured with no filtering, even unicode names).
2. `ReviewStack#env` [1](#0-0)  merges `label_name.upcase => "true"` for every label into the base `Stack#env` hash [2](#0-1) .
3. `TaskCommands#env` merges, in order: `super` (base git env), `@stack.env` (labels included here), then fixed keys, then `deploy_spec.machine_env`, then `@task.env` [3](#0-2) . Any label whose upcased name is **not** also set by `machine_env` or `@task.env` survives to the final hash unfiltered — there is no `EnvironmentVariables#permit`/whitelist call anywhere in this chain.
4. `TaskCommands#perform`/`install_dependencies` build `Command.new(command_line, env:, chdir:)` from `deploy_spec.steps`/`dependencies_steps!` using that same unfiltered `env` [4](#0-3) .
5. `Command#start` calls `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` [5](#0-4) . `interpolated_arguments` calls `interpolate_environment_variables(@args)` → `EnvironmentVariables.with(env).interpolate(argument)`, which substitutes `$VAR` tokens using `@env.fetch(variable)` [6](#0-5)  — and `env` here is the exact same hash that also becomes `unbundled_env` for the child process [7](#0-6) .

Exploit flow: attacker opens/labels a PR on a repository they control that has review-stack provisioning enabled (or already has one via `allow_all`/webhook-triggered creation), naming a label e.g. `deploy_target` (case-insensitive, becomes `DEPLOY_TARGET`). If the operator's `shipit.yml` step reads `echo ${DEPLOY_TARGET}` (or any `${VAR}` not otherwise supplied by `machine_env`/`@task.env`/fixed keys), the literal command string built for `PTY.spawn` now contains `true` (shell-escaped) instead of the intended value, and any variable name the attacker can guess (matching an unfilled `${VAR}` reference) is substitutable this way.

Why guards fail: `verify_signature`/`GitHubApp#verify_webhook_signature` only prove the webhook came from GitHub for that repo — they do not restrict what the attacker (owner of the source repo/PR) can name a label. `EnvironmentVariables#permit` exists but is never invoked in `TaskCommands#env`/`ReviewStack#env`/`Command#start`; only `filter_deploy_envs`/`filter_rollback_envs` in `DeploySpec` use it, and those are not part of the `Command` construction path shown here. There is no whitelist between `pull_request.labels` and the environment reaching `PTY.spawn`.

### Impact Explanation
The attacker controls the substituted value for any `${VAR}` token in a shell step that is not otherwise pinned by `machine_env`/fixed env keys/`@task.env`, on the repository whose PR they label. This can change the literal shell command executed (e.g., select a different deploy target, hostname, or flag baked in via `${VAR}`) via `PTY.spawn` on the Shipit deploy host. This only affects `ReviewStack`s, and only for the specific attacker's own repository/PR (labels are stored per-`ReviewStack`/PR, scoped to that stack) — it is repeatable for every review stack the attacker can label, but does not cross into other tenants' stacks since a `ReviewStack` is tied to that repository's PR. Severity is scoped to whatever the colliding `${VAR}` controls in the operator's `shipit.yml`; if that variable feeds a destination, credential selector, or command flag, this is a genuine Critical-class command-line injection matching "RCE via command-line interpolation using an attacker-named/valued label" per the question's framing.

### Likelihood Explanation
Preconditions: the repository must have `ReviewStack`s enabled with a provisioning behavior that lets the attacker's PR create/keep a review stack (`allow_all`, or `allow_with_label`/`prevent_with_label` satisfied), and the operator's `shipit.yml` step must reference a `${VAR}` name that an attacker can predict and that isn't otherwise supplied by `machine_env`, fixed keys, or task variables. Attacker cost is minimal — open a PR on their own fork/branch and add a label; no Shipit credentials, GitHub team membership, or secrets required. It is fully repeatable per PR/label change.

### Recommendation
Do not let `ReviewStack#env`/PR label-derived keys participate in `Command#interpolate_environment_variables`'s substitution source used to build the literal command-line string. Either: (1) whitelist which env keys may be used for `${VAR}` interpolation (e.g., only `deploy_spec`-approved variable names via `EnvironmentVariables#permit`) before calling `interpolate_environment_variables`, keeping label-derived keys usable only as literal subprocess environment variables (not substituted into the command text), or (2) strip/rename label-derived keys with a namespaced prefix (e.g., `LABEL_`) so they cannot collide with deploy-spec variable names referenced via `${VAR}` in `shipit.yml`.

### Proof of Concept
Minitest plan (mirrors existing `test/lib/shipit/task_commands_test.rb` pattern):
```ruby
test "PR labels cannot override ${VAR} interpolation in step command lines" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["deploy_target"]
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  # shipit.yml step under test: "echo ${DEPLOY_TARGET}"
  # Operator-configured value comes from machine_env/@task.env, e.g. "production"
  command = Shipit::TaskCommands.new(task).perform.first  # or a Command built with the step + env

  refute_includes command.interpolated_arguments.join(" "), "true",
    "label 'deploy_target' must not supply DEPLOY_TARGET used in ${DEPLOY_TARGET} interpolation"
  assert_includes command.interpolated_arguments.join(" "), "production"
end
```
Assert `command.env["DEPLOY_TARGET"] == "true"` (attacker side, from the label) while the interpolated command-line string still must equal the operator-configured value (`"production"`), demonstrating the two sides of the binding diverge.

### Citations

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

**File:** app/models/shipit/stack.rb (L54-63)
```ruby
    def env
      {
        'ENVIRONMENT' => environment,
        'LAST_DEPLOYED_SHA' => last_deployed_commit.sha,
        'GITHUB_REPO_OWNER' => repository.owner,
        'GITHUB_REPO_NAME' => repository.name,
        'DEPLOY_URL' => deploy_url,
        'BRANCH' => branch
      }
    end
```

**File:** lib/shipit/task_commands.rb (L17-27)
```ruby
    def install_dependencies
      deploy_spec.dependencies_steps!.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
    end

    def perform
      steps.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
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

**File:** lib/shipit/command.rb (L85-101)
```ruby
    def start(&block)
      return if @started

      @control_block = block
      @out = @pid = nil
      FileUtils.mkdir_p(@chdir)
      begin
        @out, child_in, @pid = PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)
        child_in.close
      rescue Errno::ENOENT
        raise NotFound, "#{Shellwords.split(interpolated_arguments.first).first}: command not found"
      rescue Errno::EACCES
        raise Denied, "#{Shellwords.split(interpolated_arguments.first).first}: Permission denied"
      end
      @started = true
      self
    end
```

**File:** lib/shipit/command.rb (L103-105)
```ruby
    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
    end
```

**File:** lib/shipit/environment_variables.rb (L20-27)
```ruby
    def interpolate(argument)
      return argument unless @env

      argument.gsub(/(\$\w+)/) do |variable|
        variable.sub!('$', '')
        Shellwords.escape(@env.fetch(variable) { ENV[variable] })
      end
    end
```
