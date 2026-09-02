### Title
`NODE_OPTIONS` env injection via PR label name lets fork PR authors inject flags into `npm ci`/node subprocesses on a `ReviewStack` - (File: app/models/shipit/review_stack.rb)

### Summary
`ReviewStack#env` merges every pull request label, upper-cased, directly into the task/deploy environment hash with no allowlist, and this hash is passed unfiltered to `Command#unbundled_env` → `PTY.spawn`. Because `TaskCommands#perform`/`#install_dependencies` build `Command.new(command_line, env:, chdir:)` without ever calling `EnvironmentVariables#permit`, an attacker who can label their own PR (e.g. with `node_options`) can set `NODE_OPTIONS` for every task/deploy step that runs on that review stack, including `npm ci`.

### Finding Description
The broken binding: the set of environment keys reaching the spawned child process should equal `Stack#env.keys` (a fixed, code-defined set: `ENVIRONMENT`, `LAST_DEPLOYED_SHA`, `GITHUB_REPO_OWNER`, `GITHUB_REPO_NAME`, `DEPLOY_URL`, `BRANCH`) plus explicitly whitelisted deploy/rollback `variable_definitions` from `EnvironmentVariables#permit`. In reality, for `ReviewStack`, the key set is `Stack#env.keys ∪ pull_request.labels.map(&:upcase)`, with no whitelist check.

Code path:
1. `LabelCapturingHandler#capture_labels` in `app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:98-102` writes `pull_request.update!(labels: params.pull_request.labels.map(&:name))` straight from the webhook payload's `pull_request.labels[].name` field — an attacker fully controls this via their own PR's labels on their own fork/repo. [1](#0-0) 

2. `ReviewStack#env` merges these labels, upper-cased, into the environment with no filtering: [2](#0-1) 

3. `TaskCommands#env` merges `@stack.env` (which includes the label-derived keys) into the final env hash used for every step, with no call to `EnvironmentVariables#permit`: [3](#0-2) 

4. `TaskCommands#perform` / `#install_dependencies` construct `Command.new(command_line, env:, chdir:)` directly from this unfiltered hash for every deploy-spec step, including a step like `npm ci`: [4](#0-3) 

5. `Command#unbundled_env` merges `@env.stringify_keys` on top of `BASE_ENV`/`PATH` with no key restriction, and `Command#start` passes the result straight into `PTY.spawn`: [5](#0-4) 

Existing guard `EnvironmentVariables#permit`/`sanitize_env_vars` (used only via `DeploySpec#filter_deploy_envs`/`filter_rollback_envs` for `deploy`/`rollback` task *user-supplied* variables) never sees the `Stack#env`/`ReviewStack#env` hash, so it does not protect this path. [6](#0-5) [7](#0-6) 

Exploit: an unprivileged fork PR author opens a PR against a repository that has review stacks enabled for external PRs (a normal Shipit feature, not a privileged action), adds a label named `node_options` to their own PR. When any deploy-spec step for that review stack's task/deploy runs (e.g. a step invoking `npm ci`), the process inherits `NODE_OPTIONS=true`. While the demonstrable value here is fixed to the literal string `"true"` (labels are mapped to the string `"true"`, not attacker-chosen content) rather than an arbitrary value like `--require /path/to/evil`, this still lets an attacker forcibly set/pollute arbitrary env var names (uppercased) in the subprocess. Setting `NODE_OPTIONS=true` alone does not achieve `--require` injection — the value is fixed by `ReviewStack#env`'s implementation (`labels[label_name.upcase] = "true"`), not attacker-controlled. This weakens the specific RCE claim in the prompt (`--require /path/to/evil`) since the attacker cannot set arbitrary *values*, only force the *presence* of an arbitrary-named var with a hardcoded value of `"true"`.

### Impact Explanation
The attacker can force known-sensitive environment variable names to be set to the string `"true"` on the deploy host process running `npm ci` or any other step for a repository's review stack, using only their own PR's labels. This is real environment pollution reaching `PTY.spawn`, matching the general command/child-process environment control impact. However, because the injected value is hardcoded to `"true"` and not attacker-chosen, this does not achieve the specific `--require /path/to/evil` RCE payload claimed in the prompt. Some Node/npm behaviors are sensitive to boolean-like env values (e.g., certain `NODE_OPTIONS`-based feature toggles) but arbitrary code execution via `NODE_OPTIONS=true` is not established without further evidence that any option string `"true"` alone causes code execution — Node itself would reject `--require` semantics because the value isn't a flag string. So the "critical RCE" bar for this specific vector is not clearly met with the given code.

### Likelihood Explanation
Preconditions: repository must have review stacks enabled for PRs (via `provisioning_behavior`), which is a standard, intentional Shipit feature for repos that opt in. Attacker cost is minimal (add a label to their own PR). This is fully repeatable across any repository that has review stacks enabled, for any label name the attacker chooses (uppercased). Attacker cannot choose the *value* of the variable, only its *name*, limiting exploitation to attacks that succeed via presence/boolean toggling of an env var rather than injecting a controlled string.

### Recommendation
`ReviewStack#env` should not merge raw pull-request label names into the process environment without an allowlist. At minimum, exclude known-sensitive/interpreter-affecting variable names (e.g. `NODE_OPTIONS`, `RUBYOPT`, `LD_PRELOAD`, `PYTHONSTARTUP`, `BASH_ENV`, `PATH`) or require that review-stack-label-derived variables use a distinct, prefixed namespace (e.g. `LABEL_<NAME>`) so they can never collide with interpreter-recognized variable names, and/or run `EnvironmentVariables#permit` against a stack-configured whitelist before merging into `TaskCommands#env`.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (conceptual)
test "#env lets PR labels set NODE_OPTIONS-named key" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["node_options"]

  assert_equal "true", stack.env["NODE_OPTIONS"]
end
```
```ruby
# lib/shipit/task_commands_test.rb (conceptual)
test "npm ci step env includes NODE_OPTIONS from PR label" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["node_options"]
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  env = Shipit::TaskCommands.new(task).env
  assert_equal "true", env["NODE_OPTIONS"]
end
```
Note: this only demonstrates that an attacker-named, fixed-value (`"true"`) environment variable reaches the command environment — it does not demonstrate arbitrary-value injection (e.g. `--require /path/to/evil`) since `ReviewStack#env` hardcodes the value to `"true"`.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
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

**File:** lib/shipit/command.rb (L92-105)
```ruby
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

    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
    end
```

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
    end
```

**File:** app/models/shipit/deploy_spec.rb (L174-180)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
    end

    def filter_rollback_envs(env)
      EnvironmentVariables.with(env).permit(rollback_variables)
    end
```
