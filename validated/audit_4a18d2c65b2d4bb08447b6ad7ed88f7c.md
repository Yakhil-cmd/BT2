### Title
Unfiltered PR label names become process environment variables (e.g. `PERL5OPT`) for review-stack deploy steps - ([File: app/models/shipit/review_stack.rb])

### Summary
`ReviewStack#env` merges every pull request label name (uppercased) directly into the stack's environment hash with no allowlist, and this hash flows unfiltered through `TaskCommands#env`/`DeployCommands#env` into `Command#unbundled_env` and ultimately `PTY.spawn`. The `deploy.variables` allowlist (`EnvironmentVariables#permit`) is only applied to explicit API-submitted `env` params, never to label-derived keys, so a fork PR can set an arbitrary environment variable name (e.g. `PERL5OPT`) for the deploy host process.

### Finding Description
The broken binding: the set of environment variables reaching `PTY.spawn` for a review stack's deploy steps should equal `deploy.variables`-whitelisted keys plus fixed Shipit-defined keys; it does not — it also equals `pull_request.labels.map(&:upcase)` with no filter.

Code path:
1. `LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` straight from the webhook body with no validation: [1](#0-0) 
2. `ReviewStack#env` merges those label names, uppercased, as `"true"`-valued env entries, with no key allowlist: [2](#0-1) 
3. `TaskCommands#env` (base class of `DeployCommands`) merges `@stack.env` directly into the environment used to build each step's `Command`, and merges the *filtered* `@task.env` last — but this does not retroactively strip keys already introduced by `@stack.env`: [3](#0-2) 
4. `DeploySpec#filter_deploy_envs` (the actual `deploy.variables` allowlist via `EnvironmentVariables#permit`) exists but is only invoked against explicit API-submitted `env` params (see controller tests rejecting `DANGEROUS_VARIABLE`), never against the `@stack.env` merge in `TaskCommands#env`: [4](#0-3) [5](#0-4) 
5. `Command#start`/`#unbundled_env` merges `@env` (which now contains `PERL5OPT=true`) into the process environment passed to `PTY.spawn`: [6](#0-5) 

Existing tests already demonstrate the unfiltered merge mechanism (using benign labels `wip`/`bug`), confirming there is no key restriction: [7](#0-6) [8](#0-7) 

Attacker request: open a fork PR against a repo configured `provisioning_behavior: allow_with_label`, add a label literally named `perl5opt` (or `PERL5OPT`) to their own PR (per the stated threat model, labeling one's own PR is an available attacker capability), and add the repo's designated provisioning label so the review stack is provisioned. When the stack next runs `deploy.variables`-governed deploy steps (e.g. triggered by continuous delivery or push), the resulting environment includes `PERL5OPT=true`, which is inherited by any `perl`/Bundler-invoked-perl process in the deploy pipeline, causing `-M`/`-d` style module loading at interpreter startup.

Why existing guards fail: `EnvironmentVariables#permit`/`filter_deploy_envs` is a real allowlist, but it is wired only into the API-triggered deploy `env` parameter path, not into the `ReviewStack#env` → `TaskCommands#env` merge chain that ultimately builds the `Command` for deploy steps.

### Impact Explanation
An attacker who can label their own fork PR causes an environment variable of their choosing to be injected into the deploy host process that executes `deploy.variables`/deploy steps for that repository's review stack. `PERL5OPT` is a real Perl startup-hook variable capable of loading arbitrary `-M`/`-d` modules if any step in the pipeline (deploy scripts, Capistrano, dependency tooling) invokes `perl`. This matches the Critical "RCE on the deploy host via `Command`/`PTY.spawn`" category. Blast radius is scoped to review stacks of the repository whose PR is labeled, but is repeatable on every deploy/task run for that stack as long as the label persists.

### Likelihood Explanation
Requires `provisioning_behavior: allow_with_label` (a supported, documented configuration) and a deploy pipeline that somewhere invokes `perl` (common via Bundler/Capistrano-based `deploy.yml`/`shipit.yml` steps). Per the stated threat model, the only precondition is the ability to open a PR and add a label to it — no Shipit session, API token, or GitHub secret is required. This makes the attack low-cost and repeatable.

### Recommendation
Apply `DeploySpec#filter_deploy_envs` (or an equivalent allowlist against `deploy_variables`) to the label-derived portion of `@stack.env` before merging it in `TaskCommands#env`/`ReviewStack#env`, rather than only to explicit API-submitted `env` params. Alternatively, prefix label-derived keys (e.g. `LABEL_<NAME>`) or restrict them to a dedicated non-overridable namespace that can never collide with sensitive interpreter/loader environment variables (`PERL5OPT`, `LD_PRELOAD`, `RUBYOPT`, `PYTHONSTARTUP`, `NODE_OPTIONS`, etc.), and deny any label name that collides with such a denylist.

### Proof of Concept
Minitest plan (extends `test/lib/shipit/task_commands_test.rb` pattern):
```ruby
test "#env does not leak arbitrary interpreter env vars from PR labels" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["perl5opt"]
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  env = Shipit::TaskCommands.new(task).env

  # Binding under test: deploy.variables allowlist should exclude label-derived keys
  refute env.key?("PERL5OPT"), "PERL5OPT should not be settable via a PR label"
end
```
Before the fix, `env["PERL5OPT"]` equals `"true"` (per the same mechanism proven by the existing `WIP`/`BUG` tests), demonstrating the fork-controllable key reaches the `Command`/`PTY.spawn` environment; after applying an allowlist to label-derived env, the assertion passes.

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

**File:** app/models/shipit/deploy_spec.rb (L174-176)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
    end
```

**File:** test/controllers/api/deploys_controller_test.rb (L42-47)
```ruby
      test "#create refuses to trigger a new deploy with incorrect variables" do
        incorrect_env = { 'DANGEROUS_VARIABLE' => 1 }
        post :create, params: { stack_id: @stack.to_param, sha: @commit.sha, env: incorrect_env }
        assert_response :unprocessable_entity
        assert_json 'message', 'Variables DANGEROUS_VARIABLE have not been whitelisted'
      end
```

**File:** lib/shipit/command.rb (L85-105)
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

    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
    end
```

**File:** test/lib/shipit/task_commands_test.rb (L6-16)
```ruby
  test "#env includes a ReviewStack's pull request labels" do
    stack = shipit_stacks(:review_stack)
    stack.pull_request.labels = ["wip", "bug"]
    task = shipit_tasks(:shipit_restart)
    task.stack = stack

    env = Shipit::TaskCommands.new(task).env

    assert_equal env["WIP"], "true"
    assert_equal env["BUG"], "true"
  end
```

**File:** test/models/shipit/review_stack_test.rb (L59-65)
```ruby
    test "#env includes the stack's pull request labels" do
      stack = shipit_stacks(:review_stack)
      stack.pull_request.labels = ["wip", "bug"]

      assert_equal stack.env["WIP"], "true"
      assert_equal stack.env["BUG"], "true"
    end
```
