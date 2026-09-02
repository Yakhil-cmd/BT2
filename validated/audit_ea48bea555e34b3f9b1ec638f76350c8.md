### Title
Unfiltered PR-label-derived environment variables (e.g. `LD_PRELOAD`) reach `PTY.spawn` for every deploy/task command on a review stack - (File: app/models/shipit/review_stack.rb, lib/shipit/task_commands.rb, lib/shipit/command.rb)

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) as an environment variable key with value `"true"`, with no allowlist of permitted keys. This merged env flows unfiltered through `TaskCommands#env` → `Command#env` → `Command#unbundled_env` → `PTY.spawn`, meaning an attacker who can label their own PR (e.g. with a label literally named `ld_preload`) can inject `LD_PRELOAD=true` (or any other sensitive env var name) into every process spawned for that review stack's deploy, task, fetch, or dependency-install commands.

### Finding Description
The broken binding: the invariant "the `deploy.variables` (and all other spawned) steps inherit no fork-controllable key such as `LD_PRELOAD`" is violated because `stack.env(key) == pull_request_label_name.upcase` for **any** label name, with no allowlist check.

Code path:
1. `LabelCapturingHandler#capture_labels` persists PR labels verbatim from the webhook payload: `pull_request.update!(labels: params.pull_request.labels.map(&:name))` [1](#0-0) . These labels come straight from GitHub PR labels — settable by the unprivileged fork PR author on their own PR/repo (an unprivileged actor per the rules can label their own PR).
2. `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` into the stack's env with **no key allowlist** [2](#0-1) .
3. `TaskCommands#env` merges `@stack.env` directly (unfiltered) into the command environment used for `install_dependencies`, `perform` (deploy/task steps), etc.: `super.merge(@stack.env).merge(...)` [3](#0-2) .
4. `DeployCommands#env` further merges on top of `TaskCommands#env`/`StackCommands#env`, never filtering out non-declared keys [4](#0-3) .
5. `Command#unbundled_env` simply stringifies and merges `@env` into the PATH-augmented base env, with no denylist/allowlist of dangerous variable names like `LD_PRELOAD`: `BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)` [5](#0-4) .
6. `Command#start` passes this env directly to `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` [6](#0-5) .

Why existing guards fail: `filter_deploy_envs`/`EnvironmentVariables#permit` (which does enforce an allowlist against `deploy_variables`) is only applied to the **user/API-submitted deploy env parameter** (`Stack#build_deploy`'s `env:` argument, and `deploys_controller`'s `:env` param) [7](#0-6) , and is tested to reject unknown keys from that specific input path [8](#0-7) . It is never applied to `stack.env`/`ReviewStack#env`, which is a completely separate merge point that reaches `Command` unfiltered, as shown directly by the existing test asserting label names become env keys: `assert_equal env["WIP"], "true"` [9](#0-8) .

Exploit flow: an unprivileged fork user opens a PR against a repo configured with `provisioning_behavior = allow_all` and `review_stacks_enabled = true`, applies a label named `ld_preload` (or any case variant) to their own PR, and GitHub emits a `pull_request` `labeled` webhook to `POST /webhooks`. `LabelCapturingHandler` persists this label onto the `PullRequest` record tied to the auto-provisioned `ReviewStack`. On the next deploy/task/dependency-install run for that review stack, `LD_PRELOAD=true` is injected into the spawned process's environment.

### Impact Explanation
Setting `LD_PRELOAD` to a value doesn't by itself achieve RCE unless the attacker can also control the file path preloaded and have that file exist on the deploy host and be loadable — `LD_PRELOAD=true` (the literal string `"true"` is the value always used, not attacker-controlled arbitrary path) would typically just fail silently or error since `"true"` is not a valid shared object path. The demonstrated primitive is that an attacker-chosen **variable name** reaches the spawned environment, but the **value** is hard-coded to the string `"true"` by `ReviewStack#env` — the attacker cannot set `LD_PRELOAD` to a path of their choosing via this mechanism. This significantly reduces the practical RCE impact: the attacker can pollute environment variable *names* they choose, but not the *values*, for this specific injection point. Genuine RCE via `LD_PRELOAD` requires the attacker to control the path/value, which this code path does not allow (value is always `"true"`). This blunts the Critical/RCE claim from the question as literally stated, though it is still a real design flaw (arbitrary env-key injection with no allowlist) that could combine with other primitives (e.g., if any deploy step interprets these boolean flags to construct paths, or if another mechanism lets an attacker control an arbitrary env value).

### Likelihood Explanation
Preconditions: `review_stacks_enabled = true` and `provisioning_behavior = allow_all` (or the PR carries the provisioning label under `allow_with_label`) so a fork PR provisions a `ReviewStack`; attacker needs no special privileges beyond opening a PR and applying a label to it, which is possible even for a PR against someone else's repo if the attacker owns the label-application right (typically requires triage/write access to the target repo to add labels; if the target repo is the attacker's own fork with review-stack-enabled webhook wiring, they can self-label). This constrains the true attack surface: labeling PRs typically requires being the repo owner, a maintainer, or a collaborator with "triage" access on the target repository — not just being a PR author on someone else's repo. This is a meaningful precondition not fully explored above.

### Recommendation
Apply a strict allowlist (or denylist of known-dangerous names such as `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `BUNDLE_GEMFILE`, `RUBYOPT`, `PATH`, etc.) to `ReviewStack#env`'s label-derived keys before merging, e.g. reject/skip label names colliding with reserved/dangerous environment variable names, and route this merge through the same `EnvironmentVariables.permit` allowlist mechanism (against a small hardcoded list of safe label-flag names or a repo-configurable list), rather than merging arbitrary uppercased label text unfiltered into the process environment.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (add)
test "#env does not allow labels to inject dangerous variable names like LD_PRELOAD" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["ld_preload"]

  assert_equal "true", stack.env["LD_PRELOAD"]
  # Demonstrates env pollution: any label name, uppercased, becomes an
  # unfiltered environment variable name reaching Command#unbundled_env
  # with no allowlist against dangerous variable names.
end
```
```ruby
# test/unit/deploy_commands_test.rb style, showing propagation to Command
test "#perform allows label-derived LD_PRELOAD to reach the spawned command env" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["ld_preload"]
  deploy = stack.trigger_continuous_delivery
  commands = Shipit::DeployCommands.new(deploy)

  assert_equal "true", commands.env["LD_PRELOAD"]
  command = commands.perform.first
  assert_equal "true", command.env["LD_PRELOAD"]
  assert_equal "true", command.unbundled_env["LD_PRELOAD"]
end
```
Both assertions pass against current code, proving the label-name-to-env-key merge is unfiltered all the way to the value that would be passed to `PTY.spawn`. Note the PoC only demonstrates key injection with the fixed value `"true"`, not attacker-controlled value injection, which limits it short of full RCE as literally claimed.

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

**File:** lib/shipit/deploy_commands.rb (L9-16)
```ruby
    def env
      commit = @task.until_commit
      super.merge(
        'SHA' => commit.sha,
        'REVISION' => commit.sha,
        'DIFF_LINK' => diff_url
      )
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

**File:** app/models/shipit/stack.rb (L161-172)
```ruby
    def build_deploy(until_commit, user, env: nil, force: false, allow_concurrency: force)
      since_commit = last_deployed_commit.presence || commits.first
      deploys.build(
        user_id: user.id,
        until_commit:,
        since_commit:,
        env: filter_deploy_envs(env.to_h),
        allow_concurrency:,
        ignored_safeties: force || !until_commit.deployable?,
        max_retries: retries_on_deploy
      )
    end
```

**File:** test/controllers/deploys_controller_test.rb (L72-76)
```ruby
    test ":create ignore :env keys not declared in the deploy spec" do
      post :create, params: { stack_id: @stack.to_param, deploy: { until_commit_id: @commit.id, env: { 'H4X0R' => '1' } } }
      new_deploy = Deploy.last
      assert_equal({}, new_deploy.env)
    end
```

**File:** test/lib/shipit/deploy_commands_test.rb (L6-15)
```ruby
  test "#env includes the stack's pull request labels" do
    stack = shipit_stacks(:review_stack)
    deploy = stack.trigger_continuous_delivery
    stack.pull_request.labels = ["wip", "bug"]

    env = Shipit::DeployCommands.new(deploy).env

    assert_equal env["WIP"], "true"
    assert_equal env["BUG"], "true"
  end
```
