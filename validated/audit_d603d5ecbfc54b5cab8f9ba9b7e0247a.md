Confirmed: no validation, length limit, or format check on `labels` at the `Shipit::PullRequest` model level (only `serialize :labels`), so the raw GitHub label name flows unfiltered end-to-end. [1](#0-0) [2](#0-1) 

### Title
Unwhitelisted PR labels are promoted verbatim into process environment variables reaching `PTY.spawn` - (File: app/models/shipit/review_stack.rb)

### Summary
`Shipit::LabelCapturingHandler#capture_labels` persists raw GitHub label names onto the stack's `PullRequest` with no length, character, or reserved-name filtering. `ReviewStack#env` then upcases each label and injects it as an environment variable, and unlike every other user-controllable env source in the codebase, this path never calls `EnvironmentVariables#permit` against a `VariableDefinition` whitelist before the value reaches `Command#start`/`PTY.spawn`.

### Finding Description
The broken binding: the set of label names accepted by `LabelCapturingHandler#capture_labels` should equal the empty whitelist enforced by `EnvironmentVariables#permit`, but instead equals the entire unrestricted set of GitHub label strings.

`LabelCapturingHandler#capture_labels` writes labels straight from the webhook payload with no filtering: [3](#0-2) 

`ReviewStack#env` merges these labels directly into the environment hash by upcasing the name as the key, with no call to `EnvironmentVariables.with(...).permit(...)`: [4](#0-3) 

This is in contrast to every other place user/attacker-influenced env data enters Shipit, all of which explicitly whitelist via `EnvironmentVariables#permit`: `DeploySpec#filter_deploy_envs`/`filter_rollback_envs` [5](#0-4) , `TaskDefinition#filter_envs` [6](#0-5) , and the controller-level strong params (`deploys_controller.rb#deploy_params`, `tasks_controller.rb#task_params`) which restrict submitted `env` keys to `stack.deploy_variables`/`definition.variables`. `ReviewStack#env` has no equivalent guard.

The unfiltered `stack.env` is merged into every task/deploy's environment by `TaskCommands#env`: [7](#0-6) 

That hash is passed to `Command.new(..., env:)`, stored as `@env`, and merged unfiltered into the process environment used to spawn the actual OS process: [8](#0-7) [9](#0-8) 

Attack flow: an attacker with the ability to label a pull request on a repository that has a review stack (per the question's threat model, "any GitHub user who can... label their own PR") sends a `labeled` action with `labels: [{"name": "GEM_HOME"}]` (or `RUBYLIB`, `GEM_PATH`). `LabelCapturingHandler#capture_labels?` → `labeled_active_stack?` returns true because the stack exists and is not archived. `capture_labels` calls `pull_request.update!(labels: ["GEM_HOME"])` with no validation — `Shipit::PullRequest` only declares `serialize :labels` [1](#0-0) , no format/length/blacklist validation exists on the column. On the next task/deploy against that stack, `ReviewStack#env` computes `labels["GEM_HOME"] = "true"`, which is merged into the command's environment and reaches `PTY.spawn`, poisoning Ruby/Bundler's gem load path for every `bundle`/`ruby` invocation of that deploy.

Existing guards do not catch this: webhook signature verification (`verify_signature`) only authenticates that GitHub sent the payload, it does not restrict label content; `ExplicitParameters` in `LabelCapturingHandler` only requires `labels` to be an `Array` of objects with a `name: String` — no charset/blacklist constraint; `EnvironmentVariables#permit` exists and is used elsewhere, but `ReviewStack#env` never invokes it.

### Impact Explanation
Any command Shipit executes for that review stack (`bundle install`, `bundle exec cap ... deploy`, custom task steps) inherits the poisoned `GEM_HOME`/`GEM_PATH`/`RUBYLIB` value, which can redirect Ruby's/Bundler's load path toward attacker-influenced or unexpected locations during `Command#start`'s `PTY.spawn` invocation, an RCE-adjacent primitive on the deploy host. This is repeatable on every deploy/task run against the affected stack for as long as the label remains, and is scoped to whichever repository/stack the attacker can label — it does not cross into other tenants' stacks unless the attacker also controls those repositories' PRs.

### Likelihood Explanation
Preconditions: the target repository must have review stacks enabled and an active (non-archived) `ReviewStack` for the attacker's PR; the attacker must be able to add a label to that PR (labeling capability, which the threat model provided in this audit assumes is available to the attacker on their own PR/repository). No Shipit secrets, session, or API token are required — only the ability to trigger a normal `labeled` GitHub webhook, which GitHub itself signs. Attacker cost is a single label addition; the exploit is trivially repeatable.

### Recommendation
In `ReviewStack#env`, run the label-derived hash (and ideally the label names themselves before persistence in `LabelCapturingHandler#capture_labels`) through `Shipit::EnvironmentVariables.with(...).permit(...)` against an explicit whitelist of allowed label-derived variable names (or disallow label names entirely from becoming env keys), and additionally validate/reject label names matching sensitive/reserved variable names (`GEM_HOME`, `GEM_PATH`, `RUBYLIB`, `BUNDLE_*`, `PATH`, `LD_PRELOAD`, etc.) at the `Shipit::PullRequest` model or `LabelCapturingHandler` layer before persistence.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (new test)
test "#env does not promote unwhitelisted label names into the environment" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["GEM_HOME"]

  assert_raises(Shipit::EnvironmentVariables::NotPermitted) do
    Shipit::EnvironmentVariables.with(stack.env).permit(stack.deploy_variables)
  end
end
```
This demonstrates that `stack.env` (and therefore the env ultimately merged by `TaskCommands#env` into `Command`) contains a `GEM_HOME` key that was never checked against any `VariableDefinition` whitelist — `ReviewStack#env` never calls `.permit`, so the assertion fails to raise, proving the unfiltered promotion of label names into process environment variables.

### Citations

**File:** app/models/shipit/pull_request.rb (L14-14)
```ruby
    serialize :labels, coder: Shipit.serialized_column(:labels, type: Array)
```

**File:** app/models/shipit/pull_request.rb (L48-48)
```ruby
      self.labels = github_pull_request.labels.map(&:name)
```

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

**File:** app/models/shipit/deploy_spec.rb (L174-180)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
    end

    def filter_rollback_envs(env)
      EnvironmentVariables.with(env).permit(rollback_variables)
    end
```

**File:** app/models/shipit/task_definition.rb (L63-65)
```ruby
    def filter_envs(env)
      EnvironmentVariables.with(env).permit(variables)
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

**File:** lib/shipit/command.rb (L85-98)
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
```

**File:** lib/shipit/command.rb (L103-105)
```ruby
    def unbundled_env
      BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)
    end
```
