### Title
`OpenedHandler#provision?` boolean-precedence bug bypasses `review_stacks_enabled`, allowing an attacker-controlled PR branch's `shipit.yml` task steps to run with `GITHUB_TOKEN` in scope - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::PullRequest::OpenedHandler#provision?` uses `&&`/`||` without parentheses around the `review_stacks_enabled` check, so `review_stacks_enabled` only gates the `allow_all` branch of the condition, not the `allow_with_label`/`prevent_with_label` branches. This lets a `Stack` be auto-provisioned with `branch: params.pull_request.head.ref` (the attacker's own fork branch) even when an operator believes review-stack auto-provisioning is off for that repository. Once such a stack exists, its `DeploySpec::FileSystem` reads `.shipit/shipit.yml` from that attacker branch, so any task later triggered against that stack executes attacker-authored steps with the real `GITHUB_TOKEN` and other secrets injected by `TaskCommands#env`/`Commands#base_env`.

### Finding Description
The claimed binding is: `repository.review_stacks_enabled == false` should imply "no review stack is provisioned for repository X," for all provisioning behaviors.

Code:
```ruby
# app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Ruby operator precedence makes `&&` bind tighter than `||`, so this evaluates as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`.

`review_stacks_enabled` is only ANDed into the first disjunct. If `repository.provisioning_behavior` is `allow_with_label` or `prevent_with_label` (independent DB columns from `review_stacks_enabled`, see `enum :provisioning_behavior` in `app/models/shipit/repository.rb:50-51`) [2](#0-1) , the second or third disjunct can be `true` regardless of `review_stacks_enabled`. So `respond_to_pull_request_opened?` (`params.action == "opened" && provision?`) [3](#0-2)  returns true and `ReviewStackAdapter#find_or_create!` provisions a stack even though the operator toggled `review_stacks_enabled` off.

`ReviewStackAdapter#create!` sets `branch: params.pull_request.head.ref` from the webhook payload [4](#0-3)  — i.e., the attacker's own fork/branch, fully attacker-controlled and requiring no approval.

Once provisioned, any task run against that stack builds its spec via `DeploySpec::FileSystem`, which resolves `.shipit/shipit.yml` as the highest-priority config file (`shipit_file_names_in_priority_order`, `config_file_path`) [5](#0-4)  read from the checked-out attacker branch. `TaskDefinition#steps`/`find_task_definition` pulls the `tasks:` block verbatim from that YAML [6](#0-5) . `TaskCommands#steps` returns `@task.definition.steps` [7](#0-6) , `#perform` wraps each into `Command.new(command_line, env:, chdir:)` [8](#0-7) , and `env` is built from `Commands#base_env`, which always includes `'GITHUB_TOKEN' => github.token` [9](#0-8) . `Command#interpolated_arguments` expands `$GITHUB_TOKEN` via `EnvironmentVariables#interpolate` (only Shellwords-escapes the value, does not strip/deny secret names) [10](#0-9)  before `Command#start` calls `PTY.spawn` [11](#0-10) .

Existing guards do not stop this: `EnvironmentVariables#permit` is only applied to deploy/rollback envs via `filter_deploy_envs`/`filter_rollback_envs` in `deploy_spec.rb:174-180` [12](#0-11) , not to the base `TaskCommands#env`, so it does not block `GITHUB_TOKEN` from being present/interpolatable. There is no code path that re-checks `review_stacks_enabled` before running a task on an already-provisioned `ReviewStack` — provisioning is the sole gate, and that gate is broken by the operator-precedence bug.

### Impact Explanation
An attacker who can open a PR against a repository with `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` (regardless of the operator's intended `review_stacks_enabled = false`) gets an automatically-created `Stack` whose `branch` is entirely attacker-controlled. If any authorized user (or automation) later triggers a task/deploy on that stack, the attacker's `.shipit/shipit.yml` steps run as shell commands via `Command`/`PTY.spawn` with `GITHUB_TOKEN` (and other deploy-time secrets from `Commands#base_env`/`TaskCommands#env`) present in the process environment and available for shell interpolation — enabling exfiltration of `GITHUB_TOKEN` and arbitrary RCE on the deploy host. This matches the Critical severity category (RCE via `Command`/`PTY.spawn`, exfiltration of `GITHUB_TOKEN`). It is repeatable against any repository configured with `provisioning_behavior_allow_with_label?`/`prevent_with_label?`, independent of the `review_stacks_enabled` flag, and does not require any privileged Shipit role.

### Likelihood Explanation
Preconditions: the target repository must have `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` (a normal, documented configuration, not an edge case) while an operator separately has `review_stacks_enabled = false` — a plausible operator expectation ("I disabled review stacks, so no PR can create one regardless of label behavior"). The attacker only needs to open a PR from their own fork/branch and, for `allow_with_label`, apply a label to their own PR (label names are attacker-controlled on their own PR events). No secrets, sessions, or maintainer roles are required to trigger provisioning. Getting a task/deploy actually executed on the resulting stack still requires some other actor (human or continuous-deployment automation) to run a task against it, which somewhat limits immediate exploitation but is standard review-stack usage.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates the entire condition:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the same fix to the structurally identical `ReopenedHandler#unarchive?` [13](#0-12)  and `LabeledHandler#respond_to_label_change?`/`archive?`/`unarchive?` if they have the same precedence issue. Additionally, consider filtering `TaskCommands#env` through an explicit variable allowlist (similar to `EnvironmentVariables#permit` used for deploy/rollback) so arbitrary task steps sourced from repository-controlled YAML cannot reference `GITHUB_TOKEN` at all.

### Proof of Concept
Add a minitest to `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`:
```ruby
test "does NOT create a stack when review_stacks_enabled is false, even if provisioning_behavior is allow_with_label and label present" do
  repository = shipit_repositories(:shipit)
  repository.review_stacks_enabled = false
  repository.provisioning_behavior = :allow_with_label
  repository.provisioning_label_name = "pull-requests-label"
  repository.save!

  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Assert both sides of the binding: before the fix, `Shipit::Stack.count` increases (violating `review_stacks_enabled == false ⇒ no stack created`); after applying the parenthesization fix, `assert_no_difference` passes.

A second-stage proof (already partly demonstrated by existing tests like `test/unit/command_test.rb`'s `#interpolate_environment_variables escape the variable contents` and `test/unit/deploy_commands_test.rb`'s `#env uses the correct Github token for a stack`) can stub `Shipit::DeploySpec::FileSystem#find_task_definition` to return a `TaskDefinition` with `steps: ['echo $GITHUB_TOKEN']`, run `Shipit::TaskCommands.new(task).perform`, and assert the interpolated command line contains the stubbed `GITHUB_TOKEN` value, confirming the secret reaches `Command#interpolated_arguments`/`PTY.spawn`.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L60-63)
```ruby
          def respond_to_pull_request_opened?
            params.action == "opened" &&
              provision?
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/models/shipit/repository.rb (L50-51)
```ruby
    PROVISIONING_BEHAVIORS = %w[allow_all allow_with_label prevent_with_label].freeze
    enum :provisioning_behavior, PROVISIONING_BEHAVIORS.zip(PROVISIONING_BEHAVIORS).to_h, prefix: :provisioning_behavior
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L87-94)
```ruby
          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```

**File:** app/models/shipit/deploy_spec/file_system.rb (L111-142)
```ruby
      def shipit_file_names_in_priority_order
        YAML_EXTENSIONS.flat_map do |ext|
          [
            "#{app_name}.#{@env}.#{ext}",
            ".shipit/#{app_name}.#{@env}.#{ext}",

            "#{app_name}.#{ext}",
            ".shipit/#{app_name}.#{ext}",

            "shipit.#{@env}.#{ext}",
            ".shipit/#{@env}.#{ext}",

            "shipit.#{ext}",
            ".shipit/shipit.#{ext}"
          ]
        end.uniq
      end

      def bare_shipit_filenames
        YAML_EXTENSIONS.flat_map do |ext|
          ["#{app_name}.#{ext}", "shipit.#{ext}", ".shipit/#{app_name}.#{ext}", ".shipit/shipit.#{ext}"]
        end.uniq
      end

      def config_file_path
        shipit_file_names_in_priority_order.each do |filename|
          path = file(filename, root: true)
          return path if path.exist?
        end

        nil
      end
```

**File:** app/models/shipit/deploy_spec.rb (L169-172)
```ruby
    def find_task_definition(id)
      definition = config('tasks', id) || discover_task_definitions[id]
      TaskDefinition.new(id, coerce_task_definition(definition) || task_not_found!(id))
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

**File:** lib/shipit/task_commands.rb (L23-27)
```ruby
    def perform
      steps.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
    end
```

**File:** lib/shipit/task_commands.rb (L29-31)
```ruby
    def steps
      @task.definition.steps
    end
```

**File:** lib/shipit/commands.rb (L37-50)
```ruby
    def base_env
      @base_env ||= begin
        env = Shipit.env.merge(
          'GITHUB_DOMAIN' => github.domain,
          'GITHUB_TOKEN' => github.token
        )

        if Shipit.use_git_askpass?
          env['GIT_ASKPASS'] = Shipit::Engine.root.join('lib', 'snippets', 'git-askpass').realpath.to_s
        end

        env
      end
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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L70-75)
```ruby
          def unarchive?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```
