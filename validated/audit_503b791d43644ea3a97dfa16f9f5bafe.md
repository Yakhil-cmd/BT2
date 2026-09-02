### Title
`shipit.yml` `machine.environment` and PR labels inject unfiltered env keys (including `BASH_ENV`) into review-stack deploy processes - (File: `app/models/shipit/deploy_spec.rb`, `lib/shipit/task_commands.rb`, `app/models/shipit/review_stack.rb`, `lib/shipit/command.rb`)

### Summary
`TaskCommands#env` merges `deploy_spec.machine_env` (read verbatim from the checked-out `shipit.yml`) and `Stack#env`/`ReviewStack#env` (which injects every PR label name as an env key) directly into the deploy environment with no key/value whitelist, unlike the API-supplied `env` param which is filtered through `EnvironmentVariables#permit`. Both `deploy_spec.machine_env` and PR label names are attacker-controlled for a fork PR under `allow_with_label` (or `allow_all`) provisioning, so an unprivileged PR author can set `BASH_ENV` (key and, for `machine_env`, value) which ends up unfiltered in `Command#env` → `Command#unbundled_env` → `PTY.spawn`.

### Finding Description
The broken binding: the code implicitly assumes `env reaching PTY.spawn == EnvironmentVariables.permit(whitelist)`, but in reality `env reaching PTY.spawn == permit(whitelist) ∪ stack.env ∪ deploy_spec.machine_env`, and the latter two are not passed through `permit` at all.

Path:
- `lib/shipit/task_commands.rb` `TaskCommands#env` (lines 33-48) builds the deploy environment as `super.merge(@stack.env).merge(...).merge(deploy_spec.machine_env).merge(@task.env)`. [1](#0-0) 
- `@stack.env` for a `ReviewStack` injects every PR label name, upcased, as an environment key with value `"true"`, with no whitelist check at all: `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }`. [2](#0-1) 
- `deploy_spec.machine_env` returns `config('machine', 'environment') || {}` — read straight from the `shipit.yml` YAML checked out from the PR branch's working tree, with no key or value restriction (both key and value are fully attacker-controlled). [3](#0-2) 
- `DeploySpec::FileSystem` loads this config from files in `@app_dir` (the task's `working_directory`, i.e. the checked-out fork commit for a review stack) via `load_config`/`config_file_path`, so a PR author fully controls `shipit.yml`'s `machine.environment` map on their own branch. [4](#0-3) 
- `Command#env` stores the merged hash verbatim (only stringifying values), and `Command#unbundled_env` merges it into the process env used by `PTY.spawn`, with no key filtering anywhere in this call chain. [5](#0-4) [6](#0-5) 

Contrast: the only place `EnvironmentVariables#permit` is applied is to task/deploy `env` params supplied through the API (`filter_deploy_envs`/`filter_rollback_envs` in `DeploySpec`, `TaskDefinition#filter_envs`), which sanitizes `@task.env`, not `@stack.env` or `deploy_spec.machine_env`. [7](#0-6) [8](#0-7) 

Reachability: `provisioning_behavior=allow_with_label` review stacks are created/updated purely by webhook events from the fork's own PR (`labeled`/`opened`/`reopened` handlers), driven by `params.repository.full_name`, `pull_request.labels`, and `pull_request.head.ref` — none of which require any Shipit credential; `provision?`/`respond_to_pull_request_opened?` only checks the label name against `repository.provisioning_label_name`. [9](#0-8) [10](#0-9) 

Attacker's exact PR: open (or label) a PR from a fork against a repo configured with `provisioning_behavior=allow_with_label`, with a label whose name is `BASH_ENV` (opt-in label) and commit a `shipit.yml` on the branch containing:
```yaml
machine:
  environment:
    BASH_ENV: /path/to/attacker_controlled_file_in_checkout
```
When `ReviewStackProvisioningQueue`/`PerformTaskJob` runs a deploy/task for that stack, `TaskCommands#env` merges this in unfiltered, `Command#unbundled_env` carries `BASH_ENV` through to `PTY.spawn`, and non-interactive `bash` sources the named file before running the configured `shipit.yml` step (e.g., `cap $ENVIRONMENT deploy`), executing attacker code as the Shipit deploy user.

Why existing guards fail: `EnvironmentVariables#permit`/`NotPermitted` only guards the `env=` param path exercised by `Api::DeploysController`/`Api::TasksController`; it is never invoked on `@stack.env` or `deploy_spec.machine_env` inside `TaskCommands#env`. `ExplicitParameters` schemas for the webhook handlers validate shape (strings present), not content of label names. No model validation restricts label names or `machine.environment` keys.

### Impact Explanation
This yields arbitrary command execution on the Shipit deploy host under the credentials/permissions of the Shipit deploy process (which typically holds `GITHUB_TOKEN` and other deploy-time secrets in its environment, per `Commands#base_env`) — a Critical, RCE-class impact matching "RCE on the deploy host via `Command`/`PTY.spawn`". It is repeatable against any repository that enables review stacks with `allow_with_label` (or `allow_all`, since `machine_env` injection does not depend on labels) and does not sandbox/scan `shipit.yml`; the blast radius is scoped to that repository's Shipit host but affects the shared deploy host and any secrets present in its environment (e.g., `GITHUB_TOKEN`), and can be repeated by any fork PR author.

### Likelihood Explanation
Preconditions: the target repository must have review stacks enabled with `provisioning_behavior` of `allow_with_label` (label vector) or any behavior (via `machine_env` vector, since that requires no label). Attacker cost is trivial — opening a PR, adding a label they control, and/or editing `shipit.yml` in their own fork, all standard unprivileged GitHub actions. No secrets or elevated GitHub/Shipit permissions are required. This is fully repeatable and requires no race condition or timing.

### Recommendation
- In `TaskCommands#env` (and any place `@stack.env`/`deploy_spec.machine_env` are merged into a `Command`), pass the result through `EnvironmentVariables#permit` against an explicit, curated whitelist (e.g., only variables declared via `deploy_variables`/`rollback_variables`/`task variables`), rejecting any unlisted key.
- In `ReviewStack#env`, stop deriving raw environment variable names from PR label text; either whitelist a fixed set of boolean flags or prefix/namespace label-derived keys (e.g., `SHIPIT_LABEL_<name>`) and still run them through `permit`.
- In `DeploySpec#machine_env`, reject or filter dangerous key names (`BASH_ENV`, `ENV`, `IFS`, `LD_PRELOAD`, `PATH`, etc.) before merging, or restrict `machine.environment` keys to an explicit allowlist independent of the PR-controlled `shipit.yml`.
- Defense in depth: have `Command#unbundled_env`/`BASE_ENV` strip a denylist of shell-influencing variables (`BASH_ENV`, `ENV`, `IFS`, `LD_PRELOAD`, `LD_LIBRARY_PATH`) from any caller-supplied `@env` before spawning.

### Proof of Concept
```ruby
# test/unit/task_commands_bash_env_test.rb
require 'test_helper'

module Shipit
  class TaskCommandsBashEnvTest < ActiveSupport::TestCase
    test "machine_env from an untrusted shipit.yml is not filtered before reaching Command#env" do
      stack = shipit_stacks(:review_stack) # configured with provisioning_behavior allow_with_label
      deploy = stack.deploys.build(until_commit: stack.commits.last)
      commands = TaskCommands.new(deploy)

      # Simulate a fork PR's shipit.yml containing:
      # machine:
      #   environment:
      #     BASH_ENV: "/tmp/attacker_payload.sh"
      commands.deploy_spec.stubs(:machine_env).returns({ "BASH_ENV" => "/tmp/attacker_payload.sh" })

      env = commands.env

      # BROKEN BINDING: env reaching PTY.spawn should equal
      # EnvironmentVariables.with(deploy_spec.machine_env).permit(whitelist) == {}
      # but instead:
      assert_equal "/tmp/attacker_payload.sh", env["BASH_ENV"]

      command = Command.new("cap $ENVIRONMENT deploy", env: env, chdir: deploy.working_directory)
      assert_equal "/tmp/attacker_payload.sh", command.unbundled_env["BASH_ENV"]
    end

    test "PR label names become unfiltered env keys on a ReviewStack" do
      stack = shipit_stacks(:review_stack)
      pull_request = stack.create_pull_request!(number: 1, github_id: 1)
      pull_request.update!(labels: ["BASH_ENV"])

      env = stack.env
      assert_equal "true", env["BASH_ENV"]
    end
  end
end
```
Both assertions demonstrate that a fork-controllable key (`BASH_ENV`) reaches the environment hash passed to `Command`/`PTY.spawn` without going through `EnvironmentVariables#permit`, violating the stated invariant.

### Citations

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

**File:** app/models/shipit/deploy_spec.rb (L69-71)
```ruby
    def machine_env
      config('machine', 'environment') || {}
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

**File:** app/models/shipit/deploy_spec/file_system.rb (L93-142)
```ruby
      def config(*)
        @config ||= load_config
        super
      end

      def load_config
        return if config_file_path.nil?

        if !Shipit.respect_bare_shipit_file? && config_file_path.to_s.end_with?(*bare_shipit_filenames)
          return { 'deploy' => { 'pre' => [shipit_not_obeying_bare_file_echo_command, 'exit 1'] } }
        end

        config_obj = read_config(config_file_path)
        build_config(config_file_path, config_obj)
      end

      YAML_EXTENSIONS = ["yml", "yaml"].freeze

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

**File:** lib/shipit/command.rb (L31-34)
```ruby
    def initialize(*args, chdir:, default_timeout: Shipit.default_inactivity_timeout, env: {})
      @args, options = parse_arguments(args)
      @timeout = parse_timeout(options['timeout'] || options[:timeout]) || default_timeout
      @env = env.transform_values { |v| v&.to_s }
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

**File:** app/models/shipit/task_definition.rb (L63-65)
```ruby
    def filter_envs(env)
      EnvironmentVariables.with(env).permit(variables)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L60-78)
```ruby
          def respond_to_pull_request_opened?
            params.action == "opened" &&
              provision?
          end

          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end

          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
          end

          def pull_request_label_names
            Array.new(pull_request["labels"]).map { |label| label["name"] }
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-97)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end

          def archive?
            (repository.provisioning_behavior_allow_with_label? && !pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && pull_request_has_provisioning_label?)
          end

          def unarchive?
            (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end

          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
          end
```
