### Title
Fork PR label names uppercase into unfiltered `bundle install` environment, allowing `BUNDLE_GEMFILE` override → RCE on deploy host - (File: `app/models/shipit/review_stack.rb`, `lib/shipit/task_commands.rb`, `lib/shipit/command.rb`)

### Summary
`ReviewStack#env` merges every PR label name (uppercased) directly into the task's environment hash with no allowlist, and that hash flows unfiltered into `Command#unbundled_env`, which is passed straight to `PTY.spawn` for the `bundle install` step. A PR author who can label their own PR can set the reserved `BUNDLE_GEMFILE` environment variable, causing `bundle` to load an attacker-controlled file from the checked-out fork branch as the Gemfile, running arbitrary Ruby on the deploy host.

### Finding Description
The broken binding: `env["BUNDLE_GEMFILE"]` should always equal a value derived from `Shipit`/repo-configured deploy spec (or be absent), never a value derived from `pull_request.labels`. Instead:

- `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` into the stack `env` with no key allowlist: [1](#0-0) 
- `LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` straight from the webhook payload with only a string-type schema check (no character restriction): [2](#0-1) 
- `TaskCommands#env` merges `@stack.env` (which is `ReviewStack#env` for a PR-triggered task) directly into the `Command` env with no `EnvironmentVariables#permit` filtering — that filtering (`filter_deploy_envs`/`filter_envs`) is only applied to the user-supplied API deploy `env` param, not to `@stack.env`: [3](#0-2) 
- `Command#unbundled_env` merges `@env` unfiltered onto `BASE_ENV`, and `Command#start` passes it straight to `PTY.spawn`: [4](#0-3) 
- The `bundle install` step itself is auto-discovered and run via `install_dependencies`, which uses this same unfiltered `env`: [5](#0-4) [6](#0-5) 

Exploit flow: attacker opens/labels a PR with a label literally named `bundle_gemfile` (case-insensitive; uppercased to `BUNDLE_GEMFILE`), and commits a file named `true` in the PR branch root containing malicious Ruby (a fake Gemfile). `LabelCapturingHandler` persists this label via a normal, valid webhook (`opened`/`labeled`/`reopened`). When the review stack task runs `install_dependencies` (auto-discovered `bundle install`), `ENV['BUNDLE_GEMFILE']="true"` is inherited by the `bundle install` subprocess; Bundler resolves this relative to the working directory (the checked-out fork commit) and evaluates the attacker's file as the Gemfile, executing arbitrary Ruby on the Shipit host.

Existing guards do not stop this: `EnvironmentVariables#permit`/`sanitize_env_vars` is a real allowlist mechanism, but it's applied only to the explicit "deploy variables" configured in `shipit.yml`/passed by API callers (`app/models/shipit/deploy_spec.rb` `filter_deploy_envs`/`filter_rollback_envs`, `app/models/shipit/task_definition.rb#filter_envs`) — not to the label-derived `ReviewStack#env` merged in `TaskCommands#env`. There is no key-name restriction anywhere in the label-capture path.

### Impact Explanation
This is Remote Code Execution on the Shipit deploy host: an unprivileged fork PR author causes an attacker-chosen Ruby payload to execute inside the `bundle install` subprocess spawned via `Command#start`/`PTY.spawn`. Since this executes with the full privileges of the deploy worker process (which also has `GITHUB_TOKEN` and other deploy-time secrets injected via `base_env`/`Shipit.env`, per `lib/shipit/commands.rb`), the attacker can exfiltrate credentials, tamper with the deploy host, or pivot to other stacks/repositories managed by the same Shipit instance. This matches the Critical RCE impact category and is repeatable for any repository that has review stacks enabled and uses Bundler auto-discovery for its deploy steps.

### Likelihood Explanation
Preconditions: the target repository must have review stacks enabled (`provisioning_behavior` allowing PR-triggered stacks) and use the Bundler-based dependency discovery (a Gemfile present, no `dependencies.override` in `shipit.yml`). Given the threat model's stated rule that a PR author labeling their own PR is in scope, the attacker cost is trivial — open a PR, add one label, commit one file — and it is fully repeatable/automatable against any repository matching the preconditions.

### Recommendation
Do not merge PR-label-derived keys into the raw process environment unfiltered. Either:
- Restrict `ReviewStack#env` label-derived keys to a safe, explicit prefix (e.g. only allow keys matching a `SHIPIT_LABEL_...` pattern) before merging, or
- Route `@stack.env`/label-derived env through `EnvironmentVariables#permit` with an explicit allowlist before it's merged in `TaskCommands#env`, and
- Additionally block/strip well-known dangerous variable names (`BUNDLE_GEMFILE`, `RUBYOPT`, `LD_PRELOAD`, `BUNDLE_*`, etc.) from any environment merged into `Command`.

### Proof of Concept
minitest plan (in `test/lib/shipit/task_commands_test.rb` style, mirrors the existing "`#env` includes a ReviewStack's pull request labels" test):

```ruby
test "#env allows BUNDLE_GEMFILE to be injected via a PR label and reaches the spawned process" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["bundle_gemfile"]
  task = shipit_tasks(:shipit_restart)
  task.stack = stack

  env = Shipit::TaskCommands.new(task).env
  assert_equal "true", env["BUNDLE_GEMFILE"]

  command = Shipit::Command.new("bundle install", env:, chdir: ".")
  assert_equal "true", command.unbundled_env["BUNDLE_GEMFILE"]
end
```
Both sides of the equality `env["BUNDLE_GEMFILE"] == nil-or-allowlisted-value` diverge: the attacker-controlled label produces `"true"` and it is not filtered before reaching `Command#unbundled_env`, confirming the finding.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** lib/shipit/task_commands.rb (L17-21)
```ruby
    def install_dependencies
      deploy_spec.dependencies_steps!.map do |command_line|
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

**File:** app/models/shipit/deploy_spec/bundler_discovery.rb (L12-37)
```ruby
      def discover_bundler
        bundle_install if bundler?
      end

      def bundle_exec(command)
        if bundler? && dependencies_steps.include?(remove_ruby_version_from_gemfile)
          "bundle exec #{command}"
        else
          command
        end
      end

      def discover_machine_env
        super.merge('BUNDLE_PATH' => bundle_path.to_s)
      end

      def bundle_install
        install_command = %(bundle install --jobs 4 --retry 2)
        [
          remove_ruby_version_from_gemfile,
          (bundle_config_frozen if frozen_mode?),
          bundle_config_path,
          bundle_without_groups,
          install_command
        ].compact
      end
```
