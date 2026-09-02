Based on the analysis, this design is fundamentally about a feature, not a vulnerability specific to `PYTHONSTARTUP`.

### Analysis

The claimed exploit path requires the attacker to control the fork branch's `shipit.yml`, which is fetched and interpreted by `DeploySpec::FileSystem` when the review-stack task's steps execute via `TaskCommands#steps` and `TaskCommands#env`. [1](#0-0) [2](#0-1) 

Critically, the same `shipit.yml` that provides `machine.environment` also provides the literal `tasks.<name>.steps` shell command lines that `Command.new(command_line, ...)` executes via `PTY.spawn` in `Command#start`. [3](#0-2) 

This means the attacker already has direct, unmediated arbitrary shell command execution as soon as their fork's `shipit.yml`-defined `tasks.<name>.steps` run — injecting `PYTHONSTARTUP` to get a python file executed offers no privilege escalation beyond what `steps: ["any shell command"]` already grants. The premise that "the step inherits no fork-controllable key" is not a meaningful security boundary, since the step's *entire command line* is fork-controllable already.

Moreover, this capability is gated behind an explicit opt-in by the repository owner: `provisioning_behavior=allow_with_label` combined with a human applying the provisioning label to the PR via `LabeledHandler#archive?`/`unarchive?`, which check `repository.provisioning_behavior_allow_with_label?` and `pull_request_has_provisioning_label?`. [4](#0-3) [5](#0-4) 

Running arbitrary attacker-supplied build/deploy/task steps for review stacks provisioned from a fork PR (once labeled) is the documented, intended behavior of the review-stack feature — it is not a bug in `ReviewStack`, `DeploySpec`, or `Command`. The label-gating on GitHub normally requires `write` access (only maintainers/collaborators can add labels to a PR from a fork on GitHub); an "unprivileged" external contributor without label permissions cannot self-label to trigger this. The scenario as described does not identify a divergent binding — both "attacker controls shell command steps" and "attacker controls env vars merged into those steps" are the same trust boundary, already crossed by design once a maintainer opts into `allow_with_label` and applies the label.

#No vulnerability found for this question.

### Citations

**File:** app/models/shipit/deploy_spec.rb (L69-71)
```ruby
    def machine_env
      config('machine', 'environment') || {}
    end
```

**File:** lib/shipit/task_commands.rb (L23-48)
```ruby
    def perform
      steps.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
    end

    def steps
      @task.definition.steps
    end

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

**File:** app/models/shipit/repository.rb (L50-51)
```ruby
    PROVISIONING_BEHAVIORS = %w[allow_all allow_with_label prevent_with_label].freeze
    enum :provisioning_behavior, PROVISIONING_BEHAVIORS.zip(PROVISIONING_BEHAVIORS).to_h, prefix: :provisioning_behavior
```
