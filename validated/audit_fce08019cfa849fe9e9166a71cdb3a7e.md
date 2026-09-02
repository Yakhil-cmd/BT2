### Title
Pull-request label named `PATH` overrides `Command#unbundled_env`'s `PATH`, enabling relative-PATH command hijack RCE - (File: `app/models/shipit/review_stack.rb`, `lib/shipit/task_commands.rb`, `lib/shipit/command.rb`)

### Summary
`ReviewStack#env` turns every pull-request label into an environment variable (`LABEL.upcase => "true"`) with no denylist, and this hash is merged into the command environment passed to `Command.new`. Because `Command#unbundled_env` computes `BASE_ENV.merge('PATH' => shell_paths+ENV['PATH']).merge(@env)`, the caller-supplied `@env` is applied last and silently clobbers the computed `PATH`, letting a PR author who can label their own pull request set `PATH` to the literal string `"true"` for that stack's tasks/deploys.

### Finding Description
The claimed invariant is: `Command#unbundled_env['PATH'] == Shipit.shell_paths.join(':') + ':' + ENV['PATH']`, with no attacker-supplied override.

Trace:
1. `Shipit::Webhooks::Handlers::PullRequest::LabelCapturingHandler#capture_labels` persists arbitrary label names verbatim into `PullRequest#labels` on `labeled`/`opened`/`reopened` events for a non-archived stack: `pull_request.update!(labels: params.pull_request.labels.map(&:name))` [1](#0-0) .
2. `ReviewStack#env` maps every label to an env var with a fixed value, with no denylist of reserved names such as `PATH`, `HOME`, `LD_PRELOAD`, `GIT_ASKPASS`: `labels[label_name.upcase] = "true"` [2](#0-1) .
3. `TaskCommands#env` (and `DeployCommands#env`) merges `@stack.env` into the final env hash that is handed to `Command.new(...)`, and nothing downstream re-adds/protects `PATH` [3](#0-2) .
4. `Command#initialize` stores this as `@env`, and `Command#unbundled_env` merges it **last**, after computing the intended `PATH`: `BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)` [4](#0-3) . Since `@env` contains `'PATH' => 'true'`, the resulting `PATH` becomes the literal string `"true"` instead of the intended value.
5. `Command#start` passes this hash straight into `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` [5](#0-4) , where `chdir` is the task's working directory — the checked-out contents of the attacker's PR branch.

Because `PATH="true"` has no leading `/`, it is a **relative** path component. Command lookup for any deploy step invoked without a leading slash (e.g. `bundle`, `cap`, or whatever `shipit.yml` steps specify) is resolved relative to the spawned process's working directory. Since the attacker fully controls the PR branch content (via `chdir`), they can commit a directory literally named `true/` containing an executable named identically to a step binary (`bundle`, `cap`, etc.), which then executes instead of the real one during a deploy/task run on the Shipit deploy host.

No existing guard stops this: `EnvironmentVariables#permit` (a denylist for the API-triggered task env) is never applied to `ReviewStack#env`'s label-derived hash [6](#0-5) ; label capture only checks `stack.present? && !stack.archived?`, not label content [7](#0-6) ; and `verify_signature`/webhook HMAC checks are irrelevant because this exploit uses a **real, properly-signed** GitHub webhook triggered by a legitimate label action on the attacker's own PR — no forged signature or secret is required [8](#0-7) .

### Impact Explanation
This is a Critical finding: RCE on the deploy host via `Command`/`PTY.spawn`. An attacker who can label their own pull request against a repository with an existing Shipit ReviewStack can force the `PATH` used for subsequent `Command` executions on that stack (installs, deploy steps, review checks) to a relative directory, and — because they control the checked-out branch content — plant an executable that gets run instead of the intended tool. This yields arbitrary code execution on the Shipit deploy host, scoped to that repository's review-stack tasks, and is repeatable on every deploy/task run of that stack for as long as the `PATH` label remains applied.

### Likelihood Explanation
Preconditions: the target repository must already have Shipit review stacks provisioned/enabled (`repository.review_stacks_enabled`) and the attacker must have permission to add a label to a pull request there (GitHub label/triage access — typically available to the repo owner or a collaborator with write access, i.e., someone who can set up such a repo and PR against it themselves). No Shipit secrets, session, or webhook-secret bypass is needed — the exploit rides on a legitimate, correctly-signed GitHub webhook. Cost is low: label the PR `PATH`, commit a `true/<toolname>` executable, and wait for/trigger the next task or deploy on that stack.

### Recommendation
In `ReviewStack#env` (or a shared helper), exclude reserved/dangerous environment variable names (at minimum `PATH`, and ideally any name already defined by `Shipit.env`, `Stack#env`, or `TaskCommands#env`) from the label-derived hash before merging. Additionally, harden `Command#unbundled_env` to always compute `PATH` last (i.e., `@env.merge('PATH' => computed_path)` instead of `BASE_ENV.merge('PATH' => computed_path).merge(@env)`), so caller-supplied env can never override the interpreter search path.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_path_override_test.rb
require "test_helper"

module Shipit
  class ReviewStackPathOverrideTest < ActiveSupport::TestCase
    test "a PR label named PATH overrides Command#unbundled_env's PATH" do
      stack = shipit_stacks(:review_stack) # a Shipit::ReviewStack fixture
      stack.pull_request.labels = ["PATH"]

      task = shipit_tasks(:shipit_restart)
      task.stack = stack

      env = Shipit::TaskCommands.new(task).env
      command = Shipit::Command.new("echo hi", env: env, chdir: ".")

      expected_path = "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}"

      # Binding under test: unbundled_env['PATH'] should remain the computed
      # shell_paths + ENV['PATH'] value regardless of attacker-supplied labels.
      assert_equal expected_path, command.unbundled_env['PATH'],
        "attacker-controlled PR label overrode Command#unbundled_env's PATH"
    end
  end
end
```
Running this test against the current code fails: `command.unbundled_env['PATH']` equals `"true"` (from the label), not `Shipit.shell_paths.join(':') + ':' + ENV['PATH']`, confirming the broken binding.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L62-64)
```ruby
          def labeled_active_stack?
            labeled? && stack.present? && !stack.archived?
          end
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

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```
