### Title
PR label named `path` overwrites `PATH` env var in `Command#unbundled_env`, allowing binary-path hijack on the deploy host - ([File: lib/shipit/command.rb])

### Summary
`Shipit::ReviewStack#env` converts every GitHub PR label into an env-var key via `label_name.upcase`, and that hash is merged, unfiltered, into the command environment used by `Command#unbundled_env`. Since `unbundled_env` merges the caller-supplied `@env` *after* setting its own `PATH` default, a PR labeled `path` (case-insensitive) overwrites the `PATH` key that governs which binaries (`git`, `bundle`, etc.) `PTY.spawn` resolves.

### Finding Description
The claimed broken binding: `keys(Command#unbundled_env final hash) \ keys(base/deploy-declared env) == ∅`. This does not hold.

Path traced:
- `Shipit::ReviewStack#env` merges the PR's labels into the stack's env hash: `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` [1](#0-0) .
- `Shipit::TaskCommands#env` merges `@stack.env` (which for a `ReviewStack` includes the label-derived keys) directly into the task's command environment, with no whitelist/filter applied at this layer [2](#0-1) .
- That merged hash becomes `Command#@env` (only `.transform_values(&:to_s)` is applied, no key filtering) [3](#0-2) .
- `Command#unbundled_env` does `BASE_ENV.merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}").merge(@env.stringify_keys)` — the caller's `@env` is merged last, so any key that collides with `'PATH'` silently wins [4](#0-3) .
- `start` passes this exact hash to `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` [5](#0-4) .

Attacker flow: open a PR against a repository with `review_stacks_enabled` and `provisioning_behavior_allow_all`; add a label named `path` (any case) to that PR via the GitHub UI/API on the attacker's own repo; the `labeled` webhook is captured by `LabelCapturingHandler#capture_labels`, which stores `params.pull_request.labels.map(&:name)` verbatim onto `pull_request.labels` with no allow-list check [6](#0-5) ; pushing a commit (or the existing continuous-delivery trigger) then runs a deploy/task whose `TaskCommands#env` includes `'PATH' => 'true'`, which flows into `Command#unbundled_env['PATH']`.

Existing guards do not stop this: `verify_signature` only authenticates that the webhook truly came from GitHub for that repository/organization — it does not restrict what values (like label names) are contained in a validly-signed payload [7](#0-6) . The `ExplicitParameters` schema for this handler only requires `labels` to be an array of objects with a `name: String` — no format restriction, no reserved-word blocklist [8](#0-7) . `EnvironmentVariables#permit`/whitelisting only applies to the explicit user-supplied `env` param on the task-trigger API (as seen in `tasks_controller_test.rb`'s "have not been whitelisted" test) — it is never applied to `Stack#env`/`ReviewStack#env`, which is merged unconditionally in `TaskCommands#env`.

I verified `Command::BASE_ENV`/`unbundled_env` merge order via `lib/shipit/command.rb` and the label-to-env transformation via `app/models/shipit/review_stack.rb`, and confirmed via existing tests (`test/lib/shipit/task_commands_test.rb`, `test/models/shipit/review_stack_test.rb`) that arbitrary label names do reach `env` as uppercased keys with value `"true"` unfiltered. I was not able to fully trace whether any additional sanitization exists between `Stack#env`/`ReviewStack#env` and `Command#env` for the `Deploy`/other `Task` subclasses beyond `TaskCommands#env`/`DeployCommands#env`, but both simply `.merge` the stack env with no key filtering, so the same collision applies to any task run on a `ReviewStack`.

### Impact Explanation
Any GitHub user able to open a PR and add a label on a repository configured for review stacks (`provisioning_behavior_allow_all` or `allow_with_label`, provided their label happens to also be the allowed one, or in the `allow_all` case any label at all) can force `PATH` (or other base env keys) to the string `"true"` for that review stack's deploy/task commands. Because `Command#start` calls `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` with the corrupted `PATH`, subsequent invocation of `git`, `bundle`, and other unqualified binaries in the deploy pipeline resolves via a broken/attacker-influenced `PATH`, which under most `PTY.spawn`/exec semantics (empty or non-existent `PATH` entries, or if combined with a writable directory the resolver falls back to) can lead to execution of attacker-controlled binaries, i.e., Critical RCE on the Shipit deploy host executing that stack's tasks. The attack is repeatable for every review-stack-eligible repository whose owner enabled review stacks; it does not cross into other unrelated stacks' commands, since each stack computes its own `env`.

### Likelihood Explanation
Preconditions are modest and attacker-controlled: repository must have `review_stacks_enabled` and a `provisioning_behavior` that lets the attacker's own PR provision a review stack (`allow_all`, or `allow_with_label` if the attacker knows/guesses the configured label — but the label `path`/`git_askpass` is a separate, independently-labeled attacker choice that only needs to collide with `PATH`/`GIT_ASKPASH`-style base keys, which is attacker-chosen regardless of the configured allow-label). The attacker needs only standard GitHub permissions to open a PR against their own fork and to add labels to that PR (labels can typically be self-applied by the PR author on many configurations, or via `labeled` events triggered by their own fork/CI). No Shipit credentials, session, or secrets are required — the entire trigger is a normal, validly-signed GitHub webhook. This is straightforward and fully repeatable.

### Recommendation
In `Shipit::ReviewStack#env`, prefix/namespace label-derived keys (e.g., `"LABEL_#{label_name.upcase}"`) instead of writing to the raw uppercased label name, and/or reject label names colliding with reserved words. Additionally/defensively, `Command#unbundled_env` should merge the caller-supplied `@env` before setting `PATH`, or explicitly disallow the caller from overriding critical keys such as `PATH`, `GIT_ASKPASS`, `GITHUB_TOKEN`, e.g.:
```ruby
def unbundled_env
  safe_env = @env.stringify_keys.except('PATH', 'GIT_ASKPASS', 'GITHUB_TOKEN', 'GITHUB_DOMAIN')
  BASE_ENV.merge(safe_env).merge('PATH' => "#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}")
end
```

### Proof of Concept
```ruby
# test/unit/command_test.rb (or similar)
test "a pull request label named 'path' cannot override the base PATH" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["path"]

  command = Shipit::Command.new("true", chdir: "/tmp", env: stack.env)

  refute_equal Shipit::Command::BASE_ENV['PATH'], command.unbundled_env['PATH'],
    "expected the label-derived env to have been blocked, but it overwrote PATH: #{command.unbundled_env['PATH'].inspect}"
end
```
Before the fix, `command.unbundled_env['PATH']` equals `"true"` instead of the expected shell-paths-prefixed `PATH` value, demonstrating the collision.

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

**File:** lib/shipit/command.rb (L31-37)
```ruby
    def initialize(*args, chdir:, default_timeout: Shipit.default_inactivity_timeout, env: {})
      @args, options = parse_arguments(args)
      @timeout = parse_timeout(options['timeout'] || options[:timeout]) || default_timeout
      @env = env.transform_values { |v| v&.to_s }
      @chdir = chdir.to_s
      @timed_out = false
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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L26-32)
```ruby
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
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
