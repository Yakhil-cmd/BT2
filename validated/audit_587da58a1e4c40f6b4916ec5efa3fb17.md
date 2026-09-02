### Title
Attacker-controlled PR label name becomes a dynamic-loader environment variable (`LD_PRELOAD`) injected into the deploy child process - (File: app/models/shipit/review_stack.rb)

### Summary
`Shipit::ReviewStack#env` merges every PR label name (upcased) directly as an environment-variable key with value `"true"` into the environment ultimately passed to `PTY.spawn`, with no denylist. An attacker who can label their own PR (`labeled_active_stack?`) can set the label `ld_preload`, causing `LD_PRELOAD=true` to be injected into the `bundle exec cap ... deploy` child process on the Shipit deploy host.

### Finding Description
The claimed binding is: `keys(ReviewStack#env additions) ∩ {LD_PRELOAD, LD_LIBRARY_PATH, ...loader-honoured vars} = ∅`. This binding does **not** hold.

`ReviewStack#env` [1](#0-0)  takes `pull_request.labels`, upcases each label name, and merges `{label.upcase => "true"}` into the stack's env with **no filtering or allow/deny list** of key names.

Labels are attacker-controlled: `LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` verbatim from the webhook payload whenever `labeled_active_stack?` is true (action `"labeled"`, stack present, not archived) [2](#0-1) . Since PR authors can label their own PRs via the GitHub UI/API, this is fully attacker-reachable with no privilege beyond opening/owning a PR.

The env then flows: `DeployCommands#env` calls `super` (i.e. `TaskCommands#env`), which merges `@stack.env` (the `ReviewStack#env` override for review stacks) into the task env [3](#0-2) , then `DeployCommands#env` adds a few more keys on top [4](#0-3) . This merged hash is passed into `Command.new(..., env:)` and used by `Command#unbundled_env`, which layers `@env` (attacker keys included) over `BASE_ENV` and `PATH`, and this exact hash is handed to `PTY.spawn` to exec the deploy command [5](#0-4) .

No guard intercepts this: `ExplicitParameters` schema for the webhook only validates label `name` is a `String` (no content restriction) [6](#0-5) ; there is no `EnvironmentVariables#permit`-style filtering applied to `ReviewStack#env`'s label-derived keys; and `labeled_active_stack?` only checks `stack.present? && !stack.archived?`, not label content [7](#0-6) .

Exploit flow: attacker opens (or already has) a PR against a repository with review stacks enabled, adds label `ld_preload` via GitHub UI/API. GitHub sends a `labeled` webhook → `LabelCapturingHandler` persists `["ld_preload"]` on `stack.pull_request` → on next deploy of that review stack, `ReviewStack#env` injects `"LD_PRELOAD" => "true"` → this reaches `PTY.spawn`'s environment for the `bundle exec cap $ENVIRONMENT deploy` child process, where the dynamic loader (`ld.so`) attempts to preload `"true"` as a shared object (typically causing a crash, or exploitable if a file/library named appropriately can be placed on a discoverable path within the deploy working directory, e.g. combined with `LD_LIBRARY_PATH`-style label injection alongside `PATH`-adjacent artifacts from the checked-out PR branch).

### Impact Explanation
This is an RCE/process-hijack primitive on the deploy host reachable purely through an unprivileged, unauthenticated-to-Shipit action (labeling one's own PR). At minimum it reliably crashes/breaks the deploy subprocess (denial of the deploy for that stack); at worst, combined with attacker control over the checked-out repository contents (the PR branch itself, cloned into `@task.working_directory`), the attacker can place a malicious shared object at a predictable path and use `LD_PRELOAD`/`LD_LIBRARY_PATH` label injection to have the dynamic loader load attacker-supplied native code into the `cap deploy` process on the Shipit deploy host — full RCE. This matches the "Critical – RCE on the deploy host via `Command`/`PTY.spawn`" category. Blast radius is scoped to the repository/stack whose PR is labeled, but is repeatable by any PR author against any repository configured with review stacks.

### Likelihood Explanation
Preconditions are low-cost and entirely attacker-controlled: the repository must have review stacks enabled (a documented, common Shipit feature), the attacker must own/control a PR against it, and the stack must not be archived. Adding a label to one's own PR requires no special GitHub permission beyond having "triage" or being the PR author with label permission on many repos (or, if labels are restricted, an attacker could still get the effect via any other GitHub actor who can label PRs on a repo they don't own, which is a separate but related risk). No Shipit secrets, tokens, or sessions are needed — this is purely a GitHub webhook triggered by an ordinary GitHub action. The exploit is trivially repeatable per deploy trigger.

### Recommendation
In `Shipit::ReviewStack#env` (app/models/shipit/review_stack.rb), enforce a strict allow-list or a mandatory prefix (e.g. only labels matching `/\AREVIEW_[A-Z0-9_]+\z/` or requiring a distinct namespace) before merging label-derived keys into the environment, and explicitly reject/strip well-known loader-honoured variable names (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, etc.) and other dangerous names (`PATH`, `BUNDLE_*`, `RUBYOPT`, `IFS`, etc.) regardless of prefix.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (conceptual addition)
test "#env strips dynamic-loader env vars derived from PR labels" do
  stack = shipit_review_stacks(:review_stack) # existing fixture review stack
  stack.pull_request.update!(labels: ['ld_preload', 'ld_library_path'])

  env = stack.env

  refute_includes env.keys, 'LD_PRELOAD'
  refute_includes env.keys, 'LD_LIBRARY_PATH'
end

# test/lib/shipit/deploy_commands_test.rb (conceptual addition)
test "DeployCommands#env never exposes LD_PRELOAD sourced from PR labels" do
  deploy = shipit_deploys(:review_stack_deploy)
  deploy.stack.pull_request.update!(labels: ['ld_preload'])

  env = Shipit::DeployCommands.new(deploy).env

  refute_includes env.keys, 'LD_PRELOAD',
    "attacker-controlled PR label must not become LD_PRELOAD in the deploy child process env"
end
```
Currently, both assertions fail: `env['LD_PRELOAD']` equals `"true"`, demonstrating the broken binding.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L29-31)
```ruby
              requires :labels, Array do
                requires :name, String
              end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L62-102)
```ruby
          def labeled_active_stack?
            labeled? && stack.present? && !stack.archived?
          end

          def unlabeled_active_stack?
            unlabeled? && stack.present? && !stack.archived?
          end

          def reopened_active_stack?
            reopened? && stack.present? && !stack.archived?
          end

          def opened?
            action == "opened"
          end

          def labeled?
            action == "labeled"
          end

          def unlabeled?
            action == "unlabeled"
          end

          def reopened?
            action == "reopened"
          end

          def action
            params.action
          end

          def pull_request
            params.pull_request
          end

          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
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
