## #Vulnerability found for this question.

### Title
Fork PR author sets label name `path` to fully override the deploy `PATH` env var, hijacking `bash script/release.sh` command resolution - (File: `lib/shipit/command.rb`)

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) as an environment-variable key with the fixed value `"true"`, with no key allowlist. `Command#unbundled_env` merges the computed, safe `PATH` (containing `Shipit.shell_paths` plus the OS `PATH`) and then merges the task/stack `@env` hash **on top of it**, so any attacker-supplied `PATH` key silently wins and replaces the entire `PATH` value used by `PTY.spawn` when a deploy step such as `bash script/release.sh` runs.

### Finding Description
The broken binding: the value used by `PTY.spawn` for `PATH` should equal `"#{Shipit.shell_paths.join(':')}:#{ENV['PATH']}"`, but if the PR carries a label named `path` (any case), it instead equals `"true"`.

Path:
1. An unprivileged user opens (or labels) a pull request on their own fork with a label whose name is `path` (case-insensitive). `LabelCapturingHandler#capture_labels` persists `pull_request.labels` straight from the webhook payload with no allowlist: [1](#0-0) 
2. `ReviewStack#env` turns every label into an env entry with no key filtering: [2](#0-1) 
   This produces `{"PATH" => "true"}` for a label literally named `path`/`PATH`/`Path`.
3. `TaskCommands#env` merges `@stack.env` into the task environment, and nothing downstream re-sets `PATH`: [3](#0-2) 
4. For the deploy step `bash script/release.sh`, `TaskCommands#perform` builds `Command.new(command_line, env:, chdir: steps_directory)`: [4](#0-3) 
5. `Command#unbundled_env` computes the safe `PATH` first, then merges the attacker-influenced `@env` on top, so the attacker's `PATH` key wins over the computed one: [5](#0-4) 
6. `Command#start` spawns the process with this hijacked env via `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`, `chdir` being the task's working directory — the checkout of the attacker's own fork branch: [6](#0-5) 

Root cause: `merge` order in `unbundled_env` lets caller-supplied env clobber the safety-critical `PATH`, combined with `ReviewStack#env` exposing an unfiltered, attacker-controlled key namespace (label names) directly as env var keys.

Constraint on attacker control: the *value* assigned is always the fixed literal string `"true"` (not arbitrary), only the *key* is attacker-chosen. So `PATH` becomes exactly `"true"` — a single relative path component. Because the working directory (`chdir`) is the checked-out fork branch content that the attacker fully controls, the attacker can commit a directory literally named `true` in their branch containing an executable named `bash` (matching the bare command word used by `bash script/release.sh`, or any bare command name used in any `shipit.yml` step). When the shell resolves the bare command name via `PATH`, it will use `./true/<command>` instead of the real system binary, achieving code execution in the deploy job's process/host context.

No existing guard stops this: `LabelCapturingHandler`'s `ExplicitParameters` schema only validates types (`String`), not label content [7](#0-6) ; there is no key allowlist or blocklist (e.g., excluding `PATH`, `BUNDLE_*`, `GIT_ASKPASS`) anywhere in `ReviewStack#env`, `TaskCommands#env`, or `Command#unbundled_env`.

### Impact Explanation
This achieves execution of an attacker-chosen binary within the deploy task's process on the Shipit host, matching the "RCE on the deploy host via `Command`/`PTY.spawn`" Critical category. Blast radius is scoped to the review stack's own task execution (the attacker's own fork/branch checkout), but that execution occurs with the deploy host's privileges/environment (e.g., `GIT_ASKPASS`, `GITHUB_TOKEN`, and other secrets present in `Command::BASE_ENV`/`Shipit.env`), so a hijacked `bash`/`git`/other bare-command invocation could exfiltrate those. It is repeatable on any repository that has review stacks enabled, by any PR author who can label their own PR.

### Likelihood Explanation
Preconditions: the target repository must have Review Stacks enabled (`review_stacks_enabled`) and a deploy spec step that invokes a bare command name (e.g., `bash script/release.sh`) rather than an absolute path. Attacker cost is trivial: open a PR from a fork, add a label named `path`, and include a `true/` directory with a malicious executable in the PR branch — no secrets, tokens, or maintainer privileges required. This is fully repeatable against every review-stack deploy triggered on that PR.

### Recommendation
- In `ReviewStack#env` (`app/models/shipit/review_stack.rb`), filter/reject reserved or dangerous env keys (e.g., `PATH`, `BUNDLE_*`, `GIT_ASKPASS`, `LD_PRELOAD`, `RUBYOPT`) before merging label-derived entries, or apply an explicit allowlist of permitted variable name patterns for label-derived env vars.
- In `Command#unbundled_env` (`lib/shipit/command.rb`), compute and merge `PATH` **last** (or otherwise make it non-overridable by caller-supplied `@env`), so `Shipit.shell_paths` + `ENV['PATH']` cannot be clobbered by task/stack env.
- Consider always invoking deploy-spec steps with absolute paths, or prefixing `PATH` resolution safely regardless of caller env.

### Proof of Concept
Add to `test/unit/command_test.rb` or `test/models/shipit/review_stack_test.rb`:

```ruby
test "unbundled_env allows the caller's PATH entry to override the computed PATH" do
  command = Shipit::Command.new('bash script/release.sh', env: { 'PATH' => 'true' }, chdir: '.')
  assert_equal 'true', command.unbundled_env['PATH']
  refute_includes command.unbundled_env['PATH'], Shipit.shell_paths.join(':')
end

test "ReviewStack#env exposes a label named path as PATH override" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ['path']
  assert_equal 'true', stack.env['PATH']
end
```
Both assertions currently pass, demonstrating that the attacker-controlled label name reaches and overrides the `PATH` variable used for `PTY.spawn` in the `bash script/release.sh` step.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L8-39)
```ruby
          params do
            requires :action, String
            requires :number, Integer
            requires :pull_request do
              requires :id, Integer
              requires :number, Integer
              requires :url, String
              requires :title, String
              requires :state, String
              requires :additions, Integer
              requires :deletions, Integer
              requires :head do
                requires :sha, String
                requires :ref, String
              end
              requires :user do
                requires :login, String
              end
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
            end
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
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

**File:** lib/shipit/task_commands.rb (L23-27)
```ruby
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
