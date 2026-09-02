### Title
Unsanitized GitHub label names flow through `LabelCapturingHandler#capture_labels` into `Command#unbundled_env`, letting a label named after a privileged interpreter variable override `PATH`/`GIT_ASKPASS`/`BUNDLE_PATH`/`RUBYOPT`/`LD_PRELOAD`/`GIT_SSH_COMMAND` on `PTY.spawn` - (File: app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb)

### Summary
`LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` verbatim into `Shipit::PullRequest#labels` with no charset/length constraint beyond `requires :name, String`. `Shipit::PullRequest` has no validation on `labels` and `ReviewStack#env` upcases every label name and merges it as `"true"` into the stack's environment, which is then merged last (and therefore wins) into the process environment handed to `PTY.spawn` in `Shipit::Command#unbundled_env`.

### Finding Description
The broken binding: for all `label_name` in `pull_request.labels`, `label_name.upcase` must never equal a name in `{PATH, GIT_ASKPASS, BUNDLE_PATH, RUBYOPT, LD_PRELOAD, GIT_SSH_COMMAND}`. No such constraint exists anywhere on the write path.

- `LabelCapturingHandler#capture_labels` writes `pull_request.update!(labels: params.pull_request.labels.map(&:name))` with the only gate being the `ExplicitParameters` schema `requires :name, String` (any string, any length, any charset) [1](#0-0) .
- `Shipit::PullRequest` has `serialize :labels` with no `validates` call constraining content [2](#0-1) .
- `Shipit::ReviewStack#env` merges `labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` on top of the base stack env [3](#0-2) .
- `StackCommands#env` / `TaskCommands#env` merge `@stack.env` into the command environment, confirmed by existing tests asserting label-derived keys land in `env` (e.g. `WIP`/`BUG`) [4](#0-3) [5](#0-4) .
- `Shipit::Command#unbundled_env` builds the final env as `BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)` — `@env` (which contains the label-derived keys) is merged **last**, so it overrides `PATH`, and any other key of the same name, right before `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` [6](#0-5) [7](#0-6) .

No existing guard intercepts this: `EnvironmentVariables#permit` is only used for whitelisting explicit `deploy_spec` variables, not for the label-derived hash [8](#0-7) ; the webhook signature check only authenticates that GitHub sent the payload, it does not sanitize label content. A label named `ld_preload`, `path`, `git_ssh_command`, `bundle_path`, `git_askpass`, or `rubyopt` on an existing, non-archived review-stack pull request passes straight through `capture_labels` into `PullRequest#labels`, and from there into every subsequent `Command` spawned for that stack (fetch, deploy, rollback, custom tasks), each time silently overriding the corresponding interpreter-honoured environment variable with the literal string `"true"`.

### Impact Explanation
Overriding `PATH` with `"true"` breaks command resolution predictably; more importantly, overriding `GIT_ASKPASS`, `GIT_SSH_COMMAND`, `RUBYOPT`, or `LD_PRELOAD` with attacker-influenced values corrupts the environment that `git`/`bundle`/Ruby subprocess invocations rely on for every task run against that stack (fetch, deploy, rollback, provisioning). In this codebase the value is hardcoded to `"true"` (not attacker-supplied content), so full arbitrary-value injection (e.g. pointing `GIT_ASKPASS` at an attacker script path) is not achieved via this specific handler — the label's *name* is fully attacker-controlled, but its resulting *value* is always `"true"`. That still causes reliable environment corruption/tool misbehavior for the affected stack (denial of correct execution / undefined command behavior), but does not on its own demonstrate secret exfiltration or RCE, since `"true"` is not a valid `GIT_ASKPASS` executable path or `LD_PRELOAD` shared-object path that would grant control-flow hijack. The blast radius is scoped to the single stack/review-stack tied to the pull request whose labels were manipulated — there is no cross-tenant/cross-repository pivot shown, since `capture_labels` only updates `stack.pull_request` for the stack resolved from the webhook's own `repository.full_name`/`number`.

### Likelihood Explanation
Preconditions: the target repository must have Shipit review stacks enabled and provisioned for the PR, and the attacker must be able to attach/change labels on that PR (typically requires write/triage access to the repository, which is a step beyond merely opening a PR from a fork on someone else's repo). If the attacker owns the repository (their own fork configured as a Shipit-tracked repo), they already control `shipit.yml`/deploy commands on that same repo and thus already have an equivalent or greater level of control over what commands run for their own stack — reducing the incremental severity of this specific finding for the self-service case. The label-name charset itself is unconstrained and trivially reachable via a normal `labeled`/`unlabeled`/`opened`/`reopened` webhook.

### Recommendation
Constrain `Shipit::PullRequest#labels` (or `LabelCapturingHandler#capture_labels`) to reject/normalize label names whose upcased form collides with reserved/interpreter-sensitive environment variable names (`PATH`, `GIT_ASKPASS`, `GIT_SSH_COMMAND`, `BUNDLE_PATH`, `RUBYOPT`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, etc.), or prefix all label-derived environment keys in `ReviewStack#env` (e.g. `LABEL_<NAME>`) so they can never collide with a bare interpreter variable name.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (illustrative)
test "#env does not allow labels to override reserved env vars" do
  stack = shipit_stacks(:review_stack)
  payload = payload_parsed(:pull_request_labeled)
  payload["pull_request"]["labels"] = [{ "name" => "ld_preload" }]

  Shipit::Webhooks::Handlers::PullRequest::LabelCapturingHandler.new(payload).process

  assert_includes stack.reload.pull_request.labels, "ld_preload"
  refute_equal "true", Shipit::Command.new("true", chdir: Dir.tmpdir, env: {}).unbundled_env["LD_PRELOAD"]
  # currently FAILS: stack.env["LD_PRELOAD"] == "true", and Command#unbundled_env
  # merges @env last, so a Command built with env: stack.env would spawn with
  # LD_PRELOAD="true" instead of the host's LD_PRELOAD (unset/inherited).
end
``` [1](#0-0) [3](#0-2) [6](#0-5)

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/pull_request.rb (L1-15)
```ruby
# frozen_string_literal: true

module Shipit
  class PullRequest < Record
    include DeferredTouch

    belongs_to :stack
    belongs_to :user
    belongs_to :head, class_name: 'Shipit::Commit', optional: true

    has_many :pull_request_assignments
    has_many :assignees, class_name: :User, through: :pull_request_assignments, source: :user

    serialize :labels, coder: Shipit.serialized_column(:labels, type: Array)

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

**File:** test/lib/shipit/task_commands_test.rb (L6-16)
```ruby
  test "#env includes a ReviewStack's pull request labels" do
    stack = shipit_stacks(:review_stack)
    stack.pull_request.labels = ["wip", "bug"]
    task = shipit_tasks(:shipit_restart)
    task.stack = stack

    env = Shipit::TaskCommands.new(task).env

    assert_equal env["WIP"], "true"
    assert_equal env["BUG"], "true"
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

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
    end
```
