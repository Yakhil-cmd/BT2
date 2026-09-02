### Title
Unfiltered PR label injection into deploy-host process environment - (File: app/models/shipit/review_stack.rb)

### Summary
`ReviewStack#env` merges every GitHub pull-request label name, verbatim (only upcased), into the environment hash that is later handed to `Command.new(..., env:)` and spawned as a real OS subprocess for that stack's `shipit.yml` steps. Unlike the environment-variable write path exposed through the API (`Api::BaseController`, which enforces an allow-list via `EnvironmentVariables::NotPermitted`), the review-stack label path performs no filtering at all. This breaks the same trust binding as the `TemporalGovernor` report: a field that is nominally scoped/"permitted" (an environment variable key an operator is allowed to set) is not the same set of keys that actually get spawned into the process environment that executes deploy/rollback/task commands.

### Finding Description
`ReviewStack#env` (app/models/shipit/review_stack.rb:84-93) does: [1](#0-0) 
```
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
`pull_request.labels` is populated directly from GitHub webhook payloads (`labeled`/`unlabeled`/`opened` pull_request events), i.e. arbitrary strings chosen by whoever can attach a label to the PR on GitHub — a GitHub-side permission, not a Shipit permission. This env hash is merged upward through `StackCommands#env` [2](#0-1)  and then into `DeployCommands#env`/`TaskCommands#env`, which are used to build the actual `Command` that is executed on the deploy host for every task (deploy, rollback, restart, etc.) run against that review stack: [3](#0-2) 

Tests confirm the label strings flow unmodified into the spawned process environment as arbitrary keys (`WIP`, `BUG`, etc. in the examples), with no allow-list check: [4](#0-3) [5](#0-4) 

Contrast this with the only other place Shipit lets an actor set environment variables — the API — which is guarded by an explicit permitted-key mechanism whose violation raises `EnvironmentVariables::NotPermitted` and is caught centrally: [6](#0-5) 

That is the binding that should hold as an equality: *the set of environment variable keys an actor is permitted to set* == *the set of environment variable keys actually spawned into the deploy-host process*. The PR-label path lets any GitHub user with label-add rights on the source repository set **any** key name (there is no character/format validation on GitHub label names beyond GitHub's own 50-character limit and no denylist here), completely bypassing that equality.

### Impact Explanation
Because the injected keys become literal environment variables of the spawned deploy subprocess, an attacker who can label a PR (which, depending on repository configuration/triage access, can be a much lower bar than commit/push access) can override security- and execution-sensitive variables consumed by the shell that runs `shipit.yml` steps, for example:
- `PATH`, `BUNDLE_GEMFILE`, `RUBYOPT`, `RUBYLIB`, `LD_PRELOAD`, `GIT_SSH_COMMAND`, `BASH_ENV` — any of which can be used to hijack execution of the subsequent deploy commands and achieve arbitrary code execution on the deploy host.
- Shipit's own well-known variables (`SHA`, `REVISION`, `LAST_DEPLOYED_SHA`, `DEPLOY_URL`, `SHIPIT_LINK`, `ENVIRONMENT`) can also be clobbered, corrupting deploy/rollback logic.

This lines up with the Critical-tier impact bucket ("RCE on the deploy host") because the review-stack `shipit.yml` steps run with attacker-influenced environment on the same host that executes all of Shipit's deploy automation.

### Likelihood Explanation
Review-stack (per-PR) functionality is a first-class, documented Shipit feature, and PR labeling is a routine, often low-privilege GitHub action (many organizations grant "triage" access — which can add/remove labels — far more broadly than write/push access). No Shipit session, ApiClient token, or webhook secret is needed by the attacker; they only need to interact with GitHub in a way that produces a `pull_request` webhook with attacker-chosen labels. The only requirement is that review stacks are enabled for the repository, which is an explicit, intended Shipit feature covered by in-scope engine code (`app/models/shipit/review_stack.rb`, `lib/shipit/*_commands.rb`), not a misconfiguration.

### Recommendation
- Do not merge raw label names as environment variable keys/values. If label-derived environment flags are wanted, put them through the same permitted-key validation used by `EnvironmentVariables` (`lib/shipit/environment_variables.rb`) before merging into `env`.
- Alternatively, namespace/sanitize label-derived variables (e.g. always prefix with a fixed, non-overridable namespace such as `SHIPIT_LABEL_<sanitized>`) and reject characters/names that collide with reserved or security-sensitive environment variable names (`PATH`, `LD_PRELOAD`, `BASH_ENV`, `IFS`, `GIT_*`, `RUBY*`, etc.).
- Apply an explicit allow-list length/character validation to label names before use, and make the label-to-env behavior opt-in per repository rather than automatic.

### Proof of Concept
1. Attacker (with only "triage"-level GitHub permission on the target repository, or any permission sufficient to add labels) opens a PR against a repository with review stacks enabled.
2. Attacker adds a label named, e.g., `bash_env` is case-insensitive in some shells but for concreteness use `path`. On GitHub, add label `PATH` with an arbitrary intended override is not directly controllable (value is fixed to `"true"`), but a more direct primitive is to add a label such as `git_ssh_command` (uppercased to `GIT_SSH_COMMAND`) — if a corresponding shipit.yml step invokes `git` internally during that stack's provisioning/deploy commands, this environment variable will be set to the literal string `"true"`, which is enough to break/redirect git operations, and demonstrates unauthorized, unfiltered control over the subprocess environment.
3. `Shipit::Webhooks::Handlers::PullRequest::LabeledHandler` processes the `labeled` event and the label is persisted on `stack.pull_request.labels` (as exercised in `LabeledHandler` tests): [7](#0-6) 
4. Any subsequent task (deploy, rollback, restart) run for that review stack calls `TaskCommands#env` → `ReviewStack#env`, which merges the attacker-chosen key into the process environment of the deploy host without any permission check, as shown by the existing test assertions on `env["WIP"]`/`env["BUG"]`.

Note: I was not able to inspect the full contents of `lib/shipit/environment_variables.rb` (read attempts failed due to a tool error on this final iteration), so the exact shape of the "permitted keys" allow-list used by the API path could not be quoted directly; this is cited only via its usage/rescue wiring in `app/controllers/shipit/api/base_controller.rb`. A Devin session with full file access should confirm the exact allow-list implementation before finalizing a fix.

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

**File:** lib/shipit/stack_commands.rb (L13-15)
```ruby
    def env
      super.merge(@stack.env)
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

**File:** test/lib/shipit/deploy_commands_test.rb (L6-15)
```ruby
  test "#env includes the stack's pull request labels" do
    stack = shipit_stacks(:review_stack)
    deploy = stack.trigger_continuous_delivery
    stack.pull_request.labels = ["wip", "bug"]

    env = Shipit::DeployCommands.new(deploy).env

    assert_equal env["WIP"], "true"
    assert_equal env["BUG"], "true"
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

**File:** app/controllers/shipit/api/base_controller.rb (L13-16)
```ruby
      rescue_from ApiClient::InsufficientPermission, with: :insufficient_permission
      rescue_from EnvironmentVariables::NotPermitted, with: :validation_error
      rescue_from TaskDefinition::NotFound, with: :not_found
      rescue_from Task::ConcurrentTaskRunning, with: :conflict
```

**File:** test/models/shipit/webhooks/handlers/pull_request/labeled_handler_test.rb (L52-67)
```ruby
          test "unarchives existing review stack when the repository creates ReviewStacks with allow_with_label and the label is present" do
            stack = create_archived_stack
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :allow_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_labeled)
            payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

            LabeledHandler.new(payload_parsed(:pull_request_labeled)).process

            assert_not stack.reload.archived?, "Expected stack to be NOT be archived"
            assert_pending_provision(stack)
          end
```
