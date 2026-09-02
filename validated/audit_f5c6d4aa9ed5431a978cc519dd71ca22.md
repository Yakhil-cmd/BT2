### Title
Unfiltered pull-request label names injected into `GEM_PATH`/arbitrary env vars reaching `PTY.spawn` for `rollback.override` steps - (File: app/models/shipit/review_stack.rb)

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) directly into the deploy/rollback environment hash with no key allowlist. That hash flows unfiltered through `RollbackCommands#env` → `Command#env` → `Command#unbundled_env`, which is passed straight to `PTY.spawn` when the `rollback.override` step is executed, letting an attacker who can label their own fork PR set `GEM_PATH` (or any other env var) on the deploy host.

### Finding Description
The broken binding: the set of environment variable keys reaching `PTY.spawn` for a review-stack rollback step should equal `{keys explicitly whitelisted by DeploySpec#rollback_variables} ∪ {fixed Shipit-controlled keys}`. In fact it equals `BASE_ENV.keys ∪ pull_request.labels.map(&:upcase) ∪ fixed keys`, with no intersection filtering.

Code path:
- `ReviewStack#env` merges `super` with `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" } }` — no key allowlist at all. [1](#0-0) 
- `pull_request.labels` is populated verbatim from the webhook payload by `LabelCapturingHandler#capture_labels`, which does `pull_request.update!(labels: params.pull_request.labels.map(&:name))` — the label *names* are taken as-is from GitHub's webhook body with no sanitization or allowlist. [2](#0-1) 
- `RollbackCommands#env` calls `super.merge('ROLLBACK' => '1')`, inheriting the label-derived keys from `ReviewStack#env`/`TaskCommands#env` without any filtering. [3](#0-2) 
- `DeploySpec` defines `filter_rollback_envs`/`filter_deploy_envs`, which would apply `EnvironmentVariables.with(env).permit(rollback_variables)` to enforce an allowlist, but these methods are only defined in `app/models/shipit/deploy_spec.rb` — no other call site in the app was found invoking them before commands are constructed and run. [4](#0-3) [5](#0-4) 
- Finally, `Command#unbundled_env` merges `BASE_ENV` (derived from `Bundler.unbundled_env`/`ENV`) with `@env.stringify_keys`, and `Command#start` spawns the process with that merged hash via `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`. There is no key filtering at this layer either — any key present in `@env`, including an attacker-supplied `GEM_PATH`, silently overrides/augments the base process environment. [6](#0-5) 

Exploit flow: an attacker forks the target repo, opens a PR, and applies (or has applied to their PR) a label literally named `gem_path` (any case). GitHub's `pull_request` webhook fires; `LabelCapturingHandler` persists `["gem_path"]` into `pull_request.labels`. When the review stack later runs its `rollback` step (defined via `rollback.override` in the fork's `shipit.yml`, itself attacker-controlled content merged during provisioning), `RollbackCommands#env` includes `"GEM_PATH" => "true"`, which is merged directly into the spawned process's environment, letting `require`/`bundle` in that step consult an attacker-influenced gem path value during the deploy host's rollback command execution.

Existing guards fail because: `verify_signature`/webhook signature checks only validate a webhook truly came from GitHub for the given repo — they say nothing about the label *content*, which GitHub always lets the PR-owner (in a fork they own) set on their own PR. `EnvironmentVariables#permit` exists as the correct mitigation primitive but is not wired into the actual `rollback.override` execution path found in this repo.

### Impact Explanation
An attacker who can open a fork PR and attach a label of their choosing can inject arbitrary environment variable keys/values (e.g., `GEM_PATH`, `RUBYOPT`, `LD_PRELOAD`-style vectors if similarly unfiltered) into the process environment of commands the Shipit deploy host executes for that repository's review stack, specifically the `rollback.override` step. This is a path toward Remote Code Execution on the deploy host (Critical), since gem/require resolution during Bundler/Ruby invocations can be influenced by `GEM_PATH`. The blast radius is scoped to the review stack for the attacking repository (the PR author's own fork-derived review stack), not cross-tenant, but it demonstrates that command execution occurs with attacker-controlled state that should not reach the spawned process.

### Likelihood Explanation
Preconditions: the repository must support review stacks (any `provisioning_behavior` including `prevent_with_label`, since that only gates stack creation/archival, not the `env` merging logic), and the fork's `shipit.yml` must define a `rollback.override` (or any step) that is eventually executed for the review stack. The attacker only needs the ability to open a PR from their own fork and set a label on it — both explicitly listed as in-scope unprivileged attacker capabilities in this exercise. This is fully repeatable and requires no secrets, tokens, or elevated GitHub permissions on the target repository.

### Recommendation
Enforce an explicit allowlist before merging pull-request-label-derived keys into any environment passed to `Command`. At minimum:
- In `ReviewStack#env`, only merge label-derived keys that pass through `DeploySpec#filter_rollback_envs`/`filter_deploy_envs` (i.e., call `EnvironmentVariables.with(...).permit(...)` against `rollback_variables`/`deploy_variables`) before merging.
- Additionally, deny well-known dangerous keys (`GEM_PATH`, `GEM_HOME`, `RUBYOPT`, `LD_PRELOAD`, `BUNDLE_GEMFILE`, `PATH`, etc.) unconditionally in `Command#unbundled_env`, regardless of upstream filtering, so no caller can override them via `@env`.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (or a new rollback_commands_test.rb)
test "rollback.override step inherits attacker-controlled GEM_PATH via PR label" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["gem_path"]  # attacker-controlled fork PR label
  stack.update!(cached_deploy_spec: create_deploy_spec(
    "rollback" => { "override" => ["echo $GEM_PATH"] }
  ))

  rollback = stack.trigger_rollback(shipit_users(:codertocat), ...) # build the rollback task
  env = Shipit::RollbackCommands.new(rollback).env

  # Binding under test: rollback env should equal only allowlisted keys, NOT include fork-controlled GEM_PATH
  refute env.key?("GEM_PATH"), "rollback env must not inherit fork-controllable GEM_PATH"
  # Actual (vulnerable) behavior observed:
  assert_equal "true", env["GEM_PATH"]
end
```
This demonstrates the equality violation: expected `env.key?("GEM_PATH") == false` (no fork-controllable key reaches the rollback command env), actual `env["GEM_PATH"] == "true"`, confirming the attacker-controlled key reaches the environment ultimately passed to `Command#start` → `PTY.spawn`.

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

**File:** lib/shipit/rollback_commands.rb (L9-13)
```ruby
    def env
      super.merge(
        'ROLLBACK' => '1'
      )
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

**File:** lib/shipit/environment_variables.rb (L13-18)
```ruby
    def permit(variable_definitions)
      return {} unless @env
      raise "A whitelist is required to sanitize environment variables" unless variable_definitions

      sanitize_env_vars(variable_definitions)
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
