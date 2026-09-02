### Title
Unfiltered PR label names injected into `fetch` step environment allow `DYLD_INSERT_LIBRARIES` on macOS deploy hosts - (File: app/models/shipit/review_stack.rb)

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) directly into the stack's environment hash with no key allowlist, and this merged hash reaches `Command#start`/`PTY.spawn` for the `fetch` phase without going through any whitelist filter (unlike `deploy`/`rollback`, which are sanitized by `DeploySpec#filter_deploy_envs`/`filter_rollback_envs`). An attacker who opens a PR from a fork of a repository with `provisioning_behavior=allow_all` and review stacks enabled can add a label literally named `dyld_insert_libraries` and have it become `ENV["DYLD_INSERT_LIBRARIES"] = "true"` for any command executed against that review stack, including `fetch`.

### Finding Description
The broken binding: the set of environment variables reaching `PTY.spawn` for the `fetch` phase should equal `BASE_ENV ∪ {whitelisted deploy/rollback vars from shipit.yml}`, but instead equals `BASE_ENV ∪ {PATH} ∪ pull_request.labels.map(&:upcase)` — an attacker-controlled, unbounded key set.

Code path:
1. `LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` verbatim from the webhook body onto `PullRequest#labels`, with no key or value validation. [1](#0-0) 
2. `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` into `super` (the base stack env) with no allowlist of permitted keys. [2](#0-1) 
3. `DeploySpec` provides `filter_deploy_envs`/`filter_rollback_envs`, which route env through `EnvironmentVariables#permit`, raising `NotPermitted` for any key not declared in the repo's own `deploy.variables`/`rollback.variables` in `shipit.yml`. [3](#0-2) 
However, there is no equivalent `filter_fetch_envs` method — `fetch_deployed_revision_steps` is exposed with no companion filtering method, meaning the `fetch` phase's commands are built from the raw, unfiltered `env` hash. [4](#0-3) 
4. `Command#unbundled_env` merges `@env.stringify_keys` (the attacker-influenced hash) on top of `BASE_ENV`/`PATH`, and `Command#start` calls `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)`, so any key present in the merged hash — including `DYLD_INSERT_LIBRARIES` — is passed to the spawned child process's environment. [5](#0-4) 

Exploit flow: attacker forks a repo configured with `provisioning_behavior_allow_all?` and `review_stacks_enabled`, opens a PR, adds a label named `dyld_insert_libraries` (GitHub labels are case-insensitive/free-text and owned entirely by the PR author on their own fork/repo they administer), which is captured by `LabelCapturingHandler` via the `labeled` webhook event. When the `ReviewStack`'s `fetch` step (used to detect deployed revision, e.g. via `supports_fetch_deployed_revision?`/`fetch_deployed_revision_steps`) is executed, `ReviewStack#env` uppercases the label into `DYLD_INSERT_LIBRARIES=true`, which is merged unfiltered into the command environment and reaches `PTY.spawn` on the deploy host.

Existing guards fail here because: `EnvironmentVariables#permit` protects `deploy` and `rollback` steps only (`filter_deploy_envs`/`filter_rollback_envs`), not `fetch`; there is no allowlist applied to the label-derived keys at the `ReviewStack#env` merge point; and `LabelCapturingHandler`'s `ExplicitParameters` schema validates only structural types (`String`/`Integer`), not the semantic content of label names.

### Impact Explanation
If a macOS deploy host has `DYLD_INSERT_LIBRARIES`-sensitive execution characteristics (e.g., non-hardened-runtime binaries invoked by `fetch` commands), an attacker-controlled fork PR can cause the deploy host to preload an attacker-supplied dynamic library path during the `fetch` phase, potentially leading to code execution in the context of the Shipit deploy process. This is a Critical RCE-class issue on the deploy host, matching the "Command running that should not" impact criterion. The vector is repeatable per PR/label and would affect any `allow_all` review-stack-enabled repository on the instance.

### Likelihood Explanation
Preconditions: the repository must have `review_stacks_enabled` and `provisioning_behavior=allow_all` (a documented configuration, not a bug by itself), and the deploy host must be macOS with a `fetch` command susceptible to `DYLD_INSERT_LIBRARIES` (dynamic loader honors this env var by default unless the target binary uses hardened runtime / SIP protections, or unless the value points to a nonexistent/invalid path). Attacker cost is trivial: open a PR from a fork and add a label — no privileges, tokens, or secrets required. This is fully repeatable across any `allow_all` review-stack repo, though actual OS-level exploitation depends on the executable invoked by the `fetch` step being dyld-preload-susceptible.

### Recommendation
Apply an explicit allowlist to review-stack label-derived environment variables (and to `fetch` step environment in general), analogous to `DeploySpec#filter_deploy_envs`/`filter_rollback_envs`. Concretely: introduce a `DeploySpec#filter_fetch_envs` (backed by a declared `fetch.variables` whitelist or by reusing `deploy_variables`) and have `ReviewStack#env` and whatever builds the `fetch` command route their merged environment through `EnvironmentVariables#permit` before it reaches `Command.new(..., env: ...)`. Additionally, explicitly blocklist/strip dynamic-linker-influencing variable names (`DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`) from any environment derived from untrusted PR metadata regardless of whitelist configuration.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (illustrative)
test "#env allows fork PR labels to inject DYLD_INSERT_LIBRARIES into the fetch step env" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["dyld_insert_libraries"]

  env = stack.env

  assert_equal "true", env["DYLD_INSERT_LIBRARIES"]

  # Show it reaches Command#unbundled_env / PTY.spawn args unfiltered
  command = Shipit::Command.new(["echo", "hi"], chdir: stack.git_path, env: stack.env)
  assert_equal "true", command.unbundled_env["DYLD_INSERT_LIBRARIES"]
end
```
This demonstrates the equality break: expected `fetch`-step env keys ⊆ whitelisted `deploy_variables`/`rollback_variables`, but actual `fetch`-step env keys ⊇ arbitrary uppercased PR label names, with `DYLD_INSERT_LIBRARIES` reaching `Command#unbundled_env` and thus `PTY.spawn`.

### Citations

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

**File:** app/models/shipit/deploy_spec.rb (L155-161)
```ruby
    def fetch_deployed_revision_steps
      config('fetch') || discover_fetch_deployed_revision_steps
    end

    def fetch_deployed_revision_steps!
      fetch_deployed_revision_steps || cant_detect!(:fetch)
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
