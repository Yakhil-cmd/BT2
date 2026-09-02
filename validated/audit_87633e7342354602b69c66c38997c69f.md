### Title
Unfiltered PR-label-derived environment injection into deploy commands enables `BUNDLE_GEMFILE` override → RCE on deploy host - ([File: app/models/shipit/review_stack.rb])

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) into the environment hash passed to `Command#start`/`PTY.spawn`, with no allowlist of permitted keys. Because label names are attacker-controlled (captured verbatim from the webhook body by `LabelCapturingHandler`), an unprivileged fork-PR author on a repo with `provisioning_behavior=allow_all` can set arbitrary environment variable *names* — including `BUNDLE_GEMFILE` — on every command Shipit runs for that review stack, bypassing the allowlist mechanism (`filter_deploy_envs`/`EnvironmentVariables#permit`) that exists for the `deploy.variables` config feature.

### Finding Description
The broken binding: the set of environment keys reaching `PTY.spawn` for a review-stack task should equal `Command::BASE_ENV ∪ Shipit.env ∪ deploy_spec.machine_env ∪ allowlisted(deploy_variables)`, i.e. no fork-supplied key should be admitted without going through `EnvironmentVariables#permit`. In practice it equals that set **plus every uppercased PR label name**, unfiltered.

Code path:
1. `LabelCapturingHandler#capture_labels` persists `params.pull_request.labels.map(&:name)` straight from the webhook JSON body onto `pull_request.labels`, with only a `String` type constraint in the `params` schema (`app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:98-102`, schema at lines 29-31). [1](#0-0) 
2. `ReviewStack#env` merges `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` into the stack's env with no key allowlist. [2](#0-1) 
3. `TaskCommands#env` / `DeployCommands#env` merge `@stack.env` (which now includes the attacker's key) into the final command environment. [3](#0-2) 
4. `Command#start` spawns the process with `unbundled_env`, which merges `@env.stringify_keys` (the attacker key/value) on top of `BASE_ENV`. [4](#0-3) 

The allowlist that exists in this codebase — `DeploySpec#filter_deploy_envs`/`#filter_rollback_envs` calling `EnvironmentVariables#permit(deploy_variables)`, which raises `NotPermitted` for any key not declared in `deploy.variables` — is applied only to the explicit user-submitted deploy-trigger `env` parameter (referenced from `app/models/shipit/stack.rb`, `app/models/shipit/deploy.rb`, `app/controllers/shipit/api/rollbacks_controller.rb`), not to `ReviewStack#env`/`TaskCommands#env`. That is the guard the question's invariant expects but which does not cover this path. [5](#0-4) [6](#0-5) 

Attacker request: open (or already have) a PR against a repo configured `provisioning_behavior=allow_all`; add a label whose name, once uppercased, equals `BUNDLE_GEMFILE` (e.g. label `bundle_gemfile`); this is captured via the `pull_request` webhook (`labeled`/`opened`/`reopened` actions) which requires no authentication secret from the attacker (webhook signature verification protects GitHub→Shipit delivery integrity but the attacker only needs GitHub to deliver a normal, legitimately signed webhook for their own repo's PR — no Shipit secret is needed by the attacker to cause GitHub to label their own PR).

Caveat on value control: `ReviewStack#env` hardcodes the value to the literal string `"true"` — the attacker controls only the **key**, not an arbitrary value. This means the attacker cannot inject `BUNDLE_GEMFILE=/attacker/path/Gemfile` directly. However, `BUNDLE_GEMFILE=true` is still a relative path from the command's working directory; because review-stack tasks check out the attacker's own fork branch into the task's working directory (`TaskCommands#checkout`/`#clone`), the attacker can commit a file literally named `true` at the repository root containing malicious Ruby (Gemfile DSL blocks execute arbitrary Ruby). If Bundler is invoked (e.g. the `dependencies` step running `bundle install`) with `chdir` inside that checkout and `BUNDLE_GEMFILE=true` set, Bundler will load and `eval` that file as the Gemfile. I was not able to fully verify, within the available tool budget, the exact `chdir`/`steps_directory` value used for the `bundle install` command relative to the fork checkout (`app/models/shipit/deploy_spec/bundler_discovery.rb` and `TaskCommands#steps_directory` were not fully inspected), so this final RCE step should be independently confirmed before treating it as proven, though the underlying environment-injection primitive itself is fully confirmed by the code.

### Impact Explanation
Confirmed, unconditional: any label an unprivileged fork PR author applies to their own PR is injected — uppercased, key-only — into every `Command` environment run for that review stack (dependency install, deploy steps, tasks), with no allowlist. This lets the attacker clobber operationally significant variables (`PATH`, `BUNDLE_GEMFILE`, `RUBYOPT`, `GIT_*`, etc.) to the literal string `"true"` on every subsequent deploy/task command for their own review stack. Combined with control of the checked-out file tree, this is a credible path to arbitrary Ruby code execution on the Shipit deploy host during the `dependencies`/`deploy` steps (Critical — RCE via `Command`/`PTY.spawn`). Blast radius is scoped to review stacks under `provisioning_behavior=allow_all` for the affected repository/environment; it does not directly cross to unrelated repositories, but any repo owner enabling `allow_all` review stacks is exposed to fork-PR authors.

### Likelihood Explanation
Preconditions: repository must have review stacks enabled with `provisioning_behavior=allow_all` (deliberately permits fork PRs to provision stacks and run their own `shipit.yml`). No Shipit credentials, session, or API token are needed — only the ability to open a PR and add a label to it, both ordinary unprivileged GitHub actions. The label-name-to-env-key mechanism is trivial and repeatable on every label change; the value being fixed to `"true"` raises the bar for a full RCE demonstration (requires the extra "file named `true`" trick, unverified end-to-end here) but does not affect the confirmed, unconditional environment-key injection.

### Recommendation
Add a strict allowlist/denylist to `ReviewStack#env`'s label-derived env merge (mirroring `EnvironmentVariables#permit`), rejecting or dropping any uppercased label name that collides with reserved/sensitive variables (`BUNDLE_GEMFILE`, `BUNDLE_PATH`, `PATH`, `RUBYOPT`, `LD_PRELOAD`, `GIT_*`, etc.) or, better, require label-derived variables to be explicitly declared (e.g. via `deploy.variables`/a repo-level allowlist) the same way `filter_deploy_envs` gates user-submitted deploy env.

### Proof of Concept
```ruby
# test/models/shipit/review_stack_test.rb (new test)
test "#env does not allow labels to override reserved environment variables" do
  stack = shipit_stacks(:review_stack)
  stack.pull_request.labels = ["bundle_gemfile"]

  # BROKEN BINDING under test:
  # expected: stack.env["BUNDLE_GEMFILE"] == nil (or unchanged from BASE_ENV)
  # actual:
  assert_equal "true", stack.env["BUNDLE_GEMFILE"]
end
```
```ruby
# test/lib/shipit/deploy_commands_test.rb (new test)
test "#env propagates label-derived BUNDLE_GEMFILE into the spawned command env" do
  stack = shipit_stacks(:review_stack)
  deploy = stack.trigger_continuous_delivery
  stack.pull_request.labels = ["bundle_gemfile"]

  env = Shipit::DeployCommands.new(deploy).env
  assert_equal "true", env["BUNDLE_GEMFILE"]

  command = Shipit::Command.new("echo test", chdir: Dir.tmpdir, env:)
  assert_equal "true", command.unbundled_env["BUNDLE_GEMFILE"]
end
```
Both assertions succeed against current code, demonstrating the fork-controllable key reaches the `Command` env with no allowlist, confirming the equality `stack.env["BUNDLE_GEMFILE"] == "true"` (attacker-controlled) instead of the expected `nil`/framework-controlled value.

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
