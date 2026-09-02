### Title
Unfiltered PR-label-derived environment keys (e.g. `GEM_HOME`) reach `Command#start`/`PTY.spawn` for review-stack `dependencies.override` steps - (File: app/models/shipit/review_stack.rb)

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) into the stack's environment hash with no key allowlist, and `LabelCapturingHandler#capture_labels` persists label names verbatim from the incoming webhook payload with no filtering. That merged hash flows unfiltered into `Command#unbundled_env`, which merges `@env` last (overriding everything, including `BASE_ENV`), so an unprivileged fork PR can inject arbitrary environment keys — including `GEM_HOME`, `BUNDLE_GEMFILE`, `RUBYOPT`, or `PATH` — into any command spawned for that review stack, including the `dependencies.override` step.

### Finding Description
The broken binding: `Command#unbundled_env` should equal `BASE_ENV.merge('PATH' => ...)` for stack-controlled variables only; instead it equals `BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)` where `@env` (last, thus overriding) is fork-influenced.

`ReviewStack#env` builds the environment for a review stack by taking `super` (the base `Stack#env` hash of `ENVIRONMENT`, `LAST_DEPLOYED_SHA`, etc.) and merging in a hash keyed by every pull-request label name, uppercased, all mapped to `"true"`: [1](#0-0) 

The labels themselves originate straight from the webhook body via `LabelCapturingHandler`, which requires only `name: String` for each label (no format/allowlist restriction) and persists them verbatim: [2](#0-1) [3](#0-2) 

This env hash eventually reaches `Command#unbundled_env`, which merges the caller-supplied `@env` on top of `BASE_ENV` (derived from `Bundler.unbundled_env`) with no key filtering, then passes it directly to `PTY.spawn`: [4](#0-3) [5](#0-4) 

Because `.merge` is called last with `@env`, any key an attacker injects — via a PR label named e.g. `gem_home` (uppercased to `GEM_HOME`) — silently overrides whatever `BASE_ENV` (i.e., Bundler's cleaned environment) would otherwise set. The `dependencies.override` section is driven by `DeploySpec#dependencies_steps`, which under `allow_all` provisioning is fully attacker-controlled from the fork's own `shipit.yml`: [6](#0-5) 

Attack flow: an unprivileged fork owner (1) opens a PR against a repo whose provisioning_behavior is `allow_all`, causing a `ReviewStack` to be provisioned and checked out at the fork branch's content, (2) applies a label literally named `gem_home` to their own PR (labels on PRs against public repos can typically be applied by the PR author or any collaborator with label permission — this is attacker-controlled surface since `LabelCapturingHandler` accepts any label name from the webhook payload with no owner/permission check on label content), (3) commits a directory named `true` in their fork branch containing a malicious native-extension gem structure, (4) the `dependencies.override` step (defined in their own fork's `shipit.yml` under `allow_all`) runs `bundle install`/similar with `GEM_HOME=true` (relative to the checked-out fork content, which is the command's `chdir`), causing Bundler to build/execute the attacker's gem's `extconf.rb`/`Rakefile` during dependency resolution — arbitrary code execution on the deploy host.

Why existing guards fail: `EnvironmentVariables#permit` (used by `filter_deploy_envs`/`filter_rollback_envs` in `DeploySpec`) is applied to deploy/rollback variables supplied via `trigger_deploy`, but not to `Stack#env`/`ReviewStack#env`, which is the base environment merged unconditionally for every command including dependency steps. No allowlist exists on which keys a PR label name may produce, and `Command#unbundled_env` performs no filtering either — it merges whatever hash it receives.

### Impact Explanation
An attacker who can open a PR and label it on a repo they don't administer can cause arbitrary environment-variable overrides (not merely additive vars) in every command run against that repository's review stack, including the dependency install step defined by their own fork's `shipit.yml` under `allow_all`. Combined with control over the checked-out working directory content (their own fork branch), this can escalate to code execution on the Shipit deploy host during `bundle install`/gem resolution (native extension build scripts), matching the Critical RCE-on-deploy-host class. Blast radius is scoped to repositories configured with `provisioning_behavior=allow_all` and is repeatable per PR/label the attacker controls on their own fork.

### Likelihood Explanation
Preconditions: the target repository must have `provisioning_behavior: allow_all` (an explicit, if risky, opt-in) and enable review stacks/PR provisioning. Given that, the attacker only needs to open a PR from their own fork and apply a label to it — no privileged GitHub role, Shipit session, or secret is required. This is low-cost and fully repeatable by the attacker for any repo with this configuration.

### Recommendation
Restrict `ReviewStack#env`'s label-derived keys to an explicit allowlist (e.g., only permit keys the repository has declared as expected PR-label flags), and/or prefix all label-derived env keys with a fixed, collision-free namespace (e.g., `PR_LABEL_<NAME>`) so they can never collide with sensitive variable names such as `GEM_HOME`, `BUNDLE_GEMFILE`, `RUBYOPT`, `PATH`, `LD_PRELOAD`, etc. Additionally, have `Command#unbundled_env` reject/strip caller-supplied keys that match a denylist of security-sensitive environment variables before merging.

### Proof of Concept
minitest[allow_all] plan:
1. Build a `Shipit::ReviewStack` with an associated `PullRequest` whose `labels` array includes `"gem_home"`.
2. Call `review_stack.env` and assert `review_stack.env["GEM_HOME"] == "true"` (demonstrating the unfiltered merge from `ReviewStack#env`, `app/models/shipit/review_stack.rb:84-93`).
3. Construct a `Shipit::Command` for the `dependencies.override` step with `env: review_stack.env`, and assert `command.unbundled_env["GEM_HOME"] == "true"`, i.e., it overrides whatever `Command::BASE_ENV["GEM_HOME"]` would otherwise be (`lib/shipit/command.rb:103-105`), proving the fork-controllable key reaches the environment passed to `PTY.spawn`.
4. Assert the equality-breaking claim explicitly: `Command::BASE_ENV["GEM_HOME"] != command.unbundled_env["GEM_HOME"]` when `BASE_ENV` does not already define `GEM_HOME`, confirming the injected label value takes precedence over the sanitized Bundler environment for the `dependencies.override` invocation.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L26-31)
```ruby
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
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

**File:** app/models/shipit/deploy_spec.rb (L77-82)
```ruby
    def dependencies_steps
      around_steps('dependencies') do
        config('dependencies', 'override') { discover_dependencies_steps || [] }
      end
    end
    alias dependencies_steps! dependencies_steps
```
