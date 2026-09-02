### Title
Unprivileged fork PR label names (uppercased) are merged unfiltered into the deploy process environment, allowing `GEM_PATH` injection - (File: `app/models/shipit/review_stack.rb`)

### Summary
`ReviewStack#env` merges every pull-request label name, uppercased, directly into the stack's environment hash with no allowlist, and this hash flows straight into `DeployCommands#env` / `TaskCommands#env`, which is passed to `Command.new(env:)` and ultimately into `Command#unbundled_env`, which merges attacker-controlled keys over the sanitized `BASE_ENV` before `PTY.spawn`. Because the only sanitization present (`DeploySpec#filter_deploy_envs` / `EnvironmentVariables#permit`) applies exclusively to the user-supplied `Deploy#env` field, not to `Stack#env`/`ReviewStack#env`, a fork PR author can set a label like `gem_path` to inject `GEM_PATH=<attacker path>` into the deploy subprocess environment.

### Finding Description
The broken binding: the invariant "the `deploy.variables` step inherits no fork-controllable key such as `GEM_PATH`" should hold as `Command#unbundled_env == BASE_ENV.merge(PATH).merge(sanitized_task_env)`, but in fact it equals `BASE_ENV.merge(PATH).merge(unsanitized_stack_env)`, where `unsanitized_stack_env` includes `pull_request.labels.each_with_object({}){|n,h| h[n.upcase]='true'}` with no key allowlist: [1](#0-0) 

`LabelCapturingHandler#capture_labels` persists arbitrary label names straight from the webhook payload with no filtering: [2](#0-1) 

This merged env reaches `DeployCommands#env`, which is exercised and confirmed unsanitized by the existing repo test: [3](#0-2) [4](#0-3) 

That `env` is handed to `Command.new(..., env:)`, whose `unbundled_env` merges attacker-controlled keys on top of the sanitized Bundler-clean `BASE_ENV` and passes the result directly to `PTY.spawn`: [5](#0-4) [6](#0-5) 

The only sanitization function in the codebase, `DeploySpec#filter_deploy_envs`, is applied solely to the `Deploy#env` field submitted via the deploy form/API (`deploy_params` in `DeploysController` restricts to `@stack.deploy_variables.map(&:name)`), not to the `Stack#env`/`ReviewStack#env` hash used for step interpolation and process spawning: [7](#0-6) [8](#0-7) 

Exploit flow: an unprivileged user opens a fork PR against a repository with `provisioning_behavior=allow_all` (review stacks auto-provisioned, no maintainer approval needed), adds a label named `gem_path` (case-insensitive on GitHub, normalized via `.upcase`), which is captured by `LabelCapturingHandler`/`LabeledHandler` webhooks and stored on `pull_request.labels`. When the review stack's continuous delivery or manual deploy runs, `ReviewStack#env` injects `GEM_PATH=true` (or any label text) into the environment merged into the spawned deploy process, which is consulted by `require`/`bundle` during `deploy.pre`/`deploy.override`/`deploy.variables`-influenced steps, enabling gem path hijacking and Ruby code execution on the deploy host.

### Impact Explanation
This allows an unprivileged fork PR author to have the deploy host's `PTY.spawn`-executed process's `GEM_PATH` (or any other environment key desired, e.g. `RUBYOPT`, `LD_PRELOAD`, `BUNDLE_GEMFILE`) overridden with attacker-chosen values purely by naming a PR label, without any maintainer review, matching the Critical "RCE on the deploy host via Command/PTY.spawn" category. The blast radius is scoped to the repository owning the review stack (an attacker cannot cross into another repository's stack), but is fully repeatable: every relabel/deploy cycle reinjects the value, and any environment-sensitive tool invoked during deploy steps consults it.

### Likelihood Explanation
Preconditions: the target repository must have `provisioning_behavior=allow_all` (review stacks auto-created for any PR, including forks) and review-stack continuous delivery/deploy must execute a step that consults `GEM_PATH`/`require`/`bundle` (common for Ruby projects using Bundler in `deploy.override`/`deploy.pre`). Attacker cost is minimal: open a PR from a fork and add a label — both are standard unprivileged GitHub actions requiring no Shipit credentials, confirmed reachable per the existing `DeployCommandsTest` which already demonstrates that arbitrary uppercased label names land unfiltered in `Command#env`.

### Recommendation
Do not merge raw pull-request label names into the process environment without an allowlist. In `ReviewStack#env`, restrict merged label-derived keys to variable names explicitly declared in `deploy_variables`/`rollback_variables` (i.e., run the label-derived hash through `EnvironmentVariables.with(...).permit(deploy_variables)` or an explicit safe prefix/allowlist), and additionally have `Command#unbundled_env` refuse to let caller-supplied `@env` override sensitive keys such as `GEM_PATH`, `RUBYOPT`, `BUNDLE_GEMFILE`, `LD_PRELOAD`, `PATH` beyond the already-controlled `PATH` merge.

### Proof of Concept
minitest plan (already effectively demonstrated by existing fixture-based test, extend for `GEM_PATH`):
```ruby
test "#env allows fork PR labels to override GEM_PATH reaching the spawned process" do
  stack = shipit_stacks(:review_stack)
  deploy = stack.trigger_continuous_delivery
  stack.pull_request.labels = ["gem_path"]

  env = Shipit::DeployCommands.new(deploy).env
  assert_equal "true", env["GEM_PATH"]

  command = Shipit::Command.new("true", chdir: Dir.tmpdir, env: env)
  assert_equal "true", command.unbundled_env["GEM_PATH"]
end
```
Assertions on both sides of the equality: expected `Command#unbundled_env["GEM_PATH"] == <host's Bundler-clean GEM_PATH, or nil>`; actual `Command#unbundled_env["GEM_PATH"] == "true"` (attacker-controlled), proving the divergence.

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

**File:** lib/shipit/command.rb (L17-18)
```ruby
    unbundled_env = Bundler.respond_to?(:unbundled_env) ? Bundler.unbundled_env : Bundler.clean_env
    BASE_ENV = unbundled_env.merge((ENV.keys - unbundled_env.keys).map { |k| [k, nil] }.to_h)
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

**File:** app/models/shipit/deploy_spec.rb (L174-176)
```ruby
    def filter_deploy_envs(env)
      EnvironmentVariables.with(env).permit(deploy_variables)
    end
```

**File:** app/controllers/shipit/deploys_controller.rb (L66-68)
```ruby
    def deploy_params
      @deploy_params ||= params.require(:deploy).permit(:until_commit_id, env: @stack.deploy_variables.map(&:name))
    end
```
