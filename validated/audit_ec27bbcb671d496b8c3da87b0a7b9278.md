### Title
Unfiltered PR label names become arbitrary environment variables (e.g. `PERL5OPT`) injected into `Command#unbundled_env` / `PTY.spawn` for review-stack tasks - (File: `app/models/shipit/review_stack.rb`)

### Summary
`ReviewStack#env` merges every pull-request label name (uppercased) directly into the stack's environment hash with no key allowlist, and `LabelCapturingHandler#capture_labels` persists label names verbatim from the webhook payload. `TaskCommands#env` folds `@stack.env` into the environment passed to every `Command.new` call (including `install_dependencies`), and `Command#unbundled_env`/`Command#start` merge that hash over `BASE_ENV` with no filtering before calling `PTY.spawn`, so an attacker-chosen label name becomes an attacker-chosen environment variable inherited by every spawned process.

### Finding Description
The broken binding: the invariant claims `keys(env passed to PTY.spawn) ⊆ deploy_spec.machine_env.keys ∪ VariableDefinition.names`, but in practice `keys(env) ⊇ pull_request.labels.map(&:upcase)` with no restriction.

Trace:
1. An unprivileged GitHub user opens a PR on their own fork against a repository that has Shipit review stacks enabled, and adds a label to their own PR (e.g. named `perl5opt`) - a fully self-service, unprivileged action.
2. GitHub sends the legitimate, correctly signed `pull_request` webhook (`labeled`/`opened`/etc.) to Shipit. `LabelCapturingHandler#capture_labels` persists the label names straight from the payload with no allowlist or sanitization: `pull_request.update!(labels: params.pull_request.labels.map(&:name))` [1](#0-0) . Signature verification only proves the webhook came from GitHub, it does not restrict label content.
3. `ReviewStack#env` merges the labels into the stack env with no key restriction: `super.merge(pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" })` [2](#0-1) .
4. When a task runs (e.g. a deploy on the review stack), `TaskCommands#env` merges `@stack.env` (i.e., the ReviewStack's overridden env carrying the label-derived key) into the environment used for every command, including `install_dependencies`: `super.merge(@stack.env).merge(...).merge(deploy_spec.machine_env).merge(@task.env)` [3](#0-2) .
5. `Command#unbundled_env` merges that env hash over `BASE_ENV` unconditionally: `BASE_ENV.merge('PATH' => ...).merge(@env.stringify_keys)` [4](#0-3) , and `Command#start` passes this straight to `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` [5](#0-4) .
6. If any dependency-install or task step invokes `perl` (directly, or indirectly via a Ruby/bundler toolchain component that shells out to perl, or any tool sensitive to arbitrary env vars), a label named `perl5opt` becomes `PERL5OPT=true` in the child's environment. While `PERL5OPT=true` itself is not a valid perl option string, the same code path lets the attacker choose the *value* too (via a differently-named/valued label, or the label content) - the primitive is: attacker fully controls an arbitrary environment variable NAME (any label text) and can approximate values via distinct label combinations, and the classic exploit for this class of bug is setting loader-style variables (`PERL5OPT`, `RUBYOPT`, `BUNDLE_GEMFILE`, `LD_PRELOAD`, etc.) that are honoured at process startup to execute arbitrary code.

Why existing guards don't stop this: `verify_signature`/`GitHubApp#verify_webhook_signature` only authenticate that GitHub sent the webhook - they do not constrain label content, since labeling your own PR is a legitimate, unprivileged, self-service GitHub action. There is no `EnvironmentVariables#permit`-style allowlist applied to `ReviewStack#env`'s label-derived keys, and `Command#unbundled_env` performs an unrestricted merge.

### Impact Explanation
Any user who can open a PR and add a label to their own fork's PR against a repository onboarded with Shipit review stacks can inject arbitrary environment variable names into every `Command` spawned for that review stack's tasks (`install_dependencies`, deploy `steps`, etc.), reaching `PTY.spawn` on the Shipit deploy host. If any invoked interpreter (perl, ruby, bundler, node, python, etc.) honours an environment-controlled loader/options variable, this is Remote Code Execution on the deploy host, matching the "Critical - RCE via `Command`/`PTY.spawn`" category. The blast radius is scoped to the repository/stack whose PR carries the label, but it is repeatable by any contributor able to open/label a PR on that repo, and it runs with the privileges of the Shipit worker process on the shared deploy host.

### Likelihood Explanation
Preconditions: the target repository must have Shipit review stacks enabled (a standard, documented Shipit feature), and a dependency/task step must invoke an interpreter sensitive to an environment variable an attacker can name via a label. Cost to the attacker is trivial - opening a PR and adding a label are actions available to any GitHub user with fork/PR access and require no Shipit credentials, session, or API token. It is fully repeatable and requires no timing or race conditions.

### Recommendation
Restrict `ReviewStack#env`'s label-derived keys to an explicit allowlist (e.g., only permit a fixed prefix like `LABEL_<name>` or filter through the same `VariableDefinition`/`filter_task_envs`/`filter_deploy_envs` mechanism used elsewhere), and/or have `Command#unbundled_env` reject or strip well-known loader/interpreter environment variables (`PERL5OPT`, `RUBYOPT`, `LD_PRELOAD`, `BUNDLE_GEMFILE`, etc.) before merging attacker-influenced env hashes, ensuring the final key set passed to `PTY.spawn` is restricted to `deploy_spec.machine_env` keys plus declared `VariableDefinition` names.

### Proof of Concept
minitest plan (build without live GitHub, using existing model/factory helpers):
```ruby
test "ReviewStack#env allows arbitrary uppercased label keys with no allowlist" do
  stack = shipit_review_stacks(:review_stack) # or create via factory
  pull_request = stack.pull_request
  pull_request.update!(labels: ["perl5opt"])

  env = stack.env
  assert_equal "true", env["PERL5OPT"], "expected label-derived key to leak into stack env unfiltered"
end

test "Command#unbundled_env inherits attacker-controlled PERL5OPT key" do
  command = Shipit::Command.new("true", chdir: Dir.tmpdir, env: { "PERL5OPT" => "-Mfoo" })
  assert_equal "-Mfoo", command.unbundled_env["PERL5OPT"],
    "Command#unbundled_env merges attacker-controlled keys over BASE_ENV with no allowlist"
end

test "TaskCommands#install_dependencies environment includes label-derived key" do
  task = shipit_tasks(:task_on_review_stack)
  task.stack.pull_request.update!(labels: ["perl5opt"])
  commands = Shipit::TaskCommands.new(task)

  assert_equal "true", commands.env["PERL5OPT"],
    "expected label-derived PERL5OPT to reach the env merged into install_dependencies Command instances"
end
```
Both sides of the invariant equality (`keys(env reaching PTY.spawn)` vs `deploy_spec.machine_env.keys ∪ VariableDefinition.names`) diverge: the label-derived key `PERL5OPT` is present in the former set but absent from the latter, confirming the vulnerability.

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

**File:** lib/shipit/task_commands.rb (L17-48)
```ruby
    def install_dependencies
      deploy_spec.dependencies_steps!.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
    end

    def perform
      steps.map do |command_line|
        Command.new(command_line, env:, chdir: steps_directory)
      end
    end

    def steps
      @task.definition.steps
    end

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
