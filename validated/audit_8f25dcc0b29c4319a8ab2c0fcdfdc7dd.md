### Title
Git ref/branch argument injection into `git fetch` positional argv via unsanitized `Stack#branch` - (File: lib/shipit/stack_commands.rb)

### Summary
`Command#parse_arguments`/`#interpolated_arguments` perform no filtering of argv elements that begin with `-`; they simply flatten, stringify, and interpolate environment variables, then splat the resulting array directly into `PTY.spawn`. `StackCommands#fetch` builds `git('fetch', 'origin', *quiet_git_arg, '--tags', '--force', @stack.branch, ...)` with `@stack.branch` sourced unmodified from `params.pull_request.head.ref` via `ReviewStackAdapter#stack_attributes`, so an attacker-controlled branch name beginning with `-` is passed as a bare positional token to `git`, with no `--` separator preventing git from parsing it as an option.

### Finding Description
The broken binding: the intended invariant is `command.args.last == validated_branch_name` where `validated_branch_name` never starts with `-`. In fact, `command.args.last == @stack.branch` with `@stack.branch` equal to the raw GitHub PR head-ref string, unconstrained.

Trace:
- `app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb:87-93` — `stack_attributes` sets `branch: params.pull_request.head.ref` directly from webhook payload, with no format validation of the branch string itself (only presence is checked at `app/models/shipit/stack.rb:102`: `validates :branch, presence: true`; no format restriction disallowing a leading `-`).
- `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:41-46` calls `ReviewStackAdapter#find_or_create!` whenever `provision?` is true (e.g., `provisioning_behavior_allow_all?`), which any external unprivileged user opening a PR against a configured repo can trigger.
- `lib/shipit/stack_commands.rb:27-35` (`#fetch`) builds `git('fetch', 'origin', *quiet_git_arg, '--tags', '--force', @stack.branch, env:, chdir: @stack.git_path)`.
- `lib/shipit/command.rb:227-240` (`#parse_arguments`) only extracts Hash-based options; it does not inspect or reject argument strings beginning with `-`.
- `lib/shipit/command.rb:81-83, 92` (`#interpolated_arguments`, `#start`) interpolate env vars and pass `*interpolated_arguments` straight to `PTY.spawn(unbundled_env, *interpolated_arguments, chdir: @chdir)` — no `--` separator is inserted before the final positional ref argument.

Existing guards do not catch this: `verify_signature`/webhook signature checks authenticate that the payload came from GitHub, but do not constrain the *content* of `head.ref` (GitHub itself allows nearly arbitrary branch names, including ones starting with `-`, subject only to git ref-name rules which do permit a leading dash in practice for many git versions/paths). `ExplicitParameters` schema on the webhook only requires `head.ref` to be a `String`, not a safe format. `Stack` validations only check `environment` format and `branch` presence, not branch format for shell/argv-hostility. There is no `--` inserted before the ref in `git fetch`, unlike, e.g., safer patterns that would use `git fetch origin -- <ref>` or validate the ref does not start with `-`.

Attacker exploit flow: An attacker forks the target repo, creates a branch literally named e.g. `--upload-pack=touch$IFS/tmp/pwned;`, opens a PR. If `provisioning_behavior_allow_all` is set, `ReviewStackAdapter#create!` persists `Stack#branch` verbatim. When `StackCommands#fetch` (or `#fetch_commit`, `#git_clone`) next runs (triggered by provisioning/refresh jobs), the resulting argv fed to `PTY.spawn` contains the attacker string as a bare positional/option-shaped token instead of a ref.

### Impact Explanation
This is a genuine argument-injection primitive into the argv passed to `PTY.spawn` for `git`. Whether it achieves full RCE depends on which git option the attacker can smuggle in and whether that option is honored by the local git client over the configured transport (the repo enforces HTTPS as of the `0.24.0` changelog entry, which limits — but per git version and configuration does not always eliminate — dangerous options like `--upload-pack` (SSH/`file://`-only relevance) or config-injection style options). Regardless of full command execution being transport-dependent, the underlying binding violation is real and file/method-supported: an unvalidated, attacker-controlled string is spliced as a positional/flag-ambiguous argv element into a `PTY.spawn` invocation with no `--` separator or leading-dash rejection. This matches the RCE-category concern raised in the question but the exploitability of a *specific* command-injection payload (e.g., `--exec=`) is not established here, because `git fetch` has no generic `--exec` option, and I could not confirm within this codebase/index that any of the git options reachable through the unguarded positional slot let an attacker execute arbitrary shell commands over the HTTPS transport actually configured by `repo_git_url`.

### Likelihood Explanation
Preconditions: `repository.review_stacks_enabled` and `provisioning_behavior_allow_all` (or `allow_with_label`/`prevent_with_label` satisfied) must be configured by the repo owner/Shipit operator — this is an explicit opt-in feature, not default-on. Given that, the attacker cost is trivial (rename a fork branch, open a PR), and it is repeatable against any repository configured this way.

### Recommendation
Reject or sanitize branch/ref names that begin with `-` (or otherwise resemble a flag) before they are used to construct `git` argv in `StackCommands#fetch`, `#fetch_commit`, and `#git_clone`; and/or always insert a `--` separator before ref arguments in git invocations (e.g., `git('fetch', 'origin', *quiet_git_arg, '--tags', '--force', '--', @stack.branch, ...)`). Additionally, add a `Stack` validation on `branch` rejecting values starting with `-`.

### Proof of Concept
Not fully substantiated as end-to-end RCE within available context — the argv-injection mechanics are demonstrable, but I could not confirm a concrete git-fetch-recognized flag over the HTTPS-only transport that yields command execution, so I cannot state this reaches the "Critical RCE" bar with certainty using only what is indexed here. A minitest such as:
```ruby
test "#fetch does not sanitize a leading-dash branch name" do
  @stack.update_column(:branch, '--upload-pack=touch /tmp/pwned')
  @stack.git_path.stubs(:exist?).returns(true)
  @stack.git_path.stubs(:empty?).returns(false)
  command = @commands.fetch
  assert_equal %w[git fetch origin --quiet --tags --force --upload-pack=touch /tmp/pwned], command.args
end
```
would prove the injection point exists (matching the observed `command.args` pattern in `test/unit/deploy_commands_test.rb:119-126`), but confirming actual command execution requires live git behavior against the configured HTTPS remote, which is outside what I can verify from the indexed code alone. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** lib/shipit/command.rb (L81-98)
```ruby
    def interpolated_arguments
      interpolate_environment_variables(@args)
    end

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

**File:** lib/shipit/command.rb (L227-240)
```ruby
    def parse_arguments(arguments)
      options = {}
      args = arguments.flatten.map do |argument|
        case argument
        when Hash
          options.merge!(argument.values.first)
          argument.keys.first
        else
          argument
        end
      end

      [args.map(&:to_s), options]
    end
```

**File:** lib/shipit/stack_commands.rb (L27-35)
```ruby
    def fetch
      create_directories
      if valid_git_repository?(@stack.git_path)
        git('fetch', 'origin', *quiet_git_arg, '--tags', '--force', @stack.branch, env:, chdir: @stack.git_path)
      else
        @stack.clear_git_cache!
        git_clone(@stack.repo_git_url, @stack.git_path, branch: @stack.branch, env:, chdir: @stack.deploys_path)
      end
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-94)
```ruby
          def create!
            ReviewStack.transaction do
              stack = scope.create!(stack_attributes)
              stack
                .build_pull_request
                .update!(
                  github_pull_request: params.pull_request
                )
            end

            Shipit::ReviewStackProvisioningQueue.add(stack)

            @stack = stack
          end

          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-70)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def pull_request
            params.pull_request
          end

          def respond_to_pull_request_opened?
            params.action == "opened" &&
              provision?
          end

          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/models/shipit/stack.rb (L96-104)
```ruby
    validates :repository, uniqueness: {
      scope: %i[environment], case_sensitive: false,
      message: 'cannot be used more than once with this environment. Check archived stacks.'
    }
    validates :environment, format: { with: /\A[a-z0-9\-_:]+\z/ }, length: { maximum: ENVIRONMENT_MAX_SIZE }
    validates :deploy_url, format: { with: URI::DEFAULT_PARSER.make_regexp(%w[http https ssh]) }, allow_blank: true
    validates :branch, presence: true

    validates :lock_reason, length: { maximum: 4096 }
```

**File:** test/unit/deploy_commands_test.rb (L119-126)
```ruby
    test "#fetch calls git fetch if repository cache already exist" do
      @stack.git_path.stubs(:exist?).returns(true)
      @stack.git_path.stubs(:empty?).returns(false)

      command = @commands.fetch

      assert_equal %w[git fetch origin --quiet --tags --force master], command.args
    end
```
