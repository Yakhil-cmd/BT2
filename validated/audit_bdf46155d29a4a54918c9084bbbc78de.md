### Title
Cross-repository commit-status write via unscoped sha lookup in `StatusHandler#process` — (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits by `Commit.where(sha: params.sha)` with no repository/stack scoping, while `Handler#stacks`/`Handler#repository_name` (which exist precisely to scope a payload to the repository that emitted it) are defined but never invoked by this subclass. Any commit sha that happens to exist in more than one stack's `commits` table — trivially achievable since public repositories share identical git history through forking/cherry-picking — will have its GitHub status applied to every matching row, regardless of which repository's webhook actually delivered the event.

### Finding Description
Intended binding: `payload.dig('repository', 'full_name') == <repository owning the Commit row that gets mutated>`. Actual code never establishes or checks this equality for status events.

Path: `Shipit::WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`) parses the raw JSON body and dispatches by `X-Github-Event` via `Shipit::Webhooks.for_event(event)`, which maps `'status'` to `[Handlers::StatusHandler]` [1](#0-0) . `StatusHandler.call(params)` builds params from an `ExplicitParameters` schema that never declares/requires a `repository` key [2](#0-1) , and `#process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no join or filter against any repository/stack [3](#0-2) . Contrast with `PushHandler`/`CheckSuiteHandler`, which do call `stacks` (itself built from `Repository.from_github_repo_name(repository_name)`) before touching commits [4](#0-3) [5](#0-4) . `create_status_from_github!` writes a real `Status` scoped to whatever `stack_id` the matched `Commit` row actually belongs to, and can flip `deployable?`/trigger `schedule_continuous_delivery` for that stack [6](#0-5) [7](#0-6) .

`WebhooksController#verify_signature` resolves the signing app via `Shipit.github(organization: repository_owner)`, where `repository_owner` is read from the same attacker-influenced payload [8](#0-7) [9](#0-8) . In the common single-GitHub-app configuration (`github_default_organization` nil), `Shipit.github` ignores the `organization` argument entirely and always returns the one configured `GitHubApp` with one shared `webhook_secret` [10](#0-9) . So signature verification only proves "a repository/app installation trusted by this Shipit instance sent this," never that the named `repository.full_name` owns the `sha`.

Exploit flow: attacker owns/controls a repository that is a legitimate Shipit-monitored stack (permitted attacker capability: "emit webhooks from a repository they own"). They fork or otherwise obtain a commit whose sha is identical to a commit already recorded against a different, unrelated stack (trivial for public repos since git objects are content-addressed). They set a commit status on that sha via the normal GitHub status API on their own repo. GitHub emits a validly-signed `status` webhook naming the attacker's own repository, but `params.sha` collides with the unrelated stack's commit row. `StatusHandler#process` updates that unrelated commit's status, potentially flipping `deployable?` and firing `ContinuousDeliveryJob` for a stack the attacker never touched.

None of the existing guards close this gap: `drop_unhandled_event` only checks the event type exists; `verify_signature` only authenticates the sender, not the sha-to-repository binding; the `ExplicitParameters` schema for `StatusHandler` never even declares `repository`; and there is no model-level constraint tying `Commit#sha` uniqueness across stacks (the DB index is `sha + stack_id`, allowing the same sha to exist in many stacks by design for forked/shared history).

### Impact Explanation
A successfully delivered `status` webhook for repository A can silently rewrite CI status (`state`, `description`, `target_url`) on a `Commit` belonging to unrelated stack/repository B, purely because the sha matches. Since `Commit#create_status_from_github!` feeds `deployable?` and `schedule_continuous_delivery`, this can trigger an unauthorized deploy on a `continuous_deployment`-enabled stack B that the attacker does not control — this is "a payload for one repository mutating another's stack, commit ... or an unauthorized deploy," explicitly listed as **Critical**. It is repeatable against any stack sharing commit history with a repository the attacker legitimately controls, and requires no privileges beyond owning/pushing to one Shipit-monitored repository.

### Likelihood Explanation
Preconditions: the attacker must own or have write access to at least one repository that is itself a Shipit-monitored stack (an explicitly allowed attacker capability per the threat model), and there must exist a commit sha shared between that repository and a target stack — which happens automatically for any fork of a public repository, or via cherry-pick/rebase of a known public commit. No secrets, sessions, or GitHub App credentials are needed; the webhook signature is genuinely produced by GitHub for the attacker's own repository event. This is low-cost and repeatable per status update.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup by the repository named in the payload (using the existing `stacks`/`repository_name` helpers from `Handler`), e.g. restrict to `stacks.flat_map(&:commits).where(sha: params.sha)` or join `Commit -> Stack -> Repository` and filter on `repository_name`, instead of a global `Commit.where(sha:)`.

### Proof of Concept
Minitest (model-level, no live GitHub) under `test/models/shipit/webhooks/handlers/status_handler_test.rb`:
```ruby
test "status event for repository A does not mutate a commit belonging to unrelated stack B with the same sha" do
  stack_a = shipit_stacks(:shipit)          # attacker-controlled/monitored repo
  stack_b = shipit_stacks(:cyclimse)        # unrelated stack attacker does not control
  shared_sha = "a" * 40

  commit_b = stack_b.commits.create!(sha: shared_sha, message: "shared history")

  payload = {
    "sha" => shared_sha,
    "state" => "success",
    "context" => "ci/attacker",
    "repository" => { "full_name" => stack_a.github_repo_name } # attacker's own repo
  }

  # Binding under test: payload.dig('repository','full_name') == stack_a.github_repo_name
  # but the mutated commit's actual repository == stack_b.repository.github_repo_name
  assert_not_equal payload.dig("repository", "full_name"), stack_b.repository.github_repo_name

  Shipit::Webhooks::Handlers::StatusHandler.new(payload).process

  assert_equal "success", commit_b.reload.status.state,
    "commit belonging to stack B was mutated by a status event naming stack A's repository"
end
```
This demonstrates `Handler#stacks`/`repository_name` are dead code for `StatusHandler`, and that the `repository.full_name` field is not enforced before writing to the matched `Commit`.

### Citations

**File:** app/models/shipit/webhooks.rb (L19-19)
```ruby
          'status' => [Handlers::StatusHandler],
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-18)
```ruby
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end
```
