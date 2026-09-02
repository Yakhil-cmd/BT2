### Title
Cross-tenant commit status forgery: StatusHandler#process mutates any commit matching `sha` regardless of which org's signature validated the request - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates a `status` webhook only against the GitHub App secret of the organization named in `repository.owner.login` [1](#0-0) [2](#0-1) . Once past that check, `StatusHandler#process` looks up commits purely `Commit.where(sha: params.sha)` with no reference at all to `repository`/`payload['repository']`, so a validly-signed webhook for org A can mutate any `Commit` row with a colliding `sha`, including ones that belong to a stack under a completely different organization B [3](#0-2) .

### Finding Description
Broken binding: `repository_owner` used to select the `github_app`/secret in `verify_signature` ("attacker-org") should equal the org that owns every `Commit` row `StatusHandler#process` is about to mutate ("victim-org"), but this equality is never checked anywhere in the path.

Trace:
1. `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login')` and calls `Shipit.github(organization: repository_owner)` to fetch the App/secret for that org, then verifies `X-Hub-Signature` against `request.raw_post` using that org's secret [1](#0-0) . This only proves the request was signed by attacker-org's own webhook secret - it says nothing about which commits the payload's `sha` refers to.
2. `WebhooksController#create` parses the raw JSON and dispatches it unchanged to every registered handler for the event, including `Handlers::StatusHandler` [4](#0-3) [5](#0-4) .
3. `Handler` (the base class) exposes a `stacks`/`repository_name` helper based on `payload.dig('repository','full_name')` that other handlers (e.g. `LabelCapturingHandler`) use to scope work to the repository named in the payload [6](#0-5) . `StatusHandler` does not use this helper or `repository` at all - its `params` schema only requires `sha`, `state`, and optional fields, with no `repository` requirement [7](#0-6) .
4. `process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [3](#0-2) . `sha` is not a global unique key across all stacks/orgs in the schema (only indexed per `stack_id, sha` per the migration `db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb`), so any commit anywhere in the Shipit instance whose sha matches the attacker-supplied value gets its status mutated via `Commit#create_status_from_github!` → `statuses.replicate_from_github!`, which also fires `Hook.emit(:commit_status, ...)` / `:deployable_status` and can trigger `stack.schedule_merges` [8](#0-7) [9](#0-8) .

Exploit: Attacker owns `attacker-org` with its own registered GitHub App/webhook secret. They pick any commit `sha` that happens to also exist under `victim-org`'s stack (e.g. because it was cherry-picked/rebased, a widely-shared commit, or simply guessed/brute-forced from a public history), compute a valid `X-Hub-Signature` using attacker-org's own secret, and POST a `status` event to `/webhooks` with `repository.owner.login = "attacker-org"` and `sha = <victim's sha>`. `verify_signature` passes (signature matches attacker-org's own secret), and `StatusHandler#process` writes a forged status (`success`/`failure`/`pending`, arbitrary `description`/`target_url`) onto the victim's commit, which can unblock `deployable?`/`blocked?` gating and `schedule_continuous_delivery`, ultimately affecting deploy eligibility for a stack the attacker never authenticated for.

Existing guards do not catch this: `verify_signature` only binds the signature to the org named in the JSON body, never to the actual `Commit`/`Stack` rows touched; `ExplicitParameters` schema for `StatusHandler` doesn't require/validate `repository`; there is no `stacks`/`repository_name` scoping used inside `StatusHandler#process` unlike the base `Handler` helper that other handlers use.

### Impact Explanation
An attacker who controls only their own org's GitHub App/webhook secret can write forged CI/commit-status data (`Status` records) onto commits belonging to any other tenant's stack, provided a sha collision exists. This is a "payload for one repository mutating another's stack/commit" scenario explicitly listed as Critical impact. Forged success statuses can flip `deployable?`/`blocked?` and trigger `schedule_continuous_delivery`, which can lead to an unauthorized deploy for the victim stack. This is repeatable against any repository as long as the attacker can find/produce a matching sha, and the blast radius spans all stacks/orgs hosted by the same Shipit instance, since `Commit.where(sha:)` is queried without any tenant scoping.

### Likelihood Explanation
Preconditions are non-trivial but realistic: it requires the attacker to know or engineer a `sha` collision between a commit in their own repo/org and a commit tracked in a victim stack (e.g. via cherry-picks, common upstream commits, forked/vendored code, or a shared submodule commit that both orgs happen to have ingested into their `shipit_commits`). No Shipit or GitHub secrets belonging to the victim are required - only the attacker's own legitimately-provisioned GitHub App/webhook secret for their own org, which they can freely register. Cost to the attacker is a single signed HTTP POST; the vulnerability is deterministically reproducible once a colliding sha is known.

### Recommendation
In `StatusHandler#process` (and any other handler that mutates `Commit`/`Status` by `sha`), scope the lookup to the repository the payload actually claims and that has been authenticated, e.g. resolve `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, get its `stacks`, and restrict `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` rather than unscoped `Commit.where(sha: params.sha)`. Additionally, `WebhooksController#verify_signature` should assert that `repository_owner` derived from the payload is consistent with the actual `Stack`/`Repository` that any subsequently touched commit belongs to, not merely be used to pick which secret to verify against.

### Proof of Concept
Minitest plan (extends `test/controllers/webhooks_controller_test.rb` style, no live GitHub calls needed since signature verification is done against locally configured `Shipit.github` app secrets in test fixtures):

```ruby
test ": status webhook signed for one org can mutate a commit belonging to a different org's stack" do
  victim_stack = shipit_stacks(:shipit) # some fixture stack under org "shopify"/victim-org
  victim_commit = shipit_commits(:...)  # fixture commit belonging to victim_stack, sha = "deadbeef..."

  # simulate attacker-org's own registered GitHub App config used to sign
  @request.headers['X-Github-Event'] = 'status'
  payload = {
    sha: victim_commit.sha,
    state: 'success',
    description: 'forged status',
    context: 'ci/attacker',
    repository: { owner: { login: 'attacker-org' } } # attacker-org has its own configured webhook_secret
  }

  sign_with_attacker_org_secret(payload) # sets X-Hub-Signature using attacker-org's secret, not victim-org's

  assert_difference -> { victim_commit.statuses.count }, 1 do
    post :create, body: payload.to_json, as: :json
    assert_response :ok
  end
end
```

Assertions on both sides of the binding:
- Before: `repository_owner` computed in `verify_signature` = `"attacker-org"`; the `Commit` mutated (`victim_commit`) belongs to `victim-org`'s stack — these differ, and the code makes no equality check between them.
- After: `victim_commit.statuses.count` increased, proving org A's authenticated webhook mutated org B's commit despite `repository_owner` ("attacker-org") never being validated against the owning org of `victim_commit.stack` ("victim-org").

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
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

**File:** app/models/shipit/webhooks.rb (L6-23)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```
