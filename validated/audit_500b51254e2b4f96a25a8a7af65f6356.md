### Title
Cross-tenant `Status` injection via `sha`-only lookup in `StatusHandler#process` bypassing webhook org binding - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` only proves that the *body* was signed with the `webhook_secret` of whatever organization is named in the attacker-supplied `repository.owner.login` field; it never checks that org against the commit/stack that the handler is about to mutate. `StatusHandler#process` then resolves the target purely by `Commit.where(sha: params.sha)`, a global lookup across all stacks/tenants, so a caller who legitimately owns Org A can forge a `status` webhook naming Org A (passes signature check) but supplying a `sha` belonging to a commit owned by Org B's stack, writing a `Status` row onto Org B's commit.

### Finding Description
The claimed binding should be: `organization_that_signed_body == organization_owning(Commit.find_by(sha: params.sha).stack)`. Tracing the code shows this equality is never enforced.

- `WebhooksController#verify_signature` derives `repository_owner` solely from the untrusted JSON body: `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0)  and uses it to pick which org's `webhook_secret` to verify against: `Shipit.github(organization: repository_owner)` / `github_app.verify_webhook_signature(...)` [2](#0-1) . This only proves "some org whose name I claim signed this," not that the claimed org owns the repository/commit referenced elsewhere in the payload.
- After signature verification, `create` simply dispatches the parsed JSON to handlers with no further repository check: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [3](#0-2) .
- `StatusHandler#process` requires only `sha` and `state` from the payload (schema has no `repository` binding) and resolves target commits with an unscoped, cross-tenant query: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [4](#0-3) . `Commit` belongs to `stack` [5](#0-4)  but the handler never checks `commit.stack.repository`/owner against `repository_owner` from the request.
- `create_status_from_github!` then writes into `statuses` and re-evaluates deployability/CD scheduling for that commit's (foreign) stack via `add_status`, which can call `stack.schedule_merges` and `ContinuousDeliveryJob` triggers when status flips to success [6](#0-5) [7](#0-6) [8](#0-7) .

Attacker request: register/own GitHub org A onboarded to Shipit (so `webhook_secret` for A exists and attacker can produce a validly-signed body using the standard GitHub webhook flow for their own repo). POST to `/webhooks` with `X-Github-Event: status`, a body with `repository.owner.login: "A"` (or `organization.login: "A"`) and `sha` set to a known commit SHA that exists in some victim stack under org B (SHAs are often discoverable via public stack pages, PRs, or commit history, not secret). Signature verifies against A's secret. `StatusHandler` finds the commit purely by `sha`, ignoring that the request was authenticated only for org A, and injects a `success`/`failure` status onto org B's commit.

No existing guard prevents this: `drop_unhandled_event` only filters by event type; `ExplicitParameters` schema for `StatusHandler` validates payload shape, not repository ownership; there is no `force_github_authentication`/`require_permission!` equivalent inside webhook handlers (webhooks are meant to be inbound, unauthenticated-by-session, secret-authenticated-by-org only); no `Repository`/`Stack` validator restricts `Commit.where(sha:)` to a particular owner.

### Impact Explanation
An attacker controlling any single Shipit-onboarded GitHub organization can inject arbitrary CI `Status` records onto commits belonging to any other tenant's stack, as long as they know or guess a target SHA. Because `Commit#status` aggregates statuses to decide `deployable?` and `add_status` can trigger `stack.schedule_merges` and `ContinuousDeliveryJob` when a commit becomes `success`, this can be leveraged to flip a foreign stack's commit into a deployable state and trigger continuous deployment/merge scheduling — a payload from one repository mutating another tenant's commit/stack and potentially causing an unauthorized deploy, matching the Critical severity category directly. This is repeatable against arbitrary onboarded stacks/commits, limited only by the attacker's knowledge of target SHAs and by their access to any one legitimate onboarded org's webhook secret exchange (which they get for free by owning that org's repo on GitHub, since GitHub itself computes/sends the signature for their own repo's events).

### Likelihood Explanation
Preconditions: attacker's own GitHub org/repo must be onboarded into Shipit (a common self-service scenario for internal-tool/PaaS-style deployments of this engine), and the attacker needs a target SHA belonging to a different tenant's stack (commonly discoverable, e.g. via public Shipit stack UI, GitHub commit history, or PR pages). No Shipit credentials, API tokens, or another org's `webhook_secret` are required — the attacker only ever needs the secret for the org they already legitimately control, which GitHub computes for them automatically on real webhook deliveries from their own repo (or which they can compute themselves offline once known, and simply POST directly to `/webhooks`, since `verify_signature` never checks source IP or GitHub-specific transport authenticity). This is low-cost and fully repeatable.

### Recommendation
In `StatusHandler#process` (and other handlers relying on cross-referencing by `sha`), verify that the resolved `commit.stack.repository`'s owner matches the `repository_owner` that was used to select the `webhook_secret` in `verify_signature`, e.g. by passing the verified `repository_owner`/`repository.full_name` through to handlers and filtering `Commit.where(sha: params.sha, stack: Stack.where(repository: matching_repo))` before creating statuses. More generally, `WebhooksController` should also enforce that `params.dig('repository','full_name')` matches an actual known `Repository` before dispatch, not merely that its owner org has a matching secret.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "#create status event from org A cannot inject a Status onto org B's commit" do
  stack_a = shipit_stacks(:shipit) # owned by org "shopify" (org A)
  stack_b = create_stack!(repository: create_repository!(owner: 'other-org', name: 'other-repo')) # org B

  commit_b = stack_b.commits.create!(sha: '1' * 40, message: 'victim commit')

  Shipit::GitHubApp.any_instance.stubs(:verify_webhook_signature).returns(true)

  payload = {
    repository: { owner: { login: 'shopify' } }, # org A, whose secret "verified" this request
    sha: commit_b.sha,
    state: 'success',
    context: 'ci/attacker'
  }.to_json

  post :create, body: payload, params: {}, headers: {
    'X-Github-Event' => 'status',
    'X-Hub-Signature' => 'sha1=whatever'
  }

  assert_response :ok
  commit_b.reload
  # FAILS the intended binding: a request authenticated only for org A
  # (stack_a's owner) wrote a Status onto stack_b's (org B's) commit.
  assert commit_b.statuses.where(context: 'ci/attacker', state: 'success').exists?,
    "expected forged status to land on org B's commit despite signature only proving org A ownership"
end
```
This demonstrates that `repository_owner` used for `verify_signature` (org A / "shopify") diverges from the actual owner of `commit_b.stack` (org B / "other-org"), yet the `Status` write succeeds — confirming the broken WEBHOOK PROVENANCE binding.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-24)
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

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L11-11)
```ruby
    belongs_to :stack
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
