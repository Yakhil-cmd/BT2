### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but handlers act on an independently-supplied `repository.full_name` — allowing cross-repository/cross-organization forged webhooks - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate an inbound webhook's HMAC against by reading `repository.owner.login` (or `organization.login`) out of the *same, attacker-controlled* JSON body it is trying to authenticate. Every event handler, however, resolves the target `Stack`/`Repository`/`Commit` to write to using a *different* field from that same body: `payload.dig('repository', 'full_name')`. Nothing ties these two fields together, so an attacker who legitimately controls one onboarded GitHub organization (and therefore knows that organization's `webhook_secret`) can forge a signature that only proves "this org's secret signed this body," while pointing `repository.full_name` at a Stack belonging to a completely different, unrelated tracked repository/organization.

### Finding Description
`verify_signature` computes the org used for HMAC verification directly from request-body content: [1](#0-0) [2](#0-1) 

The webhook secret itself is scoped per organization (Shipit explicitly supports multiple GitHub Apps/organizations, each with its own `app_id`/`webhook_secret`, as documented in `docs/setup.md`'s "Using Multiple Github Applications" section), so `Shipit.github(organization: repository_owner)` returns a distinct, org-specific secret the attacker can legitimately possess for their own onboarded org.

Once the signature passes, `create` dispatches the parsed payload to handlers unmodified: [3](#0-2) 

All handlers derive their target repository/stack from a *different* payload field, `repository.full_name`, with no cross-check against `repository.owner.login`/the organization whose secret validated the request: [4](#0-3) 

Concretely: `PushHandler` looks up stacks via `Repository.from_github_repo_name(repository_name)` and calls `stack.sync_github(expected_head_sha: params.after)` on them, and `StatusHandler` creates commit statuses for any `Commit` matching an attacker-chosen `sha`, regardless of which repository it belongs to: [5](#0-4) [6](#0-5) 

This is analogous to the Aloe finding's root cause: two different code paths are supposed to represent "the same" quantity/identity (there, asset composition at average vs. current price; here, "the organization that authenticated" vs. "the repository that is written"), but they are computed independently from inputs that can diverge, and the security-relevant check (liquidation incentive / signature validity) is bound to only one of them.

**Before the attack (intended invariant):** `organization_that_signed == owner(repository_that_is_written)`, i.e., a valid signature from org A should only ever authorize handlers to act on repositories that actually belong to org A.

**After the attacker's forged request:** `repository.owner.login = "attacker-org"` (used solely to pick the secret and pass `verify_signature`), while `repository.full_name = "victim-org/victim-repo"` (used by every handler to select the `Stack`/`Commit` to mutate). The two no longer match, and nothing in the code enforces that they must.

### Impact Explanation
An attacker who legitimately owns/administers one GitHub organization onboarded into a shared Shipit instance (a realistic multi-tenant deployment per `docs/setup.md`) can forge webhooks that are cryptographically valid (signed with their own known secret) but are processed as events for an unrelated organization's repository. This yields cross-repository writes: forcing `sync_github` on a victim stack, and injecting fabricated commit statuses (`commit.create_status_from_github!`) tied to arbitrary `sha`/`state` values on victim commits, which can influence deployability/merge checks used elsewhere in the app (e.g. `merge_status`, deploy gating). This matches the "cross-repository writes" Critical-impact category defined in scope.

### Likelihood Explanation
Requires only that the attacker control (or have legitimately been granted) one GitHub App installation/organization already onboarded to the target Shipit instance — no repository write access, no Shipit session, and no knowledge of the victim org's secret is needed, since verification always uses the secret selected by the attacker-controlled `repository.owner.login` field. This is a realistic scenario for any shared/multi-org Shipit deployment as explicitly documented.

### Recommendation
Do not derive the organization used for signature verification from an unauthenticated field that also determines the write target. Instead:
- Bind the webhook route/endpoint to a specific organization at configuration/routing time (not from payload content), or
- After verifying the signature with the organization selected from the payload, explicitly assert that `repository.full_name`'s owner matches that same verified organization before invoking any handler, rejecting the request otherwise.

### Proof of Concept
1. Attacker legitimately installs/owns a Shipit-tracked GitHub App for `attacker-org` and knows its `webhook_secret`.
2. Attacker crafts a `push` (or `status`) webhook JSON body with `repository.owner.login = "attacker-org"` but `repository.full_name = "victim-org/victim-repo"`.
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s `webhook_secret` over the raw body (per `GitHubApp#verify_webhook_signature`, `lib/shipit/github_app.rb` lines 76-83).
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` and verifies successfully since the attacker used the correct secret for that org.
5. `create` dispatches to `PushHandler`/`StatusHandler`, which resolve `Repository.from_github_repo_name("victim-org/victim-repo")` and act on victim stacks/commits, even though the signature only proved authenticity for `attacker-org`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
