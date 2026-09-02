### Title
Webhook signature is authenticated against `repository.owner.login`, but the event is applied to whatever repository `repository.full_name` names - cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` picks the GitHub App/secret to validate an inbound webhook against using `repository.owner.login` (or `organization.login`) from the JSON body, while every `Webhooks::Handlers::Handler` subclass resolves the target `Stack`/`Repository` to mutate using the independent `repository.full_name` field from the very same body. Because HMAC verification only proves "this body was signed with *some* configured organization's secret," not "the organization that signed it owns the repository referenced elsewhere in the body," an attacker who can obtain (or who is simply not required to have, when a secret is blank) one organization's webhook secret can forge a payload whose `repository.full_name` points at an entirely different organization's stack.

### Finding Description
`verify_signature` derives the authenticating organization strictly from `repository.owner.login`: [1](#0-0) 

That is the only value used to select the `GitHubApp` (and hence the `webhook_secret`) used for HMAC verification: [2](#0-1) 

Signature comparison itself is otherwise sound (`SecureCompare.secure_compare`), but note it degrades to an automatic pass when no secret is configured for that organization: [3](#0-2) 

Once verification passes, `Webhooks.for_event(event).each { |handler| handler.call(params) }` runs handlers over the full, attacker-controlled `params` hash: [4](#0-3) 

Every handler's target repository/stack lookup, however, is keyed off a *different* field of the same body — `repository.full_name` — with no cross-check that its owner matches the organization that authenticated the request: [5](#0-4) 

`Repository.from_github_repo_name` performs a plain lookup by owner/name parsed out of `full_name`, again independent of `repository.owner.login`: [6](#0-5) 

Concretely, `PushHandler` uses this `stacks` helper to trigger a GitHub sync on whatever stacks match `repository.full_name`: [7](#0-6) 

**Binding broken (equality that should hold but doesn't):**
`organization_that_authenticated(repository.owner.login)` == `organization_owning(repository.full_name)`.

The engine explicitly supports multiple GitHub App configurations keyed per-organization (`lib/shipit.rb#github_app_config`, `docs/setup.md` "Using Multiple Github Applications"), each with its own `webhook_secret`. This is precisely the deployment scenario in which the two fields can diverge: an attacker who legitimately controls (or is the admin of) one configured organization's GitHub App — and therefore possesses that organization's `webhook_secret` — can sign a payload where `repository.owner.login` is set to their own organization (so verification passes using their own secret) while `repository.full_name` is set to `"other-org/other-repo"` (so the handler acts on a stack belonging to a completely different, unrelated organization). The same bypass is unconditional (no secret needed at all) for any organization configured with a blank/absent `webhook_secret`, per `verify_webhook_signature`'s `return true unless webhook_secret`.

### Impact Explanation
This breaks the deployment-trust boundary between "the organization whose credentials authorized this webhook" and "the repository whose Shipit state gets mutated." Concretely reachable, unauthenticated-by-target-org actions include:
- Forcing `GithubSyncJob`/`stack.sync_github` to run against a victim organization's stack (`PushHandler`), and, depending on which other registered handlers key solely off `repository.full_name`/commit SHA supplied in the same forged body (e.g. commit-status/check-run driven handlers), potentially influencing CI/deployability state (`Commit#deployable?`) that gates `Stack.schedule_continuous_delivery`, i.e. a cross-repository write that can contribute to an unauthorized deploy.
- At minimum, this is an unauthenticated cross-organization/cross-repository write: an entity that should have no ability to touch another organization's Shipit stack can trigger stack-state-changing webhook handlers against it, satisfying the "cross-repository writes" High-impact category.

I was not able to fully enumerate every registered `Webhooks::Handlers` subclass's write behavior (e.g., the exact commit-status/check-run handler implementations) within the remaining investigation budget, so the maximal severity (whether it reaches automatic unauthorized deploy) is not fully confirmed — only the cross-organization/cross-repository write via the shared `Handler#stacks` resolution path is confirmed by the code cited above.

### Likelihood Explanation
Any installation using the documented multi-organization GitHub App configuration (`docs/setup.md`, "Using Multiple Github Applications") is affected as soon as the attacker legitimately controls one configured organization (a normal, non-privileged tenant of a shared Shipit instance) — no theft of another tenant's secret is required, only crafting `repository.full_name` to name a different tenant's repo. Installations that leave `webhook_secret` blank for any organization are affected unconditionally by any unauthenticated network client.

### Recommendation
In `WebhooksController#verify_signature` / `Webhooks::Handlers::Handler`, require that the organization used to select the verifying `GitHubApp` and the organization implied by `repository.full_name` (and `organization.login`, when present) are the same value before dispatching to handlers; reject the request otherwise. Equivalently, derive the target repository lookup from the same authenticated organization rather than trusting an independent, unchecked field of the same JSON body.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` (attacker is an installer/admin, knows `webhook_secret_A`) and `victim-org` (owns `victim-org/prod-stack`, uses `webhook_secret_B` unknown to the attacker).
2. Attacker POSTs to `/webhooks` with:
   - `X-Github-Event: push`
   - Body: `{"repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/prod-stack"}, "ref": "refs/heads/master", "after": "<attacker chosen sha>"}`
   - `X-Hub-Signature: sha1=<HMAC computed with webhook_secret_A over that body>`
3. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and verifies successfully using `webhook_secret_A`, which the attacker legitimately possesses.
4. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/prod-stack")`, matching the victim's real `Stack`, and calls `stack.sync_github(expected_head_sha: "<attacker chosen sha>")` — a write triggered on `victim-org`'s stack despite the request only ever being authenticated against `attacker-org`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
