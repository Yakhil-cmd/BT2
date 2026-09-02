### Title
Webhook signature is verified against `repository.owner.login`/`organization.login` while downstream handlers act on the independent, unchecked `repository.full_name` field - unsigned-field authorization bypass ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App/organization whose HMAC secret to validate against using `repository_owner`, which is read directly from the still-untrusted, attacker-supplied JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')`). Once the signature check passes, the raw `params` hash — including the `repository.full_name` field — is handed unmodified to `Shipit::Webhooks.for_event(event)` handlers (e.g. `PushHandler`), which use `repository.full_name` to resolve the target `Repository`/`Stack` and trigger actions such as enqueuing `GithubSyncJob`. [1](#0-0) [2](#0-1) 

### Finding Description
This mirrors the Timelock bug class: a value is checked/validated for one purpose (there: `success` returned from `_executeTransaction`; here: HMAC signature scoped to `repository.owner.login`) but a *different, independent* field that actually drives the side effects (`queue[txHash]=0` / `emit TransactionExecuted`; here: `repository.full_name` used to resolve which `Stack`/`Repository` is acted on) is never cross-checked against the value that was validated.

Because GitHub App webhook secrets are configured per-organization (`Shipit.github(organization: repository_owner)`), the trust boundary the code intends to enforce is: "this payload was signed by organization X, therefore it is safe to act on data about organization X's repositories." However, nothing in `verify_signature` or in the handler chain enforces that `repository.full_name`'s owner segment equals `repository_owner` used for the HMAC lookup. `repository.owner.login` and `repository.full_name` are two independent JSON fields inside the same signed body — if an app is configured with a *known/leaked or shared* secret for one org, an attacker who can produce a validly-signed payload for that org (e.g. by owning/controlling a repo under that org, or if the secret is otherwise obtainable) can set `repository.full_name` to point at a completely different org/repo that Shipit also tracks, so the HMAC check passes for org A while the actual mutation (queueing a sync job, updating commit statuses, etc.) is executed against org B's stack. [3](#0-2) 

### Impact Explanation
If exploitable, this allows cross-repository/cross-stack state manipulation (e.g. forcing a `GithubSyncJob` for a stack the attacker does not control, injecting spoofed commit statuses via `status` events, or manipulating pull-request-driven review-stack lifecycle events) despite never possessing the target organization's own webhook secret — a direct violation of the "organization that authenticated versus the repository that is written" boundary called out as in-scope, and could enable an unauthorized deploy/rollback trigger downstream.

### Likelihood Explanation
Exploitability depends entirely on whether an attacker can obtain a validly-signed payload for *some* organization configured in `Shipit.github_organizations` (e.g. because they have push access to a repo under that org, which is a much weaker requirement than access to the victim org). Since I could not fully inspect `PushHandler`/other handler implementations to confirm whether they independently re-derive or validate the owner against `repository_owner` before acting, this is reported with residual uncertainty about exploitability — the control-flow evidence in `webhooks_controller.rb` shows the signature check and the payload consumption use two different, uncorrelated fields, but I was not able to fully verify the handler-side lookup logic within the available iterations.

### Recommendation
In `verify_signature`, after computing the HMAC digest, also assert that `repository.full_name`'s owner segment (or `organization.login`) is consistent with `repository_owner` before dispatching to handlers, or better, re-verify inside each handler that the resolved `Stack`'s GitHub organization matches the organization whose secret validated the request.

### Proof of Concept
Not executed — this would require producing a validly HMAC-signed payload for an organization the tester controls, then substituting `repository.full_name` to point at a different tracked stack, and observing that `Shipit::Webhooks.for_event('push').each { |h| h.call(params) }` still processes it. This could not be demonstrated without live GitHub App credentials and is flagged for verification by a Devin session with repository access, not asserted as confirmed exploitable.

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
