### Title
Webhook signature is verified against `repository.owner.login`, but the acted-upon repository is looked up from the independent `repository.full_name` field, allowing cross-organization forged webhooks - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to validate the HMAC signature against using `params.dig('repository', 'owner', 'login')` (or `organization.login` as fallback), but every webhook handler resolves the actual `Repository`/`Stack` to operate on using a *different*, independently-controlled JSON field: `payload.dig('repository', 'full_name')`. Because these two fields are never cross-checked, a party who knows the `webhook_secret` for one configured organization can forge a request whose `repository.owner.login` matches that organization (satisfying signature verification) while `repository.full_name` names a completely different organization's repository, causing Shipit to act on a stack that the presented credential was never authorized for.

### Finding Description
The controller computes trust based on one payload field and the engine acts based on another, unrelated payload field within the same unauthenticated JSON body: [1](#0-0) 

`verify_signature` uses `repository_owner` (from `repository.owner.login`) purely to pick which `Shipit.github(organization: ...)` webhook secret to HMAC-verify against: [2](#0-1) 

Once the signature check passes, `create` dispatches the raw, attacker-supplied JSON to the relevant handler(s) unmodified: [3](#0-2) 

Every handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, pull-request handlers, etc.) inherits `Handler#stacks`/`Handler#repository_name`, which resolves the target `Repository` from a *different* field, `repository.full_name`, with no requirement that it be consistent with `repository.owner.login`: [4](#0-3) 

`Repository.from_github_repo_name` simply splits `owner/name` out of that string and looks up the record directly: [5](#0-4) 

For example, `PushHandler#process` uses `stacks` (derived from `full_name`) to trigger `stack.sync_github(expected_head_sha: params.after)` on whichever stacks match, entirely independent of which org's secret validated the request: [6](#0-5) 

The equality binding this breaks is:
`organization authenticated by verify_signature (repository.owner.login / organization.login)` ≠ `repository whose Stack is written/acted on (repository.full_name)`.

Before the attack: an attacker who knows the `webhook_secret` for organization A (e.g. because they administer a GitHub App/webhook for org A that is registered in this Shipit instance, or the secret otherwise leaked to them) can only affect stacks belonging to org A, since GitHub itself keeps `repository.owner.login` and `repository.full_name` consistent when generating real webhook deliveries.

After the attack: the attacker POSTs directly to `/github_authentication`... actually to the webhooks endpoint (`WebhooksController#create`), crafting a raw JSON body where `repository.owner.login = "org-a"` (so the HMAC is computed/verified with org A's known secret) but `repository.full_name = "org-b/private-repo"`. The signature check passes because it only validates the org-A secret over the raw body; the handler then resolves and mutates org B's `Stack` (e.g. queuing `GithubSyncJob`, updating commit `Status`, closing/opening PR-linked `MergeRequest` records, refreshing check runs) even though the attacker never had org B's webhook secret or any authorization over org B's repository.

### Impact Explanation
This crosses the "organization authenticated versus the repository that is written" boundary explicitly called out in scope. Depending on the event type forged, the impact includes unauthorized manipulation of another organization's `Stack` state: injecting fake commit statuses via `StatusHandler` (potentially unblocking deploy gating for another org's stack), triggering `GithubSyncJob`/`RefreshCheckRunsJob` against another org's repository, or manipulating `MergeRequest`/`ReviewStack` lifecycle records (via the pull_request handlers) tied to a repository the attacker does not control. This constitutes a cross-organization/cross-repository write performed with credentials scoped to a different repository, matching the "cross-repository writes" High/Critical impact category.

### Likelihood Explanation
Exploitability requires the attacker to legitimately know (or be entrusted with) the `webhook_secret` of at least one organization configured in this Shipit instance — a realistic scenario for any multi-tenant deployment where multiple GitHub organizations/teams share one Shipit engine and each org administrator independently manages their own App/webhook secret. No GitHub App private key, `GITHUB_TOKEN`, or Shipit session is needed; only knowledge of one org's `webhook_secret`, which by design is distributed to a broader circle (whoever configures the GitHub webhook for that org) than the org whose stacks get mutated. This is a direct, low-effort exploitation path: a single forged HTTP POST with a correctly computed HMAC over an inconsistent payload.

### Recommendation
In `WebhooksController#verify_signature`, and/or in `Shipit::Webhooks::Handlers::Handler`, enforce that the organization used to select the verification secret is the same organization embedded in `repository.full_name` (i.e., `repository.full_name.split('/').first` must equal `repository.owner.login`/`organization.login`), rejecting the webhook with `422` on mismatch. Alternatively, verify the signature per-repository (scoped to the exact `Repository` resolved by `full_name`) rather than per-organization derived from a separate, unchecked field.

### Proof of Concept
1. Configure (or compromise) org A's `webhook_secret` = `S_A`, known to the attacker; org B is a different organization also configured in the same Shipit instance with a private stack `org-b/secret-repo`.
2. Attacker crafts a raw JSON push payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/secret-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC_SHA1(S_A, raw_body)` and POSTs to the webhooks endpoint with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` computes `repository_owner = "org-a"`, fetches `Shipit.github(organization: "org-a")`, and the signature verifies successfully [7](#0-6) .
5. `PushHandler` resolves `stacks` via `payload.dig('repository', 'full_name')` = `"org-b/secret-repo"` [4](#0-3) , and calls `stack.sync_github(expected_head_sha: "deadbeef")` on org B's stack [6](#0-5) , even though the attacker only ever proved knowledge of org A's secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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
