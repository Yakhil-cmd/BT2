### Title
Webhook signature verification binds the organization identity, but the acted-upon repository is taken from an unverified payload field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/HMAC secret to check against based on `repository_owner`, but every event `Handler` resolves the repository to actually mutate (`Repository.from_github_repo_name`) based on a *different* field, `repository.full_name`, taken from the very same unauthenticated JSON body. Nothing in the code enforces that the owner login used for signature selection and the `full_name` used for the write path refer to the same repository/organization.

### Finding Description
`verify_signature` computes: [1](#0-0) 
using `repository_owner`, defined as: [2](#0-1) 
i.e. `params.dig('repository', 'owner', 'login')`. This chooses which organization's `webhook_secret` (via `Shipit.github(organization: repository_owner)`) is used to HMAC-verify `request.raw_post`.

Once the signature check passes, `WebhooksController#create` dispatches the *entire raw payload* to the registered `Handler`: [3](#0-2) 

Every `Handler` subclass then resolves the stacks/repository to act on using a **different** payload field: [4](#0-3) 

There is no code path anywhere in `verify_signature` or `Handler` that asserts `payload.dig('repository','owner','login') == payload.dig('repository','full_name').split('/').first`. Both values are attacker-controlled fields inside the same POST body (the signature only proves the body wasn't tampered with after signing - it says nothing about internal consistency between these two independently-read fields).

This breaks exactly the binding called out in the rules: "an organization that authenticated versus the repository that is written." A payload can be signed correctly for organization A (using organization A's `webhook_secret`, per `repository.owner.login = "org-A"`) while `repository.full_name` names a repository belonging to organization B. The signature check authenticates "this request came from someone who knows org A's webhook secret," but the mutation is applied to whatever repository `full_name` names, with no cross-check.

### Impact Explanation
An attacker who possesses (or can obtain, e.g. by configuring a webhook they legitimately control for one org/repo covered by this Shipit instance) a valid `webhook_secret` for organization A can forge a payload where `repository.owner.login = "org-A"` (to pass HMAC verification against org A's secret) but `repository.full_name = "org-B/other-repo"`. This is then dispatched to handlers that write into stacks belonging to org B:
- `PushHandler` calls `stack.sync_github(expected_head_sha: params.after)` on org B's stacks: [5](#0-4) 
- `CheckSuiteHandler` and `StatusHandler` mutate commit/check state used to gate deploy eligibility for org B's stacks.
- `pull_request/*` handlers mutate `MergeRequest` records for org B's repositories.
- `MembershipHandler` creates/deletes `Team`/`Membership`/`User` records, potentially affecting authorization for org B.

Because Shipit's core function is to gate and trigger deploys/rollbacks based on commit/CI/merge state, forging cross-repository/cross-organization webhook events that manipulate this state can lead to bypassing CI/merge requirements and triggering unauthorized deploys on a repository the attacker does not control, satisfying the "cross-repository writes" / "unauthorized deploy" impact bar.

### Likelihood Explanation
The attacker must know a `webhook_secret` valid for at least one organization/repo hosted on the same Shipit instance - this is realistic in multi-tenant deployments where different teams/orgs each configure their own GitHub App/webhook integration against a shared Shipit instance, and a webhook secret is not equivalent to full admin/API access to other orgs' repositories. Once that precondition is met, the rest of the exploit is a simple crafted POST with mismatched `owner.login` / `full_name` fields - no further privilege is required, and the impacted repository is not the one whose credential was used.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler`), enforce that the organization derived from `repository.full_name` (or `organization.login`) matches the organization whose secret successfully verified the signature before dispatching to handlers - reject the event (422) on mismatch. Alternatively, have `Handler#repository_name` and the signature-selection logic both derive from the same single trusted field, so no independent, uncorrelated field can diverge from the one used to select the verifying secret.

### Proof of Concept
1. Attacker legitimately controls organization `org-A`'s webhook configuration on this shared Shipit instance and thus knows `org-A`'s `webhook_secret`.
2. Attacker crafts a JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "org-A" },
    "full_name": "org-B/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(org-A's webhook_secret, body)>` and sets `X-Github-Event: push`.
4. `verify_signature` computes `repository_owner => "org-A"`, loads `Shipit.github(organization: "org-A")`, and the HMAC check succeeds [1](#0-0) .
5. `create` dispatches to `PushHandler`, whose `Handler#repository_name` reads `payload.dig('repository','full_name') => "org-B/victim-repo"` [6](#0-5) , resolving and mutating `org-B`'s stacks even though the request was authenticated only against `org-A`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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
