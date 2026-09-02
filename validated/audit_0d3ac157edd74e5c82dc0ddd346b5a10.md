### Title
Webhook signature verification uses a different organization key than the repository the payload actually writes to - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App / `webhook_secret` used to authenticate an inbound webhook based on `repository.owner.login` (falling back to `organization.login`), while every webhook `Handler` (via `Handler#repository_name`) determines the `Repository`/`Stack` that is actually mutated using the independent field `repository.full_name`. These two payload fields are never cross-checked against each other, breaking the intended binding: `organization that authenticated == organization that owns the repository being written`.

### Finding Description
`verify_signature` computes the verification key from the payload itself, before trusting the payload's content: [1](#0-0) 

`repository_owner` is read straight out of the untrusted JSON body: [2](#0-1) 

Meanwhile every handler resolves the repository/stack that will actually be acted on from a *different* field of the same payload, `repository.full_name`, with no dependency on `repository.owner.login`: [3](#0-2) [4](#0-3) 

Because Shipit supports multiple GitHub organizations, each with its own independently configured `webhook_secret` (`config/secrets*.yml` shows multiple orgs each carrying their own `webhook_secret`), the HMAC signature only proves "this payload was signed with Org X's secret" — it does not prove "the repository referenced inside this payload belongs to Org X." An HMAC is computed over the entire raw body, so whoever holds Org X's `webhook_secret` can sign *any* JSON body, including one where `repository.owner.login`/`organization.login` says `"OrgX"` (to pass `verify_signature`) but `repository.full_name` says `"OrgY/some-repo"` (the actual target acted on by `PushHandler`, `ClosedHandler`, `OpenedHandler`, etc., all of which call `Shipit::Repository.from_github_repo_name(params.repository.full_name)`).

This is exactly the underflow-report's bug class translated to this codebase: a field checked by the trust/authorization step (`repository.owner.login`) is not the same field that later code acts on (`repository.full_name`), so the two are silently allowed to diverge.

### Impact Explanation
An entity that legitimately controls one organization's `webhook_secret` (an org admin who configured their own GitHub App installation in Shipit, which is the expected non-privileged trust boundary between different tenant organizations of the same Shipit instance) can forge webhook deliveries whose signature is valid for their own org but whose `repository.full_name` points at a stack belonging to a *different* organization hosted by the same Shipit instance. Reachable effects include:
- `PushHandler` → `stack.sync_github(expected_head_sha:)` on another org's stack, poisoning the commit history Shipit believes is on GitHub for that stack.
- `PullRequest::OpenedHandler`/`ClosedHandler` provisioning or archiving review stacks belonging to another org's repository.
- `StatusHandler`/`CheckSuiteHandler` writing fabricated CI statuses/check runs onto another org's commits, which can influence merge-queue and deploy-readiness decisions (`reject_unless_mergeable!`, `any_status_checks_failed?`) for stacks Shipit governs.

This constitutes a cross-organization/cross-repository write performed under another tenant's authentication context — matching the "Critical: cross-repository writes / unauthorized deploy" impact class, since fabricated statuses/check-runs can unblock merges or deploys on a stack the attacker does not own.

### Likelihood Explanation
Requires the attacker to already legitimately possess a `webhook_secret` for at least one organization configured on the shared Shipit instance (i.e., be a tenant admin of Org X), and for that instance to host multiple organizations/stacks (as the repo's own `secrets_double_github_app.yml` fixture demonstrates is a supported configuration). No GitHub-side privileges are required for the target repository; only the crafted HTTP POST to Shipit's `/webhooks` endpoint with a self-computed HMAC. This is a realistic multi-tenant deployment scenario for Shipit but not exploitable by a fully anonymous/unauthenticated party.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), cross-validate that the organization used to select the verification secret matches the owner segment of `repository.full_name` (and `organization.login` when present) before dispatching to any handler; reject the request if they disagree.

### Proof of Concept
1. Shipit hosts two orgs, `OrgX` and `OrgY`, each with a distinct `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. Attacker is an admin of `OrgX` and legitimately knows `OrgX`'s `webhook_secret`.
3. Attacker crafts a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "OrgX" }, "full_name": "OrgY/target-repo" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(OrgX_webhook_secret, body)` and POSTs to `/webhooks`.
5. `verify_signature` calls `Shipit.github(organization: "OrgX")` and the signature validates successfully.
6. `PushHandler#process` runs `Repository.from_github_repo_name("OrgY/target-repo")` and enqueues `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on `OrgY`'s stack, despite the request having been authenticated only against `OrgX`'s secret.

### Citations

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
