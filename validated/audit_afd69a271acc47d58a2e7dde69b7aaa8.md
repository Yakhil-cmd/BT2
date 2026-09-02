### Title
Webhook signature verification is scoped to `repository.owner.login`, but write targets are resolved from the independent `repository.full_name` field, enabling cross‑organization writes - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
In a multi-tenant Shipit deployment (multiple GitHub organizations configured under `secrets.github`, each with its own `webhook_secret`), the webhook signature is verified against the secret selected by `repository.owner.login` (or `organization.login`) taken from the JSON body, while the actual database write target — the `Repository`/`Stack` that handlers mutate — is resolved from a **different**, independently-controlled field: `repository.full_name`. An attacker who legitimately controls one tenant organization's GitHub App/webhook secret can forge a webhook body whose `repository.owner.login` matches their own org (so it passes signature verification) while `repository.full_name` points at a victim organization's repository, causing Shipit to act on that victim's `Stack` records.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App config — and therefore the HMAC secret used to verify `X-Hub-Signature` — using: [1](#0-0) 

```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
which feeds: [2](#0-1) 

But the base `Handler` class, used by every webhook handler (`PushHandler`, `StatusHandler`, `MembershipHandler`, pull-request handlers, etc.), resolves the resource that is actually written to using a **different** JSON field, `repository.full_name`: [3](#0-2) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```
`Repository.from_github_repo_name` looks up any repository/owner pair in the database: [4](#0-3) 

Because `repository.owner.login` (used for authentication/secret selection) and `repository.full_name` (used for resolving which `Stack`s get mutated) are two independent keys inside the same signed JSON body, an attacker who controls the webhook secret for **one** tenant organization can construct an arbitrary payload where these two fields disagree. The HMAC only proves "this body was signed with organization A's secret" — it says nothing about which organization's data the body claims to describe. Handlers such as `PushHandler#process` then call `stack.sync_github(expected_head_sha: params.after)` on whatever `Stack` was resolved from the mismatched `full_name`: [5](#0-4) 

and `StatusHandler#process` creates commit statuses for arbitrary commits matched by SHA, independent of which org's secret validated the request: [6](#0-5) 

The binding that should hold is:
`organization whose webhook_secret authenticated the request == organization that owns the repository/stack being written`

This binding is broken because the authentication step and the write-resolution step each independently trust a different field of the same untrusted, attacker-suppliable JSON body.

### Impact Explanation
This crosses the tenant boundary explicitly called out as unauthorized-write / cross-repository-write impact: an attacker holding valid webhook credentials for organization A can trigger `GithubSyncJob`s, inject fabricated commit statuses (which can flip `deployable?`/CI-gating checks that guard deploys), or drive other handler side effects (e.g., membership/team churn, pull-request label/close events feeding review-stack provisioning) against a completely unrelated organization B's stacks/repositories that they have no legitimate relationship with. This matches the "cross-repository writes" / "unauthorized deploy" impact category.

### Likelihood Explanation
Requires the attacker to already control a legitimate webhook secret for at least one organization configured on the shared Shipit instance (a realistic scenario for any Shipit install serving more than one GitHub organization/team, since each org owner independently manages their own GitHub App). No access to the victim organization's secret, GitHub App private key, or a Shipit user session/API token is required — only the ability to send a crafted HTTP POST to the shared `/github/webhooks` endpoint using credentials the attacker legitimately possesses for their own tenant.

### Recommendation
Verify that the organization used to select/verify the webhook secret is the same organization that owns the resolved `Repository`/`Stack`. Concretely, in `Handler#repository_name`/`stacks`, re-derive the owning organization from the same trusted context established during signature verification (or pass the verified `repository_owner` into the handler and assert it equals the owner portion of `repository.full_name` before doing any lookup), rejecting the payload if they disagree.

### Proof of Concept
1. Shipit instance is configured with two organizations, `org-a` and `org-b`, each with its own `github.webhook_secret` in `secrets.yml`.
2. Attacker is the legitimate owner/admin of `org-a`'s GitHub App and therefore knows `org-a`'s `webhook_secret`.
3. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature` using `org-a`'s `webhook_secret` over this exact raw body and POSTs it to `/github/webhooks`.
5. `WebhooksController#repository_owner` returns `"org-a"`, `Shipit.github(organization: "org-a")` is used, and `verify_webhook_signature` succeeds because the attacker used the correct secret for `org-a`.
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("org-b/victim-repo")`, finds `org-b`'s stacks, and calls `stack.sync_github(expected_head_sha: "deadbeef...")`, causing Shipit to act on `org-b`'s repository/stack state despite the request having been authenticated only against `org-a`'s credentials.

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
