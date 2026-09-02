### Title
Webhook signature is verified against `repository.owner.login`, but the acted-upon repository is resolved from `repository.full_name` — allowing cross-organization webhook forgery in multi-org deployments - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a Shipit deployment configured with multiple GitHub Apps (one per GitHub organization, as documented for multi-org setups), the webhook signature check binds trust to the wrong field of the incoming payload. `WebhooksController#verify_signature` picks which organization's `webhook_secret` to validate the HMAC against using `repository_owner`, which is read straight out of the unauthenticated JSON body. All downstream webhook handlers, however, resolve which `Repository`/`Stack` to act on using a *different* field of that same body — `repository.full_name`. Because these two fields are never cross-checked, an attacker who legitimately controls (and thus can read/rotate) the `webhook_secret` for *any* one organization configured in this Shipit instance can forge a validly-signed webhook whose `owner.login` matches their own organization but whose `full_name` names a target repository belonging to a *different* organization.

### Finding Description
`verify_signature` derives the signing key from a payload-controlled organization: [1](#0-0) [2](#0-1) 

`repository_owner` is taken verbatim from `params.dig('repository', 'owner', 'login')` — a field inside the very body whose authenticity is what's being checked — and used to pick the `GitHubApp` (and thus which `webhook_secret`) to verify against. In a multi-org configuration each organization has its own independent `webhook_secret` (documented in `docs/setup.md:181-216`), so if the signature validates it only proves the request was signed with *that organization's* secret — it says nothing about which repository the rest of the payload claims to describe.

Every webhook handler, however, determines the target repository from a separate field, `repository.full_name`, which is not tied back to the `owner.login` used for signature selection: [3](#0-2) [4](#0-3) [5](#0-4) 

Nothing enforces `full_name.split('/').first == repository.owner.login`, and nothing enforces that the organization used to select the secret is the organization that owns the target `Repository` record. This breaks the binding "the organization whose credential authenticated the request" == "the repository the request is allowed to act on."

### Impact Explanation
An attacker who administers (or is a member with settings access to) any single GitHub organization onboarded to a multi-org Shipit instance can read that organization's own webhook secret from its GitHub App settings (a routine, non-privileged action for an org admin over their *own* org — they hold no Shipit session, `ApiClient` token, or access to any other organization). Using that secret, they can sign an arbitrary JSON body and set `repository.owner.login` to their own org (so `verify_signature` succeeds) while setting `repository.full_name` to `victim-org/victim-repo`. This lets them forge, for example:
- `push` events (`PushHandler`) causing `stacks.sync_github(expected_head_sha: ...)` to run against the victim's stack with an attacker-chosen SHA,
- `status` events (`StatusHandler`, which inherits the same `repository_name` resolution) to write arbitrary CI/commit status onto the victim repository's commits.

This is a cross-repository write into an organization the attacker does not control, achieved purely by controlling a different organization's webhook credential — matching the "cross-repository writes" / "unauthorized deploy" impact class, since forged push/status data can influence what commit is treated as green and eligible for continuous deployment on the victim stack.

### Likelihood Explanation
Requires only that the Shipit instance is configured for multiple GitHub organizations (a supported and documented configuration) and that the attacker administers one of those organizations' GitHub App — a routine trust level far below "repository write access" or "Shipit session" on the victim's side. No interaction with the victim organization or its GitHub App is needed at all.

### Recommendation
After signature verification succeeds, re-derive the organization from the *verified* signing key rather than trusting `repository.owner.login`/`organization.login` from the body for anything else. Enforce that the repository resolved via `full_name` belongs to the same organization whose `webhook_secret` validated the signature (e.g., compare `full_name.split('/').first` against the organization key used in `Shipit.github(organization: ...)`), and reject the webhook otherwise.

### Proof of Concept
1. Deploy Shipit configured with two organizations, `org-a` and `org-b`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md` "Using Multiple Github Applications").
2. As an administrator of `org-a`, retrieve `org-a`'s `webhook_secret` from GitHub App settings.
3. Craft a `push` payload:
```json
{
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" },
  "ref": "refs/heads/master",
  "after": "deadbeefcafef00d..."
}
```
4. Compute `X-Hub-Signature: sha1=HMAC(org-a-webhook-secret, body)` and POST to `/webhooks` with `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"org-a"`, fetches `org-a`'s `GitHubApp`, and the signature validates (`app/controllers/shipit/webhooks_controller.rb:24-30`).
6. `PushHandler#process` resolves the target via `payload.dig('repository', 'full_name')` = `"org-b/victim-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`) and calls `stack.sync_github(expected_head_sha: "deadbeefcafef00d...")` on `org-b`'s stack, despite the request never being signed by `org-b`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
