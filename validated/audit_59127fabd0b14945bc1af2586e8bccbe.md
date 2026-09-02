This is exactly the binding-mismatch pattern the report highlights (a field trusted for authentication vs. a different field acted upon).

### Title
Webhook signature verified against `repository.owner.login`, but handlers act on the independently-supplied `repository.full_name` — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate the HMAC signature using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` (or `organization.login`) [1](#0-0) . It verifies the raw request body's HMAC against that org's `webhook_secret` [2](#0-1) . However, the JSON payload also independently carries `repository.full_name`, which is what every webhook handler actually uses to resolve the target `Repository`/`Stack` via `Repository.from_github_repo_name` [3](#0-2) [4](#0-3) . Because the HMAC signature only proves that "someone possessing org A's webhook secret sent this raw body," and nothing in the signature verification step cross-checks that `repository.owner.login` equals `repository.full_name`'s owner segment, an attacker who legitimately controls a GitHub App installed on their own organization (org A, i.e. they know org A's `webhook_secret` because it's their own app or they compromised it) could set `repository.owner.login = "orgA"` (to pass the secret lookup and HMAC check) while setting `repository.full_name = "orgB/some-target-repo"` in the same payload.

### Finding Description
The equality that should hold is: **organization authenticated by signature == organization owning the repository written to**. In practice: `verify_signature` authenticates using `repository_owner` (from `repository.owner.login` / `organization.login`) [5](#0-4) , but the actual mutation target is derived from `repository.full_name` via `Handler#repository_name` [6](#0-5) . These are two separate JSON fields in the same payload and are never asserted to be consistent with each other before the handler acts. In Shipit's multi-org configuration (`config/secrets.development.example.yml` shows a `github:` map keyed by org, each with its own `webhook_secret`) [7](#0-6) , this means a party with a valid webhook secret for their own installed org can craft a signature that is valid for "orgA" while pointing the effective handler logic at a repository belonging to a different org (e.g., triggering `GithubSyncJob`, pull-request/review-stack provisioning, commit status writes, or membership/team changes) that they do not control.

This mirrors the report's underlying bug class: a verifier checks one identity/field (EIP-712 signer via a payload subset) while a different, unverified field or actor context is what's ultimately used to authorize the effectful action (redemption to `receiver`). Here, the verified field (`repository.owner.login`) and the acted-upon field (`repository.full_name`) are not bound together by the signature.

### Impact Explanation
This crosses the "repository write" boundary explicitly called out as in-scope: an organization authenticated (via HMAC using its `webhook_secret`) differs from the repository actually written to by the handler. Depending on which handler is invoked, this could enqueue deploy-adjacent jobs (`GithubSyncJob`), create/mutate `Team`/`Membership` records, write commit `Status`/`CheckRun` state, or drive review-stack provisioning against a stack/repository the attacker does not administer — a cross-repository write achieved without holding write access to, or a valid webhook secret for, the target repository's real owning organization.

### Likelihood Explanation
This requires the attacker to possess (or compromise) a `webhook_secret` for *some* org configured in Shipit (e.g., their own GitHub App installation, if Shipit is configured to serve multiple orgs, as documented in `secrets.development.example.yml`) [7](#0-6) , and craft a POST to `/webhooks` with mismatched `repository.owner.login` vs `repository.full_name`. This is a realistic, low-effort scenario for any Shipit deployment that legitimately serves multiple GitHub organizations (a documented, supported configuration), since each org's app owner already has a valid secret for their own org but not for others.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), assert that the owner segment of `repository.full_name` matches `repository.owner.login`/`organization.login` before dispatching to handlers, and reject the webhook (422) on mismatch. Alternatively, always resolve the target `Repository` using the same identity field that was authenticated (`repository_owner`), rather than trusting the independently supplied `full_name`.

### Proof of Concept
1. Deploy Shipit with a multi-org config: `orgA` and `orgB` each have distinct `webhook_secret`s [7](#0-6) .
2. Attacker legitimately owns/administers a GitHub App installed on `orgA` and thus knows `orgA`'s `webhook_secret`.
3. Attacker crafts a `push` (or `pull_request`) webhook JSON body where `repository.owner.login = "orgA"` and `organization.login = "orgA"`, but `repository.full_name = "orgB/target-repo"`.
4. Attacker computes `X-Hub-Signature: sha1=HMAC(orgA_webhook_secret, raw_body)` and POSTs to `/webhooks`.
5. `verify_signature` looks up `Shipit.github(organization: "orgA")` and successfully verifies the HMAC [1](#0-0) .
6. The `create` action dispatches to the registered handler with the full payload [8](#0-7) , and the handler resolves `Repository.from_github_repo_name("orgB/target-repo")` [3](#0-2)  — acting on `orgB`'s repository despite the signature only proving knowledge of `orgA`'s secret.

**Uncertainty note:** I could not fully enumerate every handler under `app/models/shipit/webhooks/handlers/**` in this session (the index surfaced only `pull_request/*` handlers and the base `Handler` class), so I cannot state with certainty every concrete side effect (e.g., whether `push`/`status`/`membership` handlers all follow the same `repository_name` pattern) — the base class pattern strongly suggests they do, since `stacks`/`repository_name` are defined once in `Handler` and inherited, but a full confirmation would require reviewing each handler file individually, which was not completed due to the iteration limit.

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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```
