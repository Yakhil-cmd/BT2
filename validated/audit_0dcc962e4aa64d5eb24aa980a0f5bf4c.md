### Title
Webhook signature verification is bound to an attacker-chosen organization while the mutated repository/commit is bound to a different, attacker-chosen value - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against by reading `repository.owner.login` (or `organization.login`) straight out of the untrusted JSON body. The handlers that actually act on the payload (`PushHandler`, `StatusHandler`, etc.) independently re-parse the same untrusted body to decide *what* to mutate (`repository.full_name`, or a bare `sha` lookup with no repository scoping at all). Because these two reads of the same attacker-controlled JSON are never checked for consistency, an attacker can pick one organization to satisfy signature verification and a completely different repository/stack to actually write to.

### Finding Description
`verify_signature` computes the organization used for HMAC verification purely from the request body: [1](#0-0) [2](#0-1) 

`verify_webhook_signature` itself skips verification entirely whenever the selected organization has no configured `webhook_secret`: [3](#0-2) 

Meanwhile, every handler derives *what gets mutated* from a completely separate field of the same JSON body, with no cross-check against the value used for signature verification: [4](#0-3) [5](#0-4) 

`StatusHandler` is even more permissive: it looks up commits globally by SHA with no repository/organization scoping whatsoever: [6](#0-5) 

The invariant the code should enforce — `organization used to verify signature == organization owning the repository/commit being mutated` — is never checked. Since `repository.owner.login` and `repository.full_name` are independent JSON fields in the same POST body, an attacker can submit `repository.owner.login = "org-with-no-webhook-secret"` (or any org whose secret is known/guessable) together with `repository.full_name = "victim-org/victim-repo"` and `sha = "<real commit sha of the victim stack>"`. `verify_signature` passes (because that decoy org has no `webhook_secret`, per the `return true unless webhook_secret` fast path), but `StatusHandler`/`PushHandler` act on the victim repository's commit/stack.

### Impact Explanation
This breaks the binding between "the organization that authenticated the webhook" and "the repository that is written," which is explicitly one of the trust boundaries in scope. Concretely:
- An attacker who knows (or can find, e.g. via a permissive multi-tenant `config/secrets.*.yml` where `webhook_secret` is left blank for some configured org) any organization slot with no `webhook_secret` can forge a `status` webhook event that passes signature verification, yet have `StatusHandler` create a fabricated `success` `Status` on any commit SHA in the system, regardless of which repository/org actually owns it.
- If the targeted stack has `continuous_deployment` enabled and relies on that status check, this can lead to an **unauthorized deploy** being triggered from a forged, unauthenticated status, and more generally to cross-repository writes into any stack's commit/status data.

### Likelihood Explanation
The webhook endpoint is unauthenticated by design (it exists specifically to receive GitHub-signed events), so any unprivileged attacker on the network can POST directly to it — no `ApiClient` token, session, or repository write access is required. The only precondition is the existence of at least one configured GitHub organization without a `webhook_secret` (shown as the default/example in `config/secrets.development.shopify.yml`) or knowledge of one org's secret; multi-tenant Shipit deployments commonly configure several organizations, so this is a realistic misconfiguration rather than a theoretical one.

### Recommendation
Bind signature verification to the same repository/organization the handler will act on: derive `repository_owner` once, verify the signature against it, and have every handler validate that `payload.dig('repository', 'full_name')` (and any `sha`/`branches` used to look up records) actually belongs to a `Repository`/`Stack` owned by that same verified organization before mutating anything. `StatusHandler` in particular must scope its `Commit` lookup to the repository/stack corresponding to the verified organization instead of searching all commits by SHA globally.

### Proof of Concept
1. Configure (or find, in a multi-tenant install) an organization `decoy-org` in `Shipit.github` with no `webhook_secret` set.
2. POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "decoy-org" }, "full_name": "victim-org/victim-repo" },
  "sha": "<known sha of a commit belonging to victim-org/victim-repo's stack>",
  "state": "success",
  "branches": [{ "name": "master" }]
}
```
3. `verify_signature` calls `Shipit.github(organization: "decoy-org").verify_webhook_signature(...)`, which returns `true` immediately because `decoy-org` has no `webhook_secret` (`lib/shipit/github_app.rb:77`), regardless of the actual `X-Hub-Signature` header sent.
4. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:21-23`) finds the commit purely by `sha`, unscoped to `decoy-org`, and creates a forged `success` status on it, potentially unblocking a deploy on `victim-org/victim-repo`'s stack.

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
