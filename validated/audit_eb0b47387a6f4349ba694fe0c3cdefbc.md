This confirms an exploitable analog to the reported bug class: the signature-verification key (`repository.owner.login` / `organization.login`) and the entity that actually gets written to (`repository.full_name`) are two independently-controlled fields inside the same unsigned-then-verified JSON body, and nothing binds them together.

### Title
Webhook signature verified against attacker's own organization while payload's `repository.full_name` targets and syncs an arbitrary victim repository - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification based on `repository.owner.login` (falling back to `organization.login`), but the actual repository that is looked up and acted upon by the event handlers is taken from a completely different, independently-controlled field: `repository.full_name`.

### Finding Description
`verify_signature` computes the signing organization purely from the payload: [1](#0-0) [2](#0-1) 

That HMAC is computed with `Shipit.github(organization: repository_owner).verify_webhook_signature`, i.e. keyed off `repository.owner.login`. Meanwhile, every handler resolves the actual repository/stacks to act on using an entirely separate field, `repository.full_name`: [3](#0-2) [4](#0-3) 

The equality the engine implicitly assumes is:
`organization that signed the payload (repository.owner.login)` == `organization/repository that the handler mutates (repository.full_name)`

Nothing enforces this. An attacker who legitimately owns a GitHub App installation on their own organization (`attacker-org`) knows that organization's `webhook_secret` and can compute a valid `X-Hub-Signature` for any JSON body they choose, because `Hook::DeliverySigner`/`verify_webhook_signature` only checks the HMAC against the raw body and the secret tied to `repository_owner` — it never checks that `repository.full_name` belongs to that same owner: [5](#0-4) 

By crafting a `push` (or `status`/`check_suite`) payload where `repository.owner.login` = `attacker-org` (so the signature check passes using the attacker's own secret) but `repository.full_name` = `victim-org/victim-repo`, the request passes `verify_signature`, then `PushHandler` resolves the stacks belonging to `victim-org/victim-repo` and triggers `stack.sync_github`: [6](#0-5) 

### Impact Explanation
This breaks the trust boundary between "which org authenticated the webhook" and "which repository's stack state gets mutated." Depending on the target handler, this allows an attacker who controls any single onboarded organization/webhook secret to force syncs, fabricate commit statuses, or manipulate check-suite/PR state for a victim organization's stacks that they have no legitimate relationship to — an unauthorized write to another repository's Shipit state, satisfying the "cross-repository writes" criterion.

### Likelihood Explanation
Requires the attacker to control (or have installed) a GitHub App with a known `webhook_secret` for at least one organization already onboarded to the Shipit instance — a realistic scenario for a multi-tenant Shipit deployment where multiple orgs self-service install the app. No repository write access, no session, and no `ApiClient` token to the victim repo are needed; only the ability to POST a crafted JSON body with a valid signature for the attacker's own org.

### Recommendation
After computing the signing organization, validate that `repository.owner.login` (or `organization.login`) matches the owner portion of `repository.full_name` before dispatching to handlers, rejecting the webhook (422) on mismatch. Alternatively, resolve the target repository/stack using the same field used for signature verification, so a single unsigned field cannot be substituted post-verification.

### Proof of Concept
1. Attacker installs/owns a GitHub App for `attacker-org` on the shared Shipit instance and knows `attacker-org`'s `webhook_secret`.
2. Attacker builds a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "attacker-org" } }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org secret, body)` and sends it with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: 'attacker-org')` and the HMAC matches → request passes.
5. `PushHandler#process` calls `Repository.from_github_repo_name('victim-org/victim-repo')` and triggers `sync_github`/`stack.sync_github(expected_head_sha: 'deadbeef')` on the victim's stack — a write triggered without any credential belonging to `victim-org`. [6](#0-5)

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
