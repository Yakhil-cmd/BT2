### Title
Webhook signature is bound to `repository.owner.login`, but write actions are keyed off unverified `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, taken directly from the untrusted JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`). Every downstream handler, however, decides *which* `Repository`/`Stack` to act on using a completely different field of the same, single unverified body: `payload.dig('repository', 'full_name')`. Nothing cross-checks that these two fields refer to the same repository/organization.

### Finding Description
`Shipit::WebhooksController#verify_signature` computes the expected HMAC using the secret configured for `repository_owner`: [1](#0-0) [2](#0-1) 

The secret comes from a per-organization config resolved via `Shipit.github(organization: ...)`; `verify_webhook_signature` just HMACs the raw body with that organization's own `webhook_secret`: [3](#0-2) 

`Shipit::Webhooks::Handlers::Handler`, the base class every event handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, `PullRequest::*Handler`, etc.) inherits from, resolves the target repository/stacks from a *different* JSON field, `repository.full_name`: [4](#0-3) [5](#0-4) 

Because the whole raw body is HMAC'd, any attacker who controls (or has been issued) a valid `webhook_secret` for **one** organization configured on the Shipit instance (`Shipit.github(organization: "org-a")`) can compute a valid signature for **any** body content they choose — including one whose `repository.owner.login`/`organization.login` says `"org-a"` (so `verify_signature` picks org‑A's secret and the HMAC checks out) while `repository.full_name` says `"org-b/some-repo"` (so the handler resolves and mutates a stack belonging to an entirely different organization/repository). The equality that should hold — *the organization whose secret authenticated the request* == *the organization/repository whose stacks are written to* — is never enforced.

### Impact Explanation
This lets an attacker who legitimately controls one organization's GitHub App/webhook installation on a shared Shipit instance forge events that mutate state belonging to a different organization's repositories/stacks, e.g.:
- `PushHandler` triggers `stack.sync_github(expected_head_sha:)` for any matching branch/stack: [6](#0-5) 
- `StatusHandler` creates commit statuses for arbitrary shas across repos: [7](#0-6) 
- Pull-request handlers can provision, archive/unarchive, and deprovision Review Stacks (i.e., trigger infrastructure automation) for a repository the forged signature was never actually issued for, as seen in the labeled/unlabeled/reopened handler tests exercising `assert_pending_provision`/archival behavior.

This is a cross-repository/cross-organization write achieved purely by exploiting the mismatch between the field used for signature-authorization and the field used for target resolution — meeting the "cross-repository writes" Critical bar.

### Likelihood Explanation
Requires the Shipit instance to host more than one organization/repository configuration (each with its own `webhook_secret`, which the engine explicitly supports via `Shipit.github(organization:)`), and requires the attacker to control (or be entitled to send signed webhooks for) at least one of those organizations. Within that realistic shared/multi-tenant deployment model, no additional privilege, `ApiClient` token, or Shipit session is needed — only the ability to send an HTTP POST with a self-computed signature.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), enforce that the organization used to select/verify the webhook secret is the same organization embedded in `repository.full_name` (and `organization.login`, when present) before any handler acts on the payload. Reject the request if they disagree.

### Proof of Concept
1. Shipit instance hosts two orgs: `org-a` (webhook secret known to attacker, e.g. attacker's own installation) and `org-b` (victim, unrelated repo/stack).
2. Attacker crafts a `pull_request` (or `push`) webhook body with:
   - `repository.owner.login` = `"org-a"`
   - `repository.full_name` = `"org-b/victim-repo"`
3. Attacker computes `X-Hub-Signature: sha1=HMAC(org_a_secret, raw_body)`.
4. `verify_signature` resolves `Shipit.github(organization: "org-a")` from `repository_owner` and successfully verifies the signature [1](#0-0) .
5. The event dispatches to the relevant handler, which resolves stacks via `repository.full_name` = `"org-b/victim-repo"` [4](#0-3) , causing writes (sync, status creation, review-stack provisioning) against `org-b`'s stack despite the signature only proving possession of `org-a`'s secret.

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
