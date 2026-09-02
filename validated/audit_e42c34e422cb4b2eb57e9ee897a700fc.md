### Title
Webhook signature verification is keyed on `repository.owner.login` while all event handlers act on `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, a field taken from the same untrusted, attacker-controlled JSON body it is trying to authenticate: `params.dig('repository', 'owner', 'login')` (with an `organization.login` fallback). Every event handler, however, resolves the repository/stack to act on from a completely different field of that same body, `repository.full_name`, via `Handler#repository_name`. These two fields are never cross-checked against each other, so the "organization whose secret authenticated the request" and "the repository that gets written to" are two independent, attacker-controlled inputs.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` does: [1](#0-0) 

It looks up the app config through `Shipit.github(organization: repository_owner)`, and `repository_owner` is derived purely from the payload: [2](#0-1) 

`verify_webhook_signature` in `lib/shipit/github_app.rb` explicitly no-ops when the resolved organization's `webhook_secret` is blank: [3](#0-2) 

Meanwhile, every webhook handler (`PushHandler`, `PullRequest::*Handler`, etc.) resolves the actual `Stack`/`Repository` to act on using a *different* payload field, `repository.full_name`, never revisiting `repository.owner.login`: [4](#0-3) [5](#0-4) 

`Repository.from_github_repo_name` simply splits `owner/name` from that separate field and does a DB lookup with no relation back to whichever organization was used for signature verification: [6](#0-5) 

Equality that should hold but does not:
`verified_organization(payload.repository.owner.login) == acted_upon_repository_owner(payload.repository.full_name)`

Because both sides are attacker-supplied fields of the same JSON body, and because `verify_webhook_signature` returns `true` unconditionally when the resolved organization has no `webhook_secret` configured (a state visible in the repo's own sample config, e.g. `config/secrets.development.shopify.yml`): [7](#0-6) 
an attacker who can reach the endpoint can pick a `repository.owner.login`/`organization.login` value that maps to an organization with no configured `webhook_secret` (or one whose secret is otherwise leaked/absent), causing signature verification to trivially pass, while pointing `repository.full_name` at an entirely unrelated repository/stack that is the real target and does have a properly configured, secret-protected GitHub App/org.

### Impact Explanation
If any organization known to `Shipit.github_organizations`/`secrets.github` lacks a `webhook_secret` (a normal transitional/misconfiguration state explicitly represented in the engine's own sample secrets files), the entire signature check is bypassed for payloads whose `repository.owner.login` maps to that organization, while the write target (`full_name`) is unconstrained and can point at a stack belonging to a different, properly-secured organization. This lets an unauthenticated attacker trigger `stack.sync_github(expected_head_sha: ...)` on an arbitrary target stack (`PushHandler#process`), or manipulate `PullRequest`/`ReviewStack` archive/unarchive/provisioning state for arbitrary review stacks, none of which requires possession of the target's actual `webhook_secret`. This crosses the "authorized organization vs. repository written" trust boundary called out as an in-scope High-severity class (unauthorized GitHub-triggered state change on a stack outside the caller's authenticated organization).

### Likelihood Explanation
Likelihood is High in any deployment that configures more than one GitHub organization, since it only requires one org (even a soon-to-be-decommissioned, staging, or newly-added org) to have a blank `webhook_secret` — a state the engine's own configuration templates show as a valid, non-error condition (`webhook_secret: # nil`). No credentials, tokens, or repository write access are needed; only the ability to POST to `/webhooks` (the public webhook endpoint) with a crafted JSON body whose `repository.owner.login`/`organization.login` differs from `repository.full_name`'s owner.

### Recommendation
Bind the repository/stack lookup used by handlers to the same organization identity that was cryptographically verified, not to a second, independently-attacker-controlled field of the same payload. Concretely:
- After `verify_signature` succeeds, assert that `payload.dig('repository', 'full_name')`'s owner segment matches the `repository_owner` used to select the verifying organization/secret, rejecting (422) any mismatch.
- Alternatively, do not permit any organization to be configured with no `webhook_secret` in non-test/non-legacy-single-app configurations, and fail closed (reject the request) rather than returning `true` when `webhook_secret` is blank for a named-organization config.

### Proof of Concept
1. Configure Shipit with two GitHub organizations in `secrets.github`: `victim-org` (has a real `webhook_secret`, owns the target stack `victim-org/critical-repo`) and `unsecured-org` (no `webhook_secret` configured, e.g. left blank as in `config/secrets.development.shopify.yml`).
2. Craft a JSON push payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": { "owner": { "login": "unsecured-org" }, "full_name": "victim-org/critical-repo" }
}
```
3. POST it to `/webhooks` with `X-Github-Event: push` and any (or no) `X-Hub-Signature` value.
4. `verify_signature` resolves `Shipit.github(organization: "unsecured-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally regardless of the signature header.
5. `PushHandler#process` resolves the target repository/stack from `repository.full_name` = `victim-org/critical-repo` and calls `stack.sync_github(expected_head_sha: "deadbeef")`, triggering state changes on `victim-org`'s stack despite the request never being authenticated against `victim-org`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
