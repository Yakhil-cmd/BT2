### Title
Webhook signature verification is keyed on `repository.owner.login` but the target repository is resolved from the unrelated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which secret) to verify the HMAC signature against using `repository_owner`, a value read directly out of the *unverified* JSON body. The action that is actually performed - resolving and mutating a `Stack`/`Repository` - is driven by a different, independently-controlled field in the same unverified body: `repository.full_name`. Nothing binds these two fields together, so the "authenticated" identity and the "acted-upon" identity can diverge.

### Finding Description
`verify_signature` computes the org used for the HMAC check purely from payload content: [1](#0-0) [2](#0-1) 

`repository_owner` is taken from `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`), and is used only to pick `Shipit.github(organization: repository_owner)` and its `webhook_secret` for the HMAC comparison in `GitHubApp#verify_webhook_signature`: [3](#0-2) 

Critically, `verify_webhook_signature` returns `true` unconditionally when no `webhook_secret` is configured for that organization (`return true unless webhook_secret`). Leaving `webhook_secret` blank is a first-class, documented configuration option, shown as the default example in both `docs/setup.md`/`config/secrets.development.shopify.yml` (`webhook_secret: # nil`) and in `test/dummy/config/secrets_double_github_app.yml`.

Once the (possibly trivially-passed) signature check succeeds, `WebhooksController#create` dispatches the *entire* raw payload to handlers: [4](#0-3) 

Every handler resolves the target repository/stack from `payload.dig('repository', 'full_name')` - a completely separate field from `repository.owner.login` used for the signature check, and never cross-checked against it: [5](#0-4) [6](#0-5) 

This is the same class of bug as the ShortCollateral report: a check is performed over one piece of state (`safetyRatio`/here, `repository.owner.login` for secret lookup) while the consequential action is taken over a different, uncovered piece of state (the liquidated amount/here, `repository.full_name`, which determines which real-world repository is mutated). The binding that should hold - "the organization whose signature was verified" == "the repository that gets written" - is never enforced.

### Impact Explanation
If any single organization configured on the Shipit instance has no `webhook_secret` set (a supported, documented configuration), an attacker can submit a completely unsigned/unauthenticated POST to `/webhooks` with `repository.owner.login` set to that unsecured organization while setting `repository.full_name` to any other org/repo tracked by the instance (e.g. a security-conscious org that *does* have a secret configured). Because handlers only use `full_name` to find the `Stack`/`Repository`, the attacker can trigger `PushHandler#process` → `stack.sync_github(expected_head_sha: ...)`, close/reopen/archive review stacks (`ClosedHandler`, `ReopenedHandler`), or manipulate commit `status`/`check_suite` state for that unrelated repository - all without ever supplying a valid signature for that repository's own organization. This crosses the "cross-repository writes"/"unauthorized deploy or rollback" bar, since a stack under one org's protection can be manipulated using zero credentials tied to that org.

### Likelihood Explanation
Likelihood is directly gated on Shipit configuration: at least one configured GitHub organization must have `webhook_secret` unset. This is not a hardened default the code enforces - it is presented as a normal/example configuration in the shipped docs and secrets templates, so real deployments (especially multi-org installs, or orgs configured before webhook secrets were added) plausibly have this state. No attacker-controlled forgery of a legitimately-signed payload is required; the bypass is purely structural (secret-less org used to skip HMAC entirely), then the unrelated `full_name` field is trusted for the actual write.

### Recommendation
Bind the verified identity to the acted-upon identity instead of treating them as independent unauthenticated inputs:
- Require and validate `webhook_secret` presence for every configured organization/app (fail closed instead of `return true unless webhook_secret`).
- After signature verification, re-derive the repository/organization the payload claims to act on (`repository.full_name`) and assert its owner matches the `repository_owner` used to select the secret that verified the signature, rejecting the request otherwise.

### Proof of Concept
1. Configure Shipit with two orgs, e.g. `OrgA` (no `webhook_secret`, per the documented example config) and `OrgB` (has `webhook_secret`, hosts a tracked `Stack` for `OrgB/critical-repo`).
2. Send `POST /webhooks` with header `X-Github-Event: push` and a hand-crafted, unsigned JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker chosen sha>",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/critical-repo" }
   }
   ```
3. `verify_signature` resolves `repository_owner` = `"OrgA"`, looks up `OrgA`'s `GitHubApp`, and `verify_webhook_signature` returns `true` immediately because `OrgA` has no `webhook_secret` - no `X-Hub-Signature` header is even required to match anything real.
4. `create` dispatches the payload to `PushHandler`, which resolves the stack via `payload.dig('repository', 'full_name')` = `"OrgB/critical-repo"` and calls `stack.sync_github(expected_head_sha: "<attacker chosen sha>")`, acting on `OrgB`'s protected stack despite the request never being authenticated for `OrgB`.

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
