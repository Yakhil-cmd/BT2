Analysis of the webhook signature verification confirms a binding break analogous to the reentrancy bug class: the field used to select the HMAC secret for verification is not the same field the event handlers use to determine which repository/stack is actually acted upon.

### Title
Webhook signature verified against `repository.owner.login`/`organization.login` while event handlers act on the unverified `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to validate the signature against using `repository_owner`, computed from `params.dig('repository','owner','login')` or `params.dig('organization','login')` [1](#0-0) . However, the event handlers that actually act on the payload (e.g. `Handlers::Handler#repository_name`, used by `PushHandler`) resolve the target repository/stack from a **different** field: `payload.dig('repository', 'full_name')` [2](#0-1) . The equality the design implicitly assumes — "the organization whose secret authenticated this request" == "the organization of the repository the handler will write to" — is never enforced in code; it only holds by convention because GitHub always sends consistent `repository.owner.login` and `repository.full_name` values together.

### Finding Description
`verify_signature` picks the `Shipit.github(organization: repository_owner)` config and calls `verify_webhook_signature`, which returns `true` unconditionally when that organization's config has no `webhook_secret` set: `return true unless webhook_secret` [3](#0-2) . Signature validation is therefore scoped per-organization based solely on the attacker-controlled `repository.owner.login`/`organization.login` field in the JSON body, not on any value tied to the actual GitHub App installation delivering the request. The downstream handler classes never re-check that the `repository.owner.login` used for auth matches the `repository.full_name` used to locate the `Stack`/`Repository` (via `Repository.from_github_repo_name`) [2](#0-1) . If any configured organization in `Shipit.github_apps`/config lacks a `webhook_secret` (a real, supported configuration state — the code explicitly treats absent secret as "skip verification"), an attacker can submit an unsigned/arbitrarily-signed webhook body whose `repository.owner.login` is set to that unsecured organization while `repository.full_name` points at a stack belonging to a *different, secured* organization, and the push/status/pull_request handlers will act on it because they never re-validate organization consistency.

### Impact Explanation
A successful exploit lets an unauthenticated caller trigger `PushHandler#process` → `stack.sync_github(expected_head_sha:)` or other handlers for a stack under an organization whose webhook secret was never bypassed, effectively achieving an unauthorized write against that stack's sync/status state without possessing that organization's actual webhook secret. This crosses the "organization that authenticated versus the repository that is written" binding called out in scope, and can drive unauthorized deploy-adjacent state changes (sync forcing head SHA, membership/team writes) without holding any credential for the targeted repository's organization.

### Likelihood Explanation
Exploitation is contingent on at least one configured organization having no `webhook_secret` (a configuration state that is explicitly supported and not flagged as unsafe anywhere in the code/docs I could examine) — I could not verify from the available index whether `Shipit.github_apps` enforces `webhook_secret` presence as mandatory across all organizations in a typical deployment, so likelihood depends on deployment-specific configuration that I cannot confirm from this codebase slice alone.

### Recommendation
In `Handler#stacks`/`repository_name`, cross-check that `payload.dig('repository','owner','login')` (or `organization.login`) equals the owner segment of `payload.dig('repository','full_name')`, and reject the webhook if they diverge. Additionally, consider making `webhook_secret` mandatory (raise/reject rather than treat as "verified") for any organization capable of triggering write-affecting handlers, closing the implicit trust gap between the signature-verification identity and the event-handler target identity.

### Proof of Concept
Not independently executable from static review — requires a live deployment with at least one `Shipit.github` organization configured without `webhook_secret` to demonstrate the divergent-field acceptance path; I could not confirm this precondition purely from the indexed code, so this should be validated against the target deployment's `Shipit.github_apps` configuration before treating it as confirmed-exploitable.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
