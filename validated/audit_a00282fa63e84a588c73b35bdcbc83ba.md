### Title
Webhook signature verification key is selected from an unverified field decoupled from the repository actually acted upon - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which per-organization `webhook_secret` to validate a webhook against using `repository_owner`, a value read straight out of the still-unauthenticated request body. [1](#0-0) [2](#0-1)  The handler that later performs the actual state mutation, however, resolves the target `Repository`/`Stack` from a different field of that same unauthenticated body, `repository.full_name`. [3](#0-2)  These two fields are never cross-checked, and `verify_webhook_signature` unconditionally passes when the selected organization has no `webhook_secret` configured. [4](#0-3) 

### Finding Description
The equality this binding is supposed to enforce is: **organization that authenticates the webhook == organization whose repository/stack is mutated by the webhook**.

Flow:
1. `verify_signature` derives `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` of the raw, not-yet-verified JSON body, and uses it to fetch `Shipit.github(organization: repository_owner)`. [1](#0-0) 
2. `verify_webhook_signature` returns `true` immediately if that organization's config has no `webhook_secret` set: `return true unless webhook_secret`. [5](#0-4)  Multi-org Shipit deployments routinely leave `webhook_secret` blank for some organizations, as shown in the shipped example config and setup docs. [6](#0-5) 
3. If verification is bypassed this way, `WebhooksController#create` dispatches the (attacker-controlled) JSON body to the matching handlers. [7](#0-6) 
4. Every handler (e.g. `PushHandler`) resolves the target stacks purely from `payload.dig('repository', 'full_name')` — a field that has no relationship enforced with `repository_owner` used in step 1. [3](#0-2) [8](#0-7) 

Consequently, an unauthenticated attacker can craft a webhook body where `repository.owner.login` (or `organization.login`) names an org configured on the Shipit instance with a blank `webhook_secret`, while `repository.full_name` names an entirely different, victim organization/repository whose stacks are actually onboarded onto Shipit. Signature verification is skipped for the "authenticating" org, but the mutation is performed against the unrelated "target" org's stacks — exactly analogous to the `ZKPay` bug where the field trusted for the accounting decision (`msg.value`/`NATIVE_ADDRESS` check) is decoupled from the field that determines the actual money movement.

### Impact Explanation
This allows unauthenticated forgery of GitHub events (push, status, check_suite, pull_request, membership, etc.) against any repository/stack managed by the Shipit instance, as long as any one configured GitHub organization on that instance has no `webhook_secret` set (an explicitly supported, documented configuration). Depending on which event is forged, this can trigger unauthorized `GithubSyncJob` runs, fabricate commit statuses, alter merge/review-stack state, or create/modify `Team`/`Membership` records used for the app's own authorization (`Shipit.github_teams`) — i.e., escalation into `Shipit.github_teams` authorization and unauthenticated manipulation of stack/task state, which are explicitly in-scope High-impact categories.

### Likelihood Explanation
High for any multi-tenant/multi-org Shipit deployment where at least one configured organization intentionally or accidentally has no `webhook_secret` (supported by the shipped `secrets.development.shopify.yml` template and `docs/setup.md`, which documents `webhook_secret` as something you "should copy... if you've set" one — implying it's optional). [6](#0-5)  No credentials, session, or repository access are required — only knowledge of a configured organization's login without a secret and the target repository's `full_name`.

### Recommendation
After determining the target repository/stack from the payload, verify that the organization used to select the `webhook_secret` (`repository_owner`) matches the actual owner of `repository.full_name`/`organization.login` acted upon by the handler, and reject the request otherwise. Additionally, consider requiring a non-blank `webhook_secret` for every configured organization (or at minimum warn/refuse boot if any organization is missing one), removing the unconditional bypass in `verify_webhook_signature`.

### Proof of Concept
1. Configure/observe a Shipit instance with two orgs in `github:` config: `attacker-org` (no `webhook_secret`) and `victim-org` (onboarded stacks).
2. POST to `/github_authentication`... (webhook endpoint) with header `X-Github-Event: push` and body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/master",
  "after": "<attacker chosen sha>"
}
```
3. `verify_signature` looks up `Shipit.github(organization: "attacker-org")`; since its `webhook_secret` is blank, `verify_webhook_signature` returns `true` regardless of the (missing/invalid) `X-Hub-Signature` header.
4. `PushHandler` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueues `sync_github` for `victim-org`'s stacks — fully attacker-controlled, with no valid signature ever produced for `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
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
