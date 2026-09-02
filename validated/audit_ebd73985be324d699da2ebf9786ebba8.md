### Title
Webhook Signature Verified Against Attacker-Chosen Organization While Handlers Act on a Different `repository.full_name` — Cross-Organization Forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Deriverse's bug class — a value used for a security-relevant decision that isn't kept authoritative/consistent with the field actually acted upon (`perp_spot_price_for_withdrowal` vs. `perp_underlying_px`) — maps onto a real trust-binding break in `Shipit::WebhooksController`. The controller selects *which GitHub App secret* verifies the inbound webhook using an attacker-controlled JSON field (`repository.owner.login`), but the handlers that actually perform writes (deploy sync, PR archiving, etc.) key off a *different* attacker-controlled field in the same payload (`repository.full_name`). Nothing binds these two fields together, so any party who legitimately possesses the webhook secret for **one** GitHub organization configured on a shared Shipit instance can forge events for stacks/repositories belonging to a **different** organization configured on that same instance.

### Finding Description
`WebhooksController#verify_signature` picks the signing secret to validate the request via: [1](#0-0) 
where `repository_owner` is read straight out of the untrusted JSON body: [2](#0-1) 

Shipit explicitly supports multiple independent GitHub organizations sharing one Shipit instance, each with its own `webhook_secret`, keyed by organization name (documented in `docs/setup.md`, "Using Multiple Github Applications"). `Shipit.github(organization: ...)` looks up the app/secret keyed by that organization string.

Once the signature check passes, `WebhooksController#create` dispatches the full payload to handlers: [3](#0-2) 

Every handler resolves the target `Stack`/`Repository` from a *separate* field, `repository.full_name`, not from `repository.owner.login`: [4](#0-3) 

For example, `PushHandler` triggers a GitHub sync (which can lead to deploy) using `repository.full_name` to find stacks and `params.after` (attacker-controlled) as the expected head SHA: [5](#0-4) 

Other handlers (`ReopenedHandler`, `UnlabeledHandler`, `AssignedHandler`, `LabelCapturingHandler`) similarly resolve `Repository.from_github_repo_name(params.repository.full_name)` to archive/unarchive review stacks or update pull request state: [6](#0-5) 

**Root cause / broken equality:** the engine implicitly assumes
`organization that authenticated the HMAC (repository.owner.login) == organization that owns the repository being written (repository.full_name)`,
but never enforces it. Since the whole JSON body is attacker-supplied before signing (an org admin controls the payload they send/replay to their own configured webhook endpoint, or any party who obtains a legitimate `webhook_secret` for org A can freely craft the rest of the JSON body, including `repository.full_name` pointing at org B's tracked repo, and sign the *entire* body with org A's secret). `verify_webhook_signature` only proves the bytes were HMAC'd with org A's secret; it proves nothing about which org's repository content is claimed inside those bytes: [7](#0-6) 

### Impact Explanation
An attacker who legitimately controls the webhook secret for any one GitHub organization configured on a multi-tenant Shipit deployment can forge webhook events (push, pull_request, check_suite, membership, status) that name a completely different organization's repository in `repository.full_name`. Because `PushHandler` calls `stack.sync_github(expected_head_sha: params.after)` for stacks matched purely by `full_name`, this results in cross-repository/cross-tenant write and can drive an unauthorized deploy sync for a repository/organization the attacker does not own or administer. This satisfies the "Critical: cross-repository writes / unauthorized deploy" impact bar, since the confused-deputy path lets an org-A credential holder affect org-B's stacks with no repository write access or Shipit session of their own on org B.

### Likelihood Explanation
Requires the target Shipit instance to be configured for more than one GitHub organization (documented, supported feature) and requires the attacker to hold a legitimate `webhook_secret` for at least one of those organizations (e.g., they are an admin of their own org's GitHub App integration pointed at the shared Shipit instance). Given that is a normal, intended configuration (not a privileged escalation on the attacker's own tenant), and no additional binding check exists anywhere in the controller or handler chain, this is straightforward to exploit once the multi-org setup is in place.

### Recommendation
After signature verification, `WebhooksController` (or `Handler`) should verify that `repository.owner.login` (or `organization.login`) used to select the signing secret is the same organization that owns `repository.full_name`, rejecting the request (422) on mismatch. Alternatively, resolve the target `Repository`/`Stack` and re-derive/re-check the owning organization from the resolved record rather than trusting the raw payload field independently in each handler.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md` multi-org setup) and each with stacks tracking repos `OrgA/repo1` and `OrgB/repo2`.
2. As an attacker who administers `OrgA`'s GitHub App/webhook (i.e., knows `OrgA`'s `webhook_secret`, but has no access to `OrgB`), craft a push payload body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "OrgB/repo2",
    "owner": { "login": "OrgA" }
  }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac(OrgA_webhook_secret, body)>` and POST to `/github/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#repository_owner` returns `"OrgA"`, so `Shipit.github(organization: "OrgA")` is used and `verify_webhook_signature` succeeds (valid HMAC for that org's secret over this exact body).
5. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("OrgB/repo2")`, entirely bypassing the fact that verification was scoped to `OrgA`, and triggers `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` for `OrgB`'s stack — a write the attacker has no authorization to perform.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L49-59)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
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
