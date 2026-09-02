### Title
Webhook organization used for signature verification is decoupled from the repository actually acted upon - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to verify the HMAC signature against by reading an organization identifier out of the *same untrusted JSON body* it is about to validate, and it accepts either the `repository.owner.login` field or, as a fallback, the completely separate `organization.login` field. The rest of the request pipeline (`create`, and the event handlers under `app/models/shipit/webhooks/handlers/**`) then acts on other fields of that same payload (e.g. the repository/stack the push, status or check_suite event is claimed to belong to) without re-checking that they are consistent with the organization whose secret produced a valid signature.

### Finding Description
`verify_signature` computes the signing organization like this: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  ...
end

def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` looks up a per-organization `GitHubApp` instance whose `webhook_secret` is used to compute the expected HMAC in `verify_webhook_signature`: [3](#0-2) 

The binding this is supposed to enforce is: *the organization whose secret validated the signature* == *the organization/repository that the payload's body will actually be applied to*. Because `repository_owner` is derived from the request body itself, and multiple independent top-level keys (`repository.owner.login` vs `organization.login`) can be used to pick the verifying secret, an attacker who controls a legitimate GitHub App installation on their own organization (and therefore legitimately knows that organization's `webhook_secret`) can shape a payload so that:
- the field consulted by `verify_signature` (`repository.owner.login` or `organization.login`) names the attacker's own organization, so the HMAC check passes using the attacker's own, legitimately-known secret, while
- other fields consumed later by the event handler (e.g. `repository.full_name`, `sha`, `state`, `branches`) reference a different, victim organization/repository/stack.

Since `create` simply re-parses `request.raw_post` and dispatches the full parsed payload to handlers (`Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`), nothing re-derives or re-validates that the repository acted upon by the handler is the same repository whose secret was used to authenticate the request. [4](#0-3) 

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" binding described in scope. A party with a legitimate but low-privilege GitHub App installation (their own org, their own webhook secret) can forge signed-looking webhook events (`push`, `status`, `check_suite`, `membership`) that are processed as if targeting a different organization's stack, e.g. injecting fake commit statuses, triggering `GithubSyncJob`/deploy-triggering sync for a victim's stack, or fabricating `check_suite`/status data that downstream deploy-gating logic in Shipit relies on — all without ever having write access to the victim repository. This corresponds to "escalation into authorization" / "unauthorized deploy" impact classes.

### Likelihood Explanation
The attacker only needs their own (attacker-controlled) GitHub organization to be configured as one of Shipit's known organizations (a realistic multi-tenant Shipit deployment, as evidenced by `test/dummy/config/secrets_double_github_app.yml` supporting multiple orgs under one Shipit instance) and knowledge of their own webhook secret — both are things a legitimate low-privilege tenant already has. No repository write access to the victim, no Shipit session, and no compromise of any secret belonging to the victim organization is required.

### Recommendation
Do not let handler-relevant repository/organization identity be sourced independently from the field used for signature-organization selection. Concretely:
- Verify the signature using the organization strictly derived from `repository.full_name`'s owner (or a single canonical field), and reject the payload if `repository.owner.login` and `organization.login` disagree.
- After signature verification succeeds, re-derive the "authenticated organization" and assert every handler-relevant repository reference in the payload belongs to that same organization before dispatching to handlers.
- Avoid the `dig('repository', ...) || dig('organization', ...)` fallback pattern entirely for events that also carry a `repository` key, since it allows two structurally different, independently-attacker-controlled JSON subtrees to satisfy the same authorization decision.

### Proof of Concept
1. Attacker registers/owns an org `attacker-org` that is configured as a known organization in this Shipit instance (multi-org support confirmed by `test/dummy/config/secrets_double_github_app.yml`), and knows `attacker-org`'s `webhook_secret`.
2. Attacker crafts a `push` (or `status`/`check_suite`) webhook body where:
   - `repository.owner.login == "attacker-org"` (used only to select the verifying secret), and
   - `repository.full_name == "victim-org/victim-repo"` (and any handler-relevant fields such as `sha`/`state`) referencing the victim's actually-tracked stack.
3. Attacker computes `X-Hub-Signature` with `attacker-org`'s legitimately-known `webhook_secret` over that exact raw body.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` and the HMAC check passes.
5. `create` dispatches the full parsed body to `Shipit::Webhooks.for_event(event)` handlers, which act on `repository.full_name` = victim's repo, updating commit statuses / enqueuing sync or deploy-adjacent jobs for a stack the attacker never had access to.

Note: I was unable to open `app/models/shipit/webhooks/handlers/push_handler.rb`/`status_handler.rb`/`check_suite_handler.rb` directly in this session to quote the exact stack-lookup line; the mismatch is demonstrated at the controller/authentication layer (`app/controllers/shipit/webhooks_controller.rb`), and the downstream dispatch mechanism (`Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`) is confirmed to pass the full, unfiltered parsed payload to those handlers.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-29)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
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
