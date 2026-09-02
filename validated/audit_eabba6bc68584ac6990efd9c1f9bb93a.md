## Analysis Result

I traced the request path from `Shipit::WebhooksController` through to the individual webhook handlers and found a genuine binding break between the entity whose signature is verified and the entity whose state is mutated.

`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization secret to check the `X-Hub-Signature` against using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`): [1](#0-0) [2](#0-1) 

Signature verification itself is a no-op when the configured app has no `webhook_secret` — a state the shipped example configs explicitly document as valid (`webhook_secret: # nil`): [3](#0-2) [4](#0-3) 

Once the request passes (or is exempted from) this check, `create` dispatches the entire raw JSON body to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. Every handler resolves the target `Stack`/`Repository` via `Handler#stacks`, which reads a *different* JSON key — `payload.dig('repository', 'full_name')` — not the `owner.login` key that gated the signature check: [5](#0-4) 

`repository.owner.login` and `repository.full_name` are independent, attacker-controlled fields inside the same unauthenticated request body; nothing ties them together. So the equality the code implicitly assumes — `organization verified == organization of the repository acted on` — does not hold. An attacker who can produce a payload for an organization with a blank/no `webhook_secret` (a supported, documented configuration for any org configured in `Shipit.github`) can set `repository.owner.login` to that unsecured/known org while setting `repository.full_name` to any other tracked `owner/repo` in the Shipit instance. The webhook is accepted with no valid signature required, yet the handler acts on the victim repository's `Stack`/`Repository`, e.g. queuing `GithubSyncJob`, mutating `Commit` `Status`, or driving `pull_request` handlers such as `Shipit::Webhooks::Handlers::PullRequest::ClosedHandler`.

### Title
Webhook signature is verified against `repository.owner.login` while handlers act on `repository.full_name` — cross-organization webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks which GitHub App secret to validate the HMAC against using `repository.owner.login`, but the handlers that actually mutate state (`Handler#stacks`) key off the unrelated `repository.full_name` field in the same attacker-supplied payload.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-49` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` and uses it to select `Shipit.github(organization: repository_owner)`, whose `verify_webhook_signature` either checks the HMAC against that org's `webhook_secret` or, when the secret is blank (a documented, valid configuration — `lib/shipit/github_app.rb:76-77`), simply returns `true`. After this check, the full untrusted `params` hash is dispatched to every registered handler for the event (`app/controllers/shipit/webhooks_controller.rb:10-15`). `Handler#stacks`/`#repository_name` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) then locates the target `Repository`/`Stack` using `payload.dig('repository', 'full_name')` — a field never tied to the value used for signature selection. Because both fields live in the same freely-constructed JSON body, an attacker can set them to different organizations.

### Impact Explanation
If any organization configured under `Shipit.github` has no `webhook_secret` set (shown as the default/example in `config/secrets.development.example.yml` and `docs/setup.md`), an attacker can send an unauthenticated POST to `/github/webhooks` with `repository.owner.login` set to that org and `repository.full_name` set to any other tracked repository. This lets an unprivileged, unauthenticated attacker drive state changes on a victim stack they have no relation to — e.g., forging commit `Status` updates that CI/required-check based deploy gating relies on, or triggering `PullRequest` handlers (`closed_handler.rb`, `labeled_handler.rb`, etc.) against the victim repository — an unauthorized cross-repository write.

### Likelihood Explanation
This requires the Shipit instance to have multiple GitHub Apps configured (documented multi-org support) with at least one org left without a `webhook_secret`, which the shipped example configs present as the default/expected state, making misconfiguration plausible in real deployments; no repository write access, session, or privileged credential is needed by the attacker.

### Recommendation
Verify the webhook signature using the same repository/organization identity that the handler will act on (derive both from the same `full_name`/owner pair, or require `Handler#stacks` to reject payloads whose `repository.owner.login` doesn't match `repository.full_name`'s owner segment), and consider making `webhook_secret` mandatory per configured organization rather than optional.

### Proof of Concept
1. Configure two orgs in `Shipit.github`: `attacker-org` (no `webhook_secret`) and `victim-org` (tracked stacks/repos in Shipit).
2. POST to `/github/webhooks` with header `X-Github-Event: push`, no valid `X-Hub-Signature`, and body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "after": "<attacker-chosen sha>"
}
```
3. `verify_signature` resolves `Shipit.github(organization: 'attacker-org')`, whose secret is blank, so `verify_webhook_signature` returns `true` and the request proceeds.
4. `PushHandler` (via `Handler#stacks`) resolves the target using `full_name: "victim-org/victim-repo"`, enqueuing a `GithubSyncJob` against the victim's stack despite the request never having been authenticated for `victim-org`.

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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
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
