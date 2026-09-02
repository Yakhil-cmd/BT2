### Title
Webhook signature is verified against the organization derived from the payload, but event handlers act on an unrelated `repository.full_name` field from the same payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate the HMAC signature against using `repository_owner`, a value read out of the untrusted JSON body itself. Once the signature check passes, `Webhooks::Handlers::Handler` (the base class used by every webhook handler) resolves which `Repository`/`Stack` to mutate using a *different* field of that same body, `repository.full_name`, with no check that it belongs to the organization that was actually used to validate the signature.

### Finding Description
In `app/controllers/shipit/webhooks_controller.rb`: [1](#0-0) 

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
``` [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up the GitHub App/`webhook_secret` configured for that particular organization (the `GithubOrganizationUnknown` rescue confirms the engine supports per-organization app/webhook configuration). Signature verification therefore only proves the request was signed with *that organization's* secret - it says nothing about the rest of the JSON body.

Once verified, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the full, attacker-controlled `params` hash to handlers such as `PushHandler` and `StatusHandler`. Every handler inherits repository resolution from `Handler`: [3](#0-2) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`repository_name` (`repository.full_name`) is never checked against `repository_owner` (`repository.owner.login`) that was used to select the signing secret. These are two independent reads of the same JSON body, and the engine only binds the signature to the first one.

The equality that should hold and is broken is:
`organization used to verify HMAC (repository.owner.login) == organization of the repository actually looked up and mutated (repository.full_name)`

### Impact Explanation
An attacker who legitimately administers (or has push access producing genuine events for) **any** organization/GitHub App installation registered on the same multi-tenant Shipit instance can craft a raw POST to `/webhooks` whose body sets `repository.owner.login`/`organization.login` to their own org (so the HMAC computed with their own known `webhook_secret` passes verification) while setting `repository.full_name` to an arbitrary victim repository hosted on a completely different, unrelated organization also registered on the instance. This is accepted as a validly-signed webhook and dispatched to handlers that act on the victim's `Stack`/`Repository`, e.g.:
- `StatusHandler` (`status` events) can inject a forged `success` commit status for an arbitrary victim commit `sha`, which feeds directly into `Commit#deployable?`/`ci.require` checks used by `DeploysController#create` (`param_error!(:require_ci, ...) unless commit.deployable?`) and by `continuous_deployment`. A forged green status can make an otherwise CI-failing commit appear deployable, enabling an unauthorized deploy on the victim's stack.
- `PushHandler` can force `stack.sync_github` on an arbitrary victim stack.

Because this can lead to an unauthorized deploy on a stack outside the attacker's authorization boundary, this reaches the Critical impact bar ("an unauthorized deploy").

### Likelihood Explanation
Requires only that the attacker control one legitimate GitHub App/organization registration on the same Shipit instance (a normal, unprivileged tenant in a multi-org deployment, not a privileged Shipit account, `ApiClient` token, or `webhook_secret`/`api_clients_secret` of the victim). No GitHub API access, TLS interception, or social engineering is needed - just a direct HTTP POST with a signature computed from the attacker's own known secret.

### Recommendation
After `verify_signature` succeeds, re-validate that every repository-identifying field consumed later by handlers (`repository.full_name`, `repository.owner.login`, `organization.login`) refers to the same organization that was used to select the verifying `webhook_secret`. Reject the webhook (422) if these disagree.

### Proof of Concept
1. Attacker registers/administers `attacker-org` as a tenant on the shared Shipit instance, and knows the `webhook_secret` configured for it (e.g. because they configured the GitHub App themselves).
2. Attacker crafts a `status` (or `push`) event JSON body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(attacker-org_webhook_secret, body)` and POSTs it to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` = `attacker-org`, fetches `attacker-org`'s `webhook_secret`, and successfully verifies the signature.
5. `StatusHandler` (via `Handler#repository_name` = `victim-org/victim-repo`) creates a forged `success` status on `victim-org/victim-repo`'s commit, independent of `attacker-org`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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
