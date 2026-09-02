### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but the handler acts on the repository named in `repository.full_name` — cross-organization stack write via signature/payload field mismatch - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization webhook secret to check the HMAC signature against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` (or `organization.login`). The event handlers, however, resolve the target repository/stack to mutate using an entirely different, signature-unprotected payload field: `payload.dig('repository', 'full_name')`. Because the HMAC only proves "this body came from whoever holds the secret for the org named in `repository.owner.login`," and not "the org that holds that secret matches `repository.full_name`," an attacker who legitimately controls a webhook secret for *one* configured organization can forge a payload whose `repository.owner.login` names their own organization (so the signature check passes) while `repository.full_name` names a stack that belongs to a different organization altogether, causing Shipit to sync/act on that unrelated victim repository's stack.

### Finding Description
In `app/controllers/shipit/webhooks_controller.rb`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) [2](#0-1) 

The signature is a valid HMAC over `request.raw_post` computed with the secret belonging to whatever organization `repository_owner` names. The verification therefore proves only that the raw body was signed by *some* org's registered secret — the one named in `repository.owner.login` — nothing more.

After signature verification passes, `create` dispatches the parsed body to handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [3](#0-2) 

Handlers (e.g. `PushHandler`) resolve the repository/stack to act on via `repository_name`, which reads `repository.full_name` — a completely separate field from the one used for signature-organization selection:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

```ruby
class PushHandler < Handler
  def process
    stacks
      .not_archived
      .where(branch:)
      .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
  end
end
``` [5](#0-4) 

**Binding that should hold:** `organization whose secret verified the signature == organization that owns the repository/stack acted upon`.

**Binding that actually holds:** `organization named in payload["repository"]["owner"]["login"] == organization whose secret verified the signature`, which is entirely independent from `organization that owns payload["repository"]["full_name"]`, the field the handler actually trusts to select which `Stack` to mutate.

Because both `repository.owner.login` and `repository.full_name` are attacker-controlled fields inside the same signed JSON body (the attacker crafts the full body and signs it themselves with a secret they legitimately hold for their own org), the attacker can set:
- `repository.owner.login = "attacker-org"` → signature check passes using attacker-org's secret (which the attacker knows, since Shipit is a multi-tenant app supporting per-organization GitHub App configuration and secrets via `Shipit.github(organization: ...)`)
- `repository.full_name = "victim-org/victim-repo"` → `PushHandler`/other handlers look up and mutate the `Stack` belonging to `victim-org`, e.g. triggering `stack.sync_github`, archiving/unarchiving review stacks, updating commit statuses, etc., none of which are protected by any further check tying `full_name`'s owner back to the verified organization.

This is a direct instance of the reported bug class ("a payload field acted on but never covered by the verified signature" / "an organization that authenticated versus the repository that is written") — here `repository.full_name` is the field acted upon by every handler, while the signature only ever certifies `repository.owner.login`/`organization.login`.

### Impact Explanation
An attacker who has legitimate write access to at least one organization/repository configured in a multi-tenant Shipit installation (i.e., they know or control that org's webhook secret because they are an authorized member able to configure or trigger webhooks for their own org) can forge webhook deliveries that pass signature verification under their own organization but target and mutate `Stack`/`Repository`/`Commit`/`PullRequest`/review-stack state belonging to a *different* organization's repository. This allows cross-repository/cross-organization writes: e.g. triggering `GithubSyncJob` for a victim stack, creating commit statuses (`StatusHandler`) on a victim repository's commits, or unarchiving/archiving review stacks and putting them into the provisioning queue — actions the attacker has no authorization to perform on the victim's repository. This satisfies the Critical impact criterion of "cross-repository writes" via a broken authentication-to-repository binding.

### Likelihood Explanation
The only prerequisite is holding a legitimate webhook secret for any one organization onboarded to the Shipit instance — a normal, expected credential for a Shipit customer/organization admin, not a privileged Shipit account, `ApiClient` token, or GitHub App private key. Crafting the JSON body and computing the HMAC with a known secret is trivial; nothing else in the request path re-validates that `repository.full_name`'s owning organization matches `repository.owner.login`/the verified organization. This is straightforward to exploit for anyone administering a second organization on the same Shipit deployment.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`/`#stacks`), enforce that the organization used to verify the signature is the same organization that owns the repository named in `repository.full_name` before any handler is allowed to act — e.g., derive `repository_owner` from `repository.full_name`'s owner segment (or require they match exactly), and reject (422) any payload where they diverge. Do not allow `repository.owner.login`/`organization.login` to be trusted independently of the field(s) that handlers use to resolve the target repository.

### Proof of Concept
1. Configure Shipit (per `docs/setup.md`) with two organizations, `attacker-org` (secret known to the attacker) and `victim-org` (a stack `victim-org/victim-repo` already tracked by Shipit), each with its own `github.webhook_secret`.
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac>` over the raw JSON body using `attacker-org`'s known webhook secret.
4. POST to `/webhooks` with `X-Github-Event: push` and the crafted signature.
5. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `attacker-org`'s `github_app`, and successfully verifies the signature against the attacker-controlled secret.
6. `create` dispatches to `PushHandler`, which resolves `repository_name` = `"victim-org/victim-repo"`, finds the corresponding `Stack`, and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack — an action the attacker was never authorized to trigger for `victim-org`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
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
