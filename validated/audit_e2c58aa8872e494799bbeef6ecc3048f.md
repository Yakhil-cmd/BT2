### Title
Webhook signature verification authenticates the payload's claimed organization, not the repository the event ultimately writes to - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the HMAC secret to check based on `repository_owner`, a value read directly out of the *unauthenticated* JSON body, and only checks that the raw body was signed by *that* organization's app secret. Nothing ties the authenticated organization to the actual repository/stack that downstream event handlers act on, which is resolved from other fields of the same attacker-supplied body (e.g. `repository.full_name`). This is the same class of bug as the OVM report: two logically-related values (“which org signed this” vs “which repository this event is about”) are expected to match, but there is no code enforcing that equality — only convention on GitHub's side, which an attacker forging their own signed payload does not have to respect.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb`:

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
``` [1](#0-0) 

`repository_owner` is extracted from the raw, not-yet-verified request body, and is used purely to select which organization's `webhook_secret` to HMAC-check against, via `Shipit.github(organization: ...)` and `GithubApp#verify_webhook_signature`: [2](#0-1) 

Once `verified` is true, `create` dispatches the *entire, attacker-controlled* payload to the registered handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [3](#0-2) 

Handlers resolve the target repository/stack from other JSON fields of that same payload (e.g. `repository.full_name`, consumed by `Repository.from_github_repo_name`):
```ruby
def self.from_github_repo_name(github_repo_name)
  repo_owner, repo_name = github_repo_name.downcase.split('/')
  find_by(owner: repo_owner, name: repo_name)
end
``` [4](#0-3) 

The equality that should hold — `organization whose secret authenticated the request == organization/repository the event is applied to` — is never checked. GitHub itself always sends consistent `repository.owner.login` / `repository.full_name` values, so this gap is invisible in normal operation, exactly like the CTC/Execution-Manager gas-limit split in the report: it only manifests when the two "sources of truth" are allowed to diverge, which here an attacker fully controls because they craft the raw JSON body themselves.

### Impact Explanation
Any party that legitimately owns a GitHub organization/App already onboarded into this multi-tenant Shipit instance (i.e., possesses that org's `webhook_secret`, which is intentionally handed to org admins so GitHub can call the webhook) can compute a valid `X-Hub-Signature` for a payload whose `repository.owner.login` matches their own org (satisfying `verify_signature`), while filling in a `repository.full_name`/other identifying fields that point at a stack belonging to a *different, unrelated* organization also hosted on the same Shipit instance. Handlers such as push/status processing would then act on that unrelated organization's repository/stack (e.g., queueing `GithubSyncJob`, updating commit statuses, creating/deleting team memberships via the `membership` event, etc.), i.e. an unauthorized cross-repository/cross-tenant write into a stack the attacker does not control — matching the "cross-repository writes" Critical impact bucket for this engine.

### Likelihood Explanation
Exploitation only requires possession of one organization's own `webhook_secret` — something any org onboarded to the Shipit instance is expected to have in order to configure their GitHub App/webhook — not a Shipit session, an `ApiClient` token, or the target organization's own secret. The only additional step is crafting a JSON body whose `repository.owner.login` differs from the repository identifiers actually consumed further downstream, which is trivial once the attacker controls the raw POST body and only needs it to pass one field-based lookup (`repository_owner`) that is entirely separate from the field(s) used to resolve the acted-upon `Repository`/`Stack`.

### Recommendation
Verify the webhook signature using the same field(s) that are subsequently used to resolve the target repository/stack (or, better, verify against every organization secret only after confirming that `repository.owner.login` and `repository.full_name`'s owner segment are identical, rejecting otherwise). Establish a single source of truth for "the organization this event belongs to" that is used both for signature selection and for resolving which `Repository`/`Stack` the event is allowed to mutate, and reject payloads where these disagree.

### Proof of Concept
1. Attacker organization `attacker-org` is legitimately configured in this Shipit instance with its own `webhook_secret` (`S_attacker`), per `config/secrets*.yml` per-org config.
2. Attacker crafts a `push` (or `status`/`membership`) webhook JSON body where:
   - `repository.owner.login = "attacker-org"` (so `repository_owner` picks `S_attacker` for verification)
   - `repository.full_name = "victim-org/victim-repo"` (the field actually used by handlers, e.g. `Repository.from_github_repo_name`, to find the Stack to act on)
3. Attacker computes `X-Hub-Signature: sha1=HMAC(S_attacker, raw_body)` and POSTs to `/webhooks`.
4. `verify_signature` looks up `Shipit.github(organization: "attacker-org")` and validates successfully against `S_attacker`.
5. `create` dispatches the full payload (with `victim-org/victim-repo` inside) to handlers, which resolve and act on the victim's `Stack`/`Repository`, e.g. triggering a sync job or mutating commit status/team membership for a repository the attacker does not control.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
