### Title
Webhook signature verification is scoped by an unauthenticated `repository.owner.login` field that is independent of the `repository.full_name` field the handlers actually act on — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-organization Shipit deployment (`config/secrets.yml` `github:` keyed by multiple org names), `WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to use for HMAC verification based on `repository.owner.login` (falling back to `organization.login`) taken directly from the unauthenticated JSON body. Once the signature check passes, the actual event handlers (`PushHandler`, `MembershipHandler`, pull-request handlers, etc.) determine *which repository/stack to act on* using a **different** field from the same unauthenticated body: `repository.full_name`. These two fields are never cross-checked against each other.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb`:
```ruby
before_action :check_if_ping, :drop_unhandled_event, :verify_signature
...
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

`repository_owner` is read straight out of the untrusted request body and used to pick the `Shipit::GithubApp` instance (and its `webhook_secret`) that the HMAC is checked against: [2](#0-1) 

Once `head(422)` is not called (i.e. the HMAC matches the secret for whatever org `repository_owner` names), `create` dispatches the same raw payload to handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [3](#0-2) 

But every handler resolves the target repository from `repository.full_name`, not from `repository.owner.login`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

`PushHandler` then calls `stack.sync_github(expected_head_sha: params.after)` for every non-archived stack matching that repository and branch: [5](#0-4) 

This is the exact analog of the reported bug class: **an organization that authenticated (via the org whose `webhook_secret` matched) versus the repository that is written/acted on (derived from `full_name`)**. Nothing binds those two fields together. An attacker who legitimately controls the webhook configuration/secret for one organization onboarded into this Shipit instance (`OrgB`) — a normal, unprivileged action available to any org that installs the app and is handed its own webhook secret by GitHub — can craft an arbitrary HTTP POST directly to `/webhooks` with:
- `repository.owner.login = "OrgB"` (or `organization.login = "OrgB"`) so `verify_signature` selects `OrgB`'s `webhook_secret` for HMAC verification, which the attacker legitimately possesses,
- `repository.full_name = "OrgA/victim-repo"` — a repository belonging to a *different* organization also hosted by this Shipit instance, which the attacker has no access to and no secret for.

The forged HMAC (computed by the attacker with `OrgB`'s secret over their own crafted body) passes `verify_signature` because the code only checks "does this body's HMAC match the secret for the org named in this body" — never "does the org that owns the acted-upon repository match the org whose secret validated this request."

### Impact Explanation
Handlers triggered this way operate on `OrgA`'s stacks despite the request only being authenticated against `OrgB`. For `PushHandler`, this invokes `stack.sync_github(expected_head_sha:)` on stacks belonging to a repository/org the attacker was never authorized to send events for. Depending on stack configuration, `sync_github` can update the tracked HEAD and, for stacks with `continuous_deployment` enabled, lead into `trigger_continuous_delivery` → `trigger_deploy`, resulting in an unauthorized deploy being kicked off for another organization's stack based on a forged cross-org event. Other handlers (`MembershipHandler`, `PullRequest::*Handler`, `StatusHandler`, `CheckSuiteHandler`) similarly key their side effects (creating/removing team memberships, archiving/unarchiving review stacks, recording commit statuses) off `repository.full_name`/`organization.login` fields that are not validated against the org whose secret authenticated the request. This crosses the "unauthorized deploy" / cross-repository-write boundary called out as in-scope Critical/High impact.

### Likelihood Explanation
Exploitation only requires an attacker to (a) be an admin/owner of any single GitHub organization that has been onboarded to the shared Shipit instance (a normal, expected, unprivileged-relative-to-other-tenants position in a multi-org deployment as documented in `config/secrets.development.shopify.yml` / `docs/setup.md`), and (b) send a single crafted HTTP request directly to the public `/webhooks` endpoint — no interaction with GitHub itself is required, since Shipit's own verification logic, not GitHub's delivery mechanism, is what's being bypassed. This is straightforward to construct once the multi-org config is known (the org list is discoverable from the Shipit UI/settings).

### Recommendation
Bind the field used to select the verification secret to the field used to determine the acted-upon repository. Concretely:
- Derive the "authenticating organization" and the "target repository owner" from the same value, e.g. always use `repository.full_name.split('/').first` (or ensure `repository.owner.login == full_name.split('/').first`) before calling `Shipit.github(organization:)`.
- After signature verification succeeds, re-verify inside `create`/each handler that the resolved repository's owner matches the organization whose secret validated the signature, rejecting the event otherwise.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (`config/secrets.yml`), each hosting at least one stack (`OrgA/victim-repo`, tracked by Shipit; `OrgB/whatever`).
2. As the legitimate owner of `OrgB`, obtain `OrgB`'s `webhook_secret` (as delivered by GitHub when the app/webhook was configured for `OrgB`).
3. Craft a JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha, ideally an existing commit on OrgA/victim-repo>",
  "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgA/victim-repo" }
}
```
4. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgB_webhook_secret, body)>`.
5. `POST /webhooks` with `X-Github-Event: push` and the header above.
6. `verify_signature` resolves `repository_owner` = `"OrgB"`, fetches `OrgB`'s app/secret, and validates the HMAC successfully (since the attacker computed it with the correct, legitimately-known secret).
7. `create` dispatches to `PushHandler`, which resolves `repository_name` = `"OrgA/victim-repo"` and calls `stack.sync_github(expected_head_sha: ...)` on `OrgA`'s stack — an action never authenticated by `OrgA`'s credentials.

Note: I was unable to inspect the full body of `Shipit::Stack#sync_github` / `Shipit::GithubSyncJob` in this pass to trace every downstream side effect (e.g., exact conditions under which continuous deployment auto-triggers), so the deploy-triggering chain described above is based on `trigger_continuous_delivery`/`trigger_deploy` wiring found in `app/models/shipit/stack.rb` rather than a direct read of `sync_github`'s body; a full session with file access would be needed to confirm the exact downstream blast radius per stack configuration.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
