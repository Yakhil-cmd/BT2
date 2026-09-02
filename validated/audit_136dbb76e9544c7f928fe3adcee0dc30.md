### Title
Webhook Signature Verification Binds to Attacker-Controlled `organization`/`repository.owner` Field, Not the `repository.full_name` the Event Handlers Act On - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret used to validate the `X-Hub-Signature` HMAC based on an organization name taken from the same untrusted JSON body it is about to validate, while the event handlers that actually mutate state (`PushHandler`, the `PullRequest::*` handlers) resolve the target `Stack`/`Repository` from a *different* field (`repository.full_name`) in that same body. These two fields are never cross-checked, so the "organization that authenticated" and the "repository that is written" are not the same binding.

### Finding Description
`verify_signature` computes the signer to check against like this: [1](#0-0) 

and derives that organization purely from the request body: [2](#0-1) 

Note the fallback: if `repository.owner.login` is absent, it falls back to the top-level `organization.login` — both attacker-supplied JSON fields.

Once the signature is accepted, `create` dispatches the entire attacker-controlled body to handlers: [3](#0-2) 

Handlers resolve the `Stack` to act on using a *different* field of the same payload, `repository.full_name`, with no reference at all to `repository.owner.login` or `organization.login`: [4](#0-3) 

For example, `PushHandler` uses this to look up stacks and force `sync_github`: [5](#0-4) 

The binding that should hold is:
`organization used to select webhook_secret for HMAC verification == owner of the repository.full_name acted on by the handler`

Because both fields are independently attacker-controlled inside the same unsigned-until-verified JSON body, an attacker who is a legitimate admin of their own onboarded organization (`attacker-org`, with a real GitHub App/webhook secret configured for that org in this multi-tenant Shipit deployment, per `config/secrets.yml`/`docs/setup.md` multi-org layout) can craft a POST directly to `/webhooks` with:
```json
{
  "organization": { "login": "attacker-org" },
  "repository": { "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>"
}
```
Since `repository.owner` is omitted, `repository_owner` falls back to `attacker-org`, so `verify_signature` validates the HMAC using `attacker-org`'s own webhook secret — which the attacker legitimately knows. The signature check passes. `PushHandler#process` then resolves stacks via `repository.full_name = "victim-org/victim-repo"`, completely independent of the org used for authentication, and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack.

The same disjoint binding affects the `pull_request/*` handlers (`opened_handler.rb`, `closed_handler.rb`, etc.), all of which resolve their target stack via `Repository.from_github_repo_name` off `repository.full_name` rather than the authenticated organization.

### Impact Explanation
This lets an attacker who controls one onboarded organization's webhook secret forge webhook deliveries that are processed as if they originated from a completely different organization's repository. Depending on which handler is targeted, this can force unscheduled/forced `sync_github` refreshes, spoof pull-request lifecycle events (`opened`, `closed`, `labeled`) that drive Shipit's merge-queue/review-stack automation, or inject fabricated commit statuses — i.e., cross-repository interference/writes across organizational trust boundaries the webhook_secret system is supposed to enforce. This matches the "organization that authenticated versus the repository that is written" binding-break category and rises to unauthorized cross-repository state manipulation.

### Likelihood Explanation
Requires the attacker to control (as a legitimate, unprivileged party relative to the victim) a webhook secret for *some* organization already onboarded onto the shared Shipit instance — not the victim's secret, not any Shipit account credentials, and no repository write access to the victim repo. In any multi-tenant deployment (the documented use case per `docs/setup.md`, `config/secrets.development.shopify.yml` showing multiple orgs configured), this is a modest bar and entirely unprivileged with respect to the victim.

### Recommendation
After verifying the HMAC signature, re-derive the acting organization from the same field the handlers use (`repository.full_name`'s owner segment) and require it to match the organization whose secret validated the signature (`repository_owner`), rejecting the webhook if they diverge. Alternatively, have `Handler#repository_name`/`stacks` cross-check the resolved `Repository`'s owner against the verified `repository_owner` before dispatching.

### Proof of Concept
1. Attacker is an admin of `attacker-org`, an organization already configured in Shipit's `github:` secrets with its own `webhook_secret`.
2. Attacker crafts JSON body:
```json
{
  "organization": {"login": "attacker-org"},
  "repository": {"full_name": "victim-org/victim-repo"},
  "ref": "refs/heads/main",
  "after": "deadbeef"
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac>` using `attacker-org`'s webhook secret over the raw body, and sets `X-Github-Event: push`.
4. `POST /webhooks` — `verify_signature` computes `repository_owner` as `attacker-org` (via fallback since `repository.owner` is absent), looks up `Shipit.github(organization: "attacker-org")`, and the HMAC check passes.
5. `PushHandler.call(params)` resolves `stacks` via `payload.dig('repository','full_name')` = `"victim-org/victim-repo"`, unrelated to `attacker-org`, and calls `stack.sync_github(expected_head_sha: "deadbeef")` on the victim's stack — a cross-organization action triggered using only the attacker's own org credentials. [6](#0-5) [4](#0-3) [7](#0-6)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-23)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
```
