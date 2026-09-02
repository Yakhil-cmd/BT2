### Title
Webhook signature verified against `repository.owner.login`, but events are applied to the repository named by `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController` selects the GitHub App/secret used to verify a webhook's HMAC signature using one field of the untrusted, not-yet-verified JSON body (`repository.owner.login` / `organization.login`), while every event handler acts on a repository selected from a *different* field of the same untrusted body (`repository.full_name`). Because these two lookups are never checked for consistency, and because `verify_webhook_signature` trivially returns `true` when no `webhook_secret` is configured for the org selected by the first field, an attacker can pick an org that has no configured secret to sail through signature verification while pointing the payload at a completely different, protected repository/stack.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App config to check the signature against based on `repository_owner`: [1](#0-0) [2](#0-1) 

```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

That value is fed into `Shipit.github(organization: repository_owner)`, which looks up per-organization config (including `webhook_secret`) and builds a `GitHubApp` used to verify the `X-Hub-Signature` header: [3](#0-2) 

```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

Crucially, `verify_webhook_signature` unconditionally returns `true` when the resolved organization has no `webhook_secret` configured — this is documented as optional ("If you've set a webhook secret during the App creation, you should copy it here"), so operators of multi-organization Shipit installs can easily have some orgs without a secret configured.

Separately, once the request passes the `verify_signature` before_action, `create` re-parses the same raw body and dispatches it to handlers: [4](#0-3) 

Every handler determines which `Repository`/`Stack` records to mutate from a **different JSON field**, `repository.full_name`, not `repository.owner.login`: [5](#0-4) 

```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

Because the entire payload is attacker-controlled JSON prior to verification, there is no binding forcing `repository.owner.login` (used to select which secret authenticates the request) to equal the owner segment embedded in `repository.full_name` (used to select which repository/stack is actually acted upon). An attacker who knows (or guesses) that some organization configured in this Shipit instance has no `webhook_secret` set can:

1. Set `repository.owner.login` (or `organization.login`) to that unsecured org, so `verify_webhook_signature` short-circuits to `true` with no signature needed at all.
2. Set `repository.full_name` to `victim-org/victim-repo` — a different, secured repository already tracked by Shipit.
3. Send arbitrary event bodies (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.) that are then processed by the corresponding handler against the victim stack, with no valid GitHub-issued signature for that repository at all.

This breaks exactly the "organization that authenticated versus the repository that is written" binding.

### Impact Explanation
Handlers act on `stacks` derived from the spoofable `repository.full_name`:
- `PushHandler` calls `stack.sync_github(expected_head_sha: params.after)` for any not-archived stack on the matching branch — attacker-controlled sync/deploy-trigger flow. [6](#0-5) 
- `status`/`check_suite` handlers write commit statuses/check runs that feed into `StatusChecker`, which gates continuous delivery and merge-queue merges — i.e. forged CI status can unblock an unauthorized automated deploy or merge.
- `pull_request` (unlabeled/labeled/reopened) handlers archive/unarchive review stacks and trigger provisioning for a targeted repository/PR.
- `membership` events create/delete `Team`/`Membership`/`User` records used for authorization (`Shipit.github_teams`), so this can be used to escalate into the authorization model.

This crosses several of the explicitly in-scope impact categories: cross-repository writes and escalation into `Shipit.github_teams` authorization (via forged `membership` events), and can enable an unauthorized deploy/merge via forged status/check-suite events feeding `StatusChecker`.

### Likelihood Explanation
Exploitability depends entirely on the operator's configuration: it requires at least one organization registered in `Shipit.github_app_config` without a `webhook_secret` (explicitly documented as optional) while other organizations/repos tracked by the same instance are secured. Multi-org Shipit deployments where some orgs are added without configuring a webhook secret (e.g., quickly onboarded/internal orgs) make this readily reachable by any unauthenticated actor who can reach the `/webhooks` endpoint and knows or guesses an org name without a secret — no GitHub App private key, API token, or Shipit session is needed.

### Recommendation
Verify the webhook signature using the organization/repository actually targeted by the handlers (`repository.full_name`), not a separate, independently-controlled field. At minimum, cross-check that `repository.owner.login`/`organization.login` matches the owner segment of `repository.full_name` before dispatching to handlers, and reject the request if they diverge. Additionally, consider refusing to treat a missing `webhook_secret` as an implicit "always verified" bypass — instead, require an explicit signature-optional whitelist rather than defaulting `verify_webhook_signature` to `true`.

### Proof of Concept
Assume Shipit is configured with two orgs: `unsecured-org` (no `webhook_secret`) and `victim-org` (has a repo/stack `victim-org/victim-repo` tracked, secured with a `webhook_secret`).

```
POST /webhooks
X-Github-Event: push
Content-Type: application/json
(no X-Hub-Signature header needed)

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha-that-exists-on-github>",
  "repository": {
    "owner": { "login": "unsecured-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```

- `repository_owner` resolves to `unsecured-org` → `Shipit.github(organization: "unsecured-org").verify_webhook_signature(...)` returns `true` immediately because `webhook_secret` is blank for that org.
- `create` then parses the body and calls `PushHandler.call(params)`, whose `repository_name` resolves to `victim-org/victim-repo`, causing `Stack#sync_github` to run for the victim's stack — despite no valid signature ever being produced for `victim-org`. [7](#0-6) [3](#0-2) [5](#0-4)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-62)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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
