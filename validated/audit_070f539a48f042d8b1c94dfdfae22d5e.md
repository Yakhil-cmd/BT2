### Title
Cross-organization webhook forgery: signing organization is never bound to the repository the payload acts on - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to use for HMAC validation based on `repository_owner`, a field taken from the *unauthenticated* JSON body (`params.dig('repository','owner','login')` or `params.dig('organization','login')). The event handlers that subsequently act on the same payload, however, resolve the target `Repository`/`Stack` from a *different* body field, `repository.full_name` (`app/models/shipit/webhooks/handlers/handler.rb#repository_name`, and equivalent lookups in `push_handler.rb`, `pull_request/*_handler.rb`). Nothing ties these two fields together, so the "organization whose secret authenticated the request" and "repository the request is allowed to act on" are two independently attacker-controlled JSON keys that are never checked for consistency.

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

The signature check only proves that the raw body was signed with the `webhook_secret` belonging to whichever organization `repository.owner.login` (or `organization.login`) names inside the *same, attacker-supplied* body. It does not prove that the resolved organization owns the repository actually referenced elsewhere in the body.

Handlers ignore `repository.owner.login` entirely and instead resolve the target repository from `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

`PushHandler` (and the `pull_request/*` handlers) use exactly this to find stacks and act on them:
```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [3](#0-2) 

Shipit explicitly supports configuring multiple, independent GitHub Apps/organizations in one instance, each with its own `webhook_secret`: [4](#0-3) [5](#0-4) 

**Binding broken:** `organization authenticated by webhook_secret` ≠ `repository the handler writes to`. Before the malicious request: `repository_owner("A") == owner-of(full_name)`. After a crafted request: `repository_owner` can be `"A"` (whose secret the attacker knows/controls, because it's their own onboarded GitHub App/org) while `repository.full_name` is `"B/victim-repo"`, a completely different, unrelated tenant tracked by the same Shipit instance.

### Impact Explanation
Any principal that legitimately owns the `webhook_secret` for **one** organization configured in a multi-org Shipit deployment (e.g., the admin of their own low-trust GitHub org/App that was onboarded onto the shared Shipit instance) can forge a valid `X-Hub-Signature` for an arbitrary payload, then set `repository.full_name` in that same payload to point at any other organization's/repository's stack tracked by the instance. Because `verify_webhook_signature` only checks the raw body against the secret picked from the (attacker-controlled) `repository_owner`/`organization` field, and the handler dispatch never re-validates that this organization actually owns `full_name`, the forged event is accepted as legitimate for a repository the attacker does not control.

Concretely, this lets the attacker drive `stack.sync_github(expected_head_sha: <arbitrary sha>)` for a victim stack via `PushHandler`, or archive/unarchive/create review stacks via the `pull_request` handlers for a victim's `PullRequest`/`ReviewStackAdapter`, cross-tenant — i.e. cross-repository writes to state (sync jobs, review stack lifecycle) that should only be reachable via the victim organization's own GitHub webhook. If `continuous_deployment` is enabled on the affected stack, forcing a sync of an attacker-chosen (but pre-existing, since GitHub API validation happens downstream) commit SHA can trigger an unauthorized deploy of that commit. This satisfies the "unauthorized deploy" / "cross-repository writes" Critical impact bucket, contingent on the multi-org configuration being used (which is a documented, supported deployment mode of this engine, not a misconfiguration outside scope).

### Likelihood Explanation
Requires: (1) the Shipit instance to be configured with more than one GitHub organization (documented supported feature), and (2) the attacker to hold legitimate credentials for the `webhook_secret` of at least one of those organizations (e.g., they are an admin of their own onboarded org, a scenario that is not "privileged" with respect to other tenants' repositories). Given those preconditions — which do not require compromising GitHub, stealing the victim's secret, or any of the explicitly excluded privileged-access vectors — the forgery itself is trivial: compute one HMAC-SHA1 over a crafted JSON body and POST it to `/github/webhooks`. Likelihood is Medium-High in any multi-tenant Shipit deployment.

### Recommendation
In `verify_signature`, after establishing which GitHub App's secret validated the signature, cross-check that the resolved `repository_owner` actually matches the owner segment of `repository.full_name` (and of `organization.login` when present) before dispatching to handlers; reject the request (422) on mismatch. Alternatively, always verify against the `webhook_secret` of the organization that legitimately owns the target repository (as looked up from Shipit's own `Repository` records), rather than trusting an attacker-suppliable field to select which secret to check against.

### Proof of Concept
Preconditions: Shipit configured with two orgs in `secrets.yml`, `attacker-org` (attacker is the org/App admin, knows `webhook_secret_A`) and `victim-org` (tracked stack `victim-org/victim-repo`, unrelated to attacker).

1. Attacker crafts a push payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<sha attacker wants synced/deployed>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
2. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(webhook_secret_A, body)>` using their own known `webhook_secret_A`.
3. POST to `/github/webhooks` with header `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`), verifies successfully against `webhook_secret_A` — matches, since attacker signed with that secret. [6](#0-5) 
5. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which resolves stacks via `payload.dig('repository','full_name')` == `"victim-org/victim-repo"`, entirely bypassing the fact that the signature was validated under `attacker-org`'s secret, and calls `stack.sync_github(expected_head_sha: "<attacker sha>")` on the victim's stack. [7](#0-6) [3](#0-2) 

Note: I could not fully inspect `lib/shipit.rb`'s `github(organization:)` lookup implementation or `Stack#sync_github`/`GithubSyncJob` internals in this session due to tool errors on the final iteration; the multi-org lookup mechanics (`TOP_LEVEL_GH_KEYS`, `GithubOrganizationUnknown`) were confirmed to exist via grep but not read in full, and downstream deploy-trigger conditions from a forced sync (e.g., whether `continuous_deployment` alone is sufficient) were not verified end-to-end.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** lib/shipit.rb (L61-63)
```ruby

  GithubOrganizationUnknown = Class.new(StandardError)
  TOP_LEVEL_GH_KEYS = [:app_id, :installation_id, :webhook_secret, :private_key, :oauth, :domain].freeze
```
