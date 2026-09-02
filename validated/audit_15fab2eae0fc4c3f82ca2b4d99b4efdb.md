### Title
Webhook signature verification is scoped to the payload's `repository.owner.login`, but handlers act on the unvalidated `repository.full_name` / global commit `sha` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and therefore which `webhook_secret`) to use for HMAC verification based on `repository_owner`, a field read directly out of the untrusted JSON body. Every downstream `Shipit::Webhooks::Handlers::Handler` subclass, however, resolves the target `Repository`/`Stack`/`Commit` using a *different* field of the same untrusted body (`repository.full_name`, or for `StatusHandler`, a bare `sha` lookup with no repository scoping at all). Nothing ties these two fields together, so the organization whose secret authenticated the request is not proven to be the organization/repository actually acted upon.

### Finding Description
`verify_signature` computes:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

This means the app config (and its `webhook_secret`) used to check the HMAC is chosen from `repository.owner.login`, which is fully attacker-controlled JSON — it does not need to match anything else in the payload.

Once verified, `create` dispatches the raw parsed `params` to handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [2](#0-1) 

The base `Handler` class resolves the target repository from `repository.full_name`, a separate field from `repository.owner.login`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

`PushHandler` uses this to sync a stack to an attacker-chosen `expected_head_sha`:
```ruby
def process
  stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [4](#0-3) 

`StatusHandler` is even less scoped — it does not consult `repository.full_name` at all, and instead writes a commit status to any commit in the whole Shipit database matching an attacker-supplied `sha`:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [5](#0-4) 

All `pull_request.*` handlers (`opened`, `closed`, `labeled`, `unlabeled`, `reopened`, `assigned`) likewise resolve the acted-upon repository via `params.repository.full_name`:
```ruby
def repository
  Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
end
``` [6](#0-5) 

**Attack:** an attacker with a legitimate GitHub App installed on their own organization ("attacker-org") knows that organization's `webhook_secret` (they can trigger real webhook deliveries from a repo they own to derive/replay a valid signature, or the org is one they administer, per `Shipit.github` multi-org config). They send a POST to `/webhooks` with:
- `X-Hub-Signature` computed with `attacker-org`'s webhook secret,
- `repository.owner.login` = `"attacker-org"` (so `verify_signature` picks the correct/known secret and passes),
- `repository.full_name` = `"victim-org/victim-repo"` (or, for the `status` event, simply a `sha` belonging to a commit in a victim stack) — a value the code never cross-checks against `repository.owner.login`.

Because `repository_owner` (used for authentication) and `repository_name`/`sha` (used for authorization/target-selection) are two independent, unauthenticated fields of the same JSON body, the equality the code implicitly relies on — *organization that authenticated == repository being written to* — does not hold and is never enforced.

### Impact Explanation
This breaks the binding "an organization that authenticated versus the repository that is written," matching the analog class in scope. Concretely:
- Via `StatusHandler`, an attacker can forge arbitrary commit `state`/`context`/`description`/`target_url` for **any** commit sha tracked anywhere in the Shipit instance (public commit SHAs are trivially discoverable on GitHub), without ever having access to the victim repository or organization. Forged "success" CI statuses can satisfy Shipit's merge/deploy-readiness checks (`Status::Group`/`CommitChecks`), enabling an unauthorized merge or unblocking an unauthorized deploy — squarely in the "Critical: unauthorized deploy, rollback or merge" bucket.
- Via `PushHandler`, an attacker can force `GithubSyncJob`/`sync_github` to run against a victim stack with an attacker-chosen `expected_head_sha`, corrupting the stack's known commit list.
- Via the `pull_request.*` handlers, an attacker can archive/unarchive victim review stacks or manipulate victim PR-driven provisioning behavior cross-repository.

### Likelihood Explanation
Exploitation requires the attacker to control (or have credentials for) at least one GitHub App/organization already configured in Shipit's multi-org `secrets.yml` (`Shipit.github`) — i.e., they must be able to produce a validly-signed webhook body for *some* org known to the instance, which the deployment operator explicitly trusts to interact with the `/webhooks` endpoint. Given that, forging the divergent `repository.owner.login` vs `repository.full_name`/`sha` fields requires no special access and is a simple raw HTTP POST with a hand-crafted JSON body and a correctly computed HMAC. `WebhooksController` skips CSRF protection and has no other request-origin binding, so likelihood is high once one org's secret is available to the attacker.

### Recommendation
When resolving the target `Repository`/`Stack`/`Commit` in `Handler`, `PushHandler`, `StatusHandler`, and the `pull_request.*` handlers, validate that the resolved repository's `owner` matches `repository_owner` (the value used to select the verifying `webhook_secret`), and reject/ignore the event otherwise. For `StatusHandler` specifically, scope the `Commit` lookup to commits belonging to a stack whose repository owner matches the authenticated organization, instead of a global `Commit.where(sha: ...)` lookup.

### Proof of Concept
1. Configure Shipit with two orgs in `secrets.yml`: `attacker-org` (attacker controls it, knows `webhook_secret`) and `victim-org` (hosts the target stack, tracked commit `abcd123`).
2. Attacker computes `sha256`/`sha1` HMAC of a JSON body over `attacker-org`'s known `webhook_secret`:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "sha": "abcd123",
  "state": "success",
  "context": "ci/required-check",
  "created_at": "2026-09-02T00:00:00Z"
}
```
3. POST to `/webhooks` with `X-Github-Event: status` and the computed `X-Hub-Signature`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and verifies successfully against attacker's own secret.
5. `StatusHandler#process` runs `Commit.where(sha: "abcd123")` — matching the victim's commit regardless of `attacker-org` — and creates a forged "success" status on it, potentially unblocking merge/deploy safety checks for `victim-org/victim-repo`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
