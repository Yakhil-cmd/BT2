## Analysis

This confirms the vulnerability. `Handler#stacks` resolves the target stack from `payload.dig('repository', 'full_name')` [1](#0-0) , which is looked up via `Repository.from_github_repo_name` by splitting `owner/name` from that same field [2](#0-1) . Meanwhile, `WebhooksController#verify_signature` selects which GitHub App/webhook secret to verify the HMAC against using a *different* field: `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`) [3](#0-2) . Nothing in the engine enforces that `repository.full_name`'s owner segment matches `repository.owner.login`/`organization.login`. In a multi-org Shipit deployment (explicitly documented in `config/secrets.development.example.yml` lines 18-38, each org has its own independent `webhook_secret`), an attacker who is an admin of their own legitimately-configured GitHub org can self-sign an arbitrary JSON body with their own org's secret, set `repository.owner.login`/`organization.login` to their own org (so `verify_signature` picks their own valid secret and passes), while setting `repository.full_name` to `"victim-org/victim-repo"`. The signature check passes and the same raw payload is then dispatched to handlers (e.g. `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, `MembershipHandler`), which act on `repository.full_name` to find and mutate the victim's `Stack`/`Commit`/`Team`/`Membership` records — an authenticated-organization-vs-written-repository binding break.

### Title
Webhook signature verification binds to `repository.owner.login`/`organization.login` while handlers act on the unverified `repository.full_name`, allowing cross-organization webhook forgery - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to validate an incoming webhook's HMAC using `repository.owner.login` (or `organization.login`), but every event `Handler` resolves the affected `Stack` via `repository.full_name`. These two fields are never checked for consistency, so any organization with its own legitimately configured GitHub App/webhook secret can forge a signed webhook whose `owner.login` matches their own org (to pass verification) while `full_name` points at a completely different, victim-owned repository.

### Finding Description
`verify_signature` computes:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
and validates the raw POST body's HMAC signature against `Shipit.github(organization: repository_owner)`'s configured `webhook_secret` [4](#0-3) .

After this check passes, `create` re-parses the same raw body and dispatches it unchanged to registered handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [5](#0-4) .

Every handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) inherits `Handler#stacks`, which resolves the target `Repository`/`Stack` from a **different** payload field, `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [1](#0-0) 

`Repository.from_github_repo_name` splits this field on `/` to get owner/name and looks up the DB record directly [2](#0-1) , with no cross-check against `repository.owner.login`.

The binding that is broken: **the organization authenticated by the HMAC check (`repository.owner.login`) is not the same field as the repository whose `Stack` state is written (`repository.full_name`)**. Shipit explicitly supports configuring independent `webhook_secret`s per GitHub organization (see the multi-org example in `config/secrets.development.example.yml` lines 18-38), so a legitimate admin of Org A knows Org A's `webhook_secret` and can produce a valid signature for a payload whose `repository.owner.login = "org-a"` (passes verification) but whose `repository.full_name = "org-b/victim-repo"` (acted on by the handler).

### Impact Explanation
This allows a user who only controls one organization's GitHub App installation on a shared/multi-org Shipit instance to forge webhook events (push, status, check_suite, membership, pull_request, etc.) that are processed as if they came from a completely different, victim organization's repository. Concretely this can:
- Trigger `GithubSyncJob`/`sync_github` on a victim's `Stack` with an attacker-chosen `expected_head_sha`, influencing commit ingestion and continuous-deployment triggers for a repository the attacker does not own [6](#0-5) .
- Inject forged commit `Status` records or check-run refresh triggers against a victim stack's commits.
- Manipulate `Team`/`Membership` records via the `membership` handler using attacker-controlled `organization.login`/`team` data while such objects are shared globally.

Given continuous deployment can be configured on stacks, and Shipit's deploy/merge pipeline reacts to CI status and push events, this can plausibly be leveraged toward an unauthorized deploy or corrupted deployment state for a repository the attacker doesn't control — satisfying the "unauthorized deploy" High-impact bucket, contingent on the specific handler reached and stack configuration.

### Likelihood Explanation
Requires the attacker to control (or be an admin of) at least one GitHub organization/App that is itself legitimately configured in the same multi-tenant Shipit instance (a scenario the engine documents and supports), and to craft a raw JSON payload by hand (bypassing GitHub's UI) since the mismatch between `owner.login` and `full_name` never legitimately occurs in genuine GitHub-issued webhooks. This is plausible in shared/multi-org Shipit deployments but not exploitable against a single-org, single-secret installation (where `repository_owner` and `full_name`'s owner segment necessarily belong to the same tenant).

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), enforce that the owner segment of `repository.full_name` matches `repository.owner.login` (or `organization.login`) before processing, rejecting payloads where they diverge. Alternatively, resolve the target `Stack`/`Repository` using the same verified `repository_owner` value used for signature selection, rather than trusting `full_name` independently.

### Proof of Concept
1. Configure Shipit with two GitHub orgs, `org-a` and `org-b`, each with its own `github.webhook_secret` (per the multi-org example in `config/secrets.development.example.yml`).
2. As an admin of `org-a`, know `org-a`'s `webhook_secret`.
3. Craft a push webhook JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  }
}
```
4. Compute `X-Hub-Signature: sha1=<hmac_sha1(org-a-webhook-secret, body)>`.
5. POST to `/webhooks` with `X-Github-Event: push`.
6. `verify_signature` computes `repository_owner = "org-a"`, verifies successfully against `org-a`'s secret [7](#0-6) .
7. `PushHandler.process` resolves stacks via `Repository.from_github_repo_name("org-b/victim-repo")` and calls `stack.sync_github(expected_head_sha: "deadbeef")` on `org-b`'s stack [6](#0-5) , even though the attacker has no relationship with `org-b`.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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
