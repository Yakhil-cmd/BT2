### Title
`status` webhook binds signature verification to the payload's organization but writes commit status to any commit matched globally by SHA, breaking the "organization authenticated == repository written" trust boundary - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound GitHub webhook solely against the organization/owner derived from the payload (`repository.owner.login`, falling back to `organization.login`), and looks up the matching GitHub App/webhook secret for *that org only*. [1](#0-0) [2](#0-1) 

However, once the signature is accepted, `Shipit::Webhooks::Handlers::StatusHandler#process` performs its write with **no repository binding at all** — it looks up the target `Commit` purely by SHA across the entire Shipit database, and never validates that the `repository` field in the payload (or the authenticated organization) matches the commit's actual stack/repository: [3](#0-2) 

This is the same class of bug as the reported issue: a value used at authentication/verification time (`rateData.protocolFeeRate` vs. the interest-rate/liquidity state it should synchronize) diverges from the value actually acted upon downstream. Here, the "organization" bound by `verify_signature` diverges from the "repository" whose commit status is actually mutated.

### Finding Description
`Shipit` supports multiple independent GitHub App configurations, one per organization, each with its own `webhook_secret` (see `test/dummy/config/secrets_double_github_app.yml`, which configures `OrgTwo` with a distinct app/secret). `verify_signature` selects which secret to check against using only the org login extracted from the incoming payload:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [4](#0-3) 

This only proves the request was signed with *some org's* configured secret — it establishes no binding to the specific `repository` (or commit) that the event payload subsequently mutates. Once `create` dispatches to the registered handler for the event type, `StatusHandler` (invoked for GitHub `status` events) never re-checks `repository` at all:

```ruby
params do
  requires :sha, String
  requires :state, String
  accepts :description, String
  accepts :target_url, String
  accepts :context, String
  accepts :created_at, String
  accepts :branches, Array do
    requires :name, String
  end
end

def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [5](#0-4) 

Note `repository` is not even a declared/required parameter for this handler — unlike `PushHandler`, `CheckSuiteHandler`, or the `PullRequest::*` handlers, which all scope their queries through `stacks` (derived from `Repository.from_github_repo_name(payload.dig('repository','full_name'))`). [6](#0-5) [7](#0-6) 

Equality that should hold but doesn't:
`organization authenticated by verify_signature (payload.repository.owner.login)` == `repository/stack whose Commit is mutated by StatusHandler (found purely via global Commit.where(sha:))`

Before the attacker's request: a `status` event correctly scoped to a commit in repo/org X only affects commits belonging to X because in practice X's own CI is the only entity capable of producing a signed webhook naming a commit sha from X's history.

After the attacker's crafted request: an org Y (tracked separately by Shipit with its own GitHub App/webhook secret) can produce a *validly signed* `status` webhook (signed with Y's own secret, satisfying `verify_signature`) whose `sha` field names a commit that actually belongs to a *different* tracked stack/repository (e.g., a shared/forked commit history, a mirrored repository, or a commit SHA the attacker learns from the target stack's public commit history/API). `StatusHandler` will happily attach that fabricated status to the unrelated commit, because it never checks that the sha's owning repository matches the authenticated organization.

### Impact Explanation
Commit statuses gate Shipit's deploy-safety logic: `Commit#create_status_from_github!` feeds into the commit's aggregated CI status, which in turn is used by `Stack`/`UndeployedCommit`/`release_status` checks (`test/unit/shipit_deployment_checks_test.rb`, `Stack` delegating `release_status?`) to decide whether a commit is deployable. By forging a `status` event from an org whose webhook the attacker can legitimately trigger (their own tracked, unprivileged organization), they can inject a fabricated "success"/"failure" status onto a commit belonging to a **different** organization's stack that Shipit also tracks — flipping deployability checks and enabling an unauthorized deploy (or blocking a legitimate one) on a repository the attacker has no authorization over. This matches the "unauthorized deploy" Critical/High impact category, since it breaks the binding between the authenticated organization and the repository/commit actually written.

### Likelihood Explanation
Exploitability depends on the attacker being able to name a `sha` that exists in the target stack's `commits` table. This is realistic in common Shipit deployment topologies: forked/mirrored repositories that share git history across organizations, review-app repos that clone from an upstream org, or simply an attacker with legitimate but unprivileged webhook-triggering rights on their own tracked org guessing/observing a target commit sha from public commit history or the Shipit UI (commit shas are visible in Shipit's own web UI/API without requiring the "read:stack" permission gate that protects the API, since the web UI lists commits for all non-archived stacks by default). No repository write access, GitHub App private key, or Shipit session/API token is required — only the ability to have one's own tracked org emit a webhook (e.g., posting a commit status via the GitHub API to a repo the attacker controls, or via any CI integration on that repo).

### Recommendation
`StatusHandler#process` (and any other handler doing GitHub-payload-driven writes) should scope commit lookups through the `repository` field of the payload, mirroring the pattern used by `PushHandler`/`CheckSuiteHandler`/`Handler#stacks`, e.g.:

```ruby
params do
  requires :sha, String
  requires :state, String
  requires :repository do
    requires :full_name, String
  end
  ...
end

def process
  stacks.flat_map(&:commits).select { |c| c.sha == params.sha }.each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

More generally, `verify_signature` should not be treated as proof that the *entire payload* (including unrelated repository/commit references) is trustworthy for the specific repository being mutated — every handler must independently re-derive its target scope from `payload.dig('repository', 'full_name')` and verify it against the authenticated organization, rather than trusting global lookups keyed only on attacker-controlled fields like `sha`.

### Proof of Concept
1. Shipit is configured (per `test/dummy/config/secrets_double_github_app.yml`) to track two organizations, `OrgOne` and `OrgTwo`, each with a distinct GitHub App/`webhook_secret`, and each has a stack with tracked commits (`Repository.from_github_repo_name`).
2. Attacker controls a repository under `OrgOne` (e.g. as a contributor able to trigger CI/status webhooks to Shipit — no Shipit account or API token needed).
3. Attacker learns (via Shipit's public commit list or GitHub) a commit SHA belonging to a stack under `OrgTwo` that shares history with, or is otherwise reachable from, a repo they control (e.g. a fork).
4. Attacker triggers a `status` event on their own `OrgOne` repository/CI with `sha` set to that `OrgTwo` commit SHA and `state: "success"`.
5. GitHub signs the webhook with `OrgOne`'s legitimate `webhook_secret`; `verify_signature` calls `Shipit.github(organization: 'OrgOne')` and the signature validates.
6. `StatusHandler#process` executes `Commit.where(sha: params.sha)`, finds the `OrgTwo` commit (no repository check), and calls `commit.create_status_from_github!(params)`, injecting a forged status onto a commit in `OrgTwo`'s stack that the attacker has no authorization over — potentially flipping that stack's deployability/CI checks.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-24)
```ruby
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
