### Title
Cross-repository commit status forgery via unscoped SHA lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` updates commit statuses by looking up commits **solely by SHA**, with no verification that the SHA belongs to the repository/organization whose webhook signature was actually verified. This breaks the equality `organization authenticated (via `verify_webhook_signature` on `repository.owner.login`) == repository whose Commit row is written (via `Commit.where(sha: params.sha)`)`. Because Git SHAs are content-addressed and identical across forks/copies until history diverges, an attacker who controls (or forks) any repository with an identical commit can forge a `status` webhook that is validly signed for *their own* organization but that mutates the commit-status state of a *different, unrelated* tracked stack's commit.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/organization whose secret must sign the payload strictly from the payload's own `repository.owner.login` (or `organization.login`) field: [1](#0-0) [2](#0-1) 

This only guarantees that the signature matches *some* organization's registered webhook secret — it says nothing about which `Commit`/`Stack` will end up being mutated by the handler. The dispatch then hands the raw, self-declared `params` straight to the handler: [3](#0-2) 

`StatusHandler#process`, unlike `PushHandler` (which scopes lookups through `Repository.from_github_repo_name(repository_name)` via `Handler#stacks`), performs a **global** lookup by `sha` alone, with no repository/stack scoping at all: [4](#0-3) [5](#0-4) 

Because Git commit SHAs are computed purely from commit content (tree, parents, author/committer, message/timestamp), two different repositories legitimately tracked by the same Shipit instance can contain a `Commit` row with the identical `sha` — for example when one repository is a fork/mirror of another, or shares history via a common ancestor prior to divergence. The webhook signature only proves "this payload came from GitHub for the organization named in the payload's `repository.owner.login`" — it does **not** prove "this `sha` belongs to that organization's repository." An attacker who controls (or has push access to) any organization/repository independently registered as a Shipit stack can therefore:
1. Fork or otherwise obtain a repository containing a commit whose SHA equals a commit SHA already tracked in a *different, unrelated* stack (the target).
2. Trigger a GitHub `status` event on their own repository for that SHA (e.g., via their own CI, a GitHub Action, or the Statuses API on a repo they control) with `state: "success"`.
3. GitHub signs and delivers this webhook using the attacker's own organization's legitimate webhook secret — the signature check in `verify_signature` passes because it is validated against the attacker's own org, not the victim's.
4. `StatusHandler#process` finds the victim's `Commit` row purely by matching `sha` and calls `commit.create_status_from_github!(params)`, forging a green/passing status on the victim stack's commit — a write into a repository/stack the attacker's authenticated organization has no relationship to.

This is the exact analog of the reported bug class: a value ("BTC" price) is trusted as a stand-in for a related-but-distinct value ("WBTC" price) without verifying they remain equivalent. Here, "the organization whose signature was verified" is trusted as a stand-in for "the repository whose commit is being mutated," without verifying the commit actually belongs to that organization's repository.

### Impact Explanation
Commit statuses gate whether Shipit considers a commit "deployable" (required CI checks green) via `Commit#create_status_from_github!` and the stack's deployable-status computation. Forging a passing status for a required check on an unrelated stack's commit can make Shipit believe an otherwise-blocked commit is safe to deploy, enabling an **unauthorized deploy** of code whose real CI checks never passed — a cross-repository write into the victim's commit-status/deployability state from an attacker who was never authorized on that repository. This satisfies the Critical bar (cross-repository writes / unauthorized deploy).

### Likelihood Explanation
Exploitation requires the attacker to control at least one repository/organization already registered with this Shipit instance (an "unprivileged" tenant, not a privileged Shipit account) and to find or engineer a SHA collision with a targeted stack's commit — most realistically via forks/mirrors sharing history, which is common in mono-organization or open-source setups. No Shipit session, `ApiClient` token, or knowledge of another org's `webhook_secret` is required, since the forged webhook is legitimately signed by GitHub for the attacker's own organization.

### Recommendation
Scope `StatusHandler#process` (and any other handler performing bare `sha`-based lookups) to the repository named in the webhook payload, mirroring `Handler#stacks`/`Repository.from_github_repo_name`, e.g. restrict the `Commit.where(sha: params.sha)` query to commits belonging to stacks/review-stacks of `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))` before applying `create_status_from_github!`.

### Proof of Concept
1. Configure Shipit to track two independent stacks/repositories, `victim-org/app` and `attacker-org/app-fork`, where `attacker-org/app-fork` is a fork of `victim-org/app` sharing a common commit `X` (identical SHA) that is currently pending/blocking deploy in `victim-org/app`.
2. As the owner of `attacker-org/app-fork` (an unprivileged Shipit tenant with no access to `victim-org`), trigger a GitHub `status` event on commit `X` in `attacker-org/app-fork` with `state: "success"` (e.g., via a GitHub Action `Statuses` API call on their own repo).
3. GitHub signs and posts this webhook to Shipit's `WebhooksController#create`; `verify_signature` succeeds because it validates against `attacker-org`'s own webhook secret.
4. `StatusHandler#process` executes `Commit.where(sha: 'X').each { |commit| commit.create_status_from_github!(params) }`, which matches and updates the `Commit` row belonging to `victim-org/app`, marking the victim's blocking check as green and potentially unlocking deployment for a commit that never actually passed CI in the victim's repository.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
