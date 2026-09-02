### Title
Cross-Repository Commit-Status Forgery via Global SHA Lookup Breaks Webhook Organization/Repository Binding - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates an incoming GitHub webhook against the GitHub App configured for the **organization named in the payload's `repository.owner.login`** field, but that same `repository` field is discarded once the payload reaches the event handler. `StatusHandler#process` looks up the target `Commit` purely by its **global SHA value across the entire Shipit installation**, with no scoping to the repository/organization that was actually authenticated. This breaks the trust binding `{authenticated organization} == {repository/commit actually written}`, exactly analogous to the Nomad `onReceive()` bug where `transferId` was verified but `_amount`/`_localToken` were not bound to it.

### Finding Description
`WebhooksController#verify_signature` derives the signing organization from the payload itself: [1](#0-0) [2](#0-1) 

It then dispatches the *entire* raw parsed payload to the matching handler without re-checking that the org used for HMAC verification is the same entity that will actually be mutated: [3](#0-2) 

`Shipit::Webhooks::Handlers::StatusHandler` (registered for the `status` event) only declares `sha`, `state`, `description`, `target_url`, `context`, `created_at`, `branches` in its params contract — it never requires or consults `repository`: [4](#0-3) 

The actual write is performed by a **global, unscoped** lookup: [5](#0-4) 

`Commit.where(sha: params.sha)` matches every `Commit` row in the database with that SHA, irrespective of which `Repository`/`Stack`/organization it belongs to. Since a Git commit SHA is a hash of tree/parent/author/message content only, it is identical across forks, mirrors, or any repository that happens to share the same commit (a common, legitimate occurrence for forked or mirrored repositories tracked by different Shipit stacks). Any organization/app owner who can legitimately sign a webhook for **their own** installed GitHub App (satisfying `verify_signature`) can therefore forge a `status` event whose `sha` matches a commit that lives in a **different, unrelated stack**, and have `commit.create_status_from_github!(params)` write an attacker-controlled `state`/`description`/`context` onto that victim commit.

This status is consumed downstream by stack-level gating logic that determines merge/deploy readiness: [6](#0-5) 

`branch_status`/`merge_status` read `commit.status.simple_state` to decide whether a branch is deployable/mergeable — logic driven entirely by the forged status row.

### Impact Explanation
The binding broken is: `authenticated_organization == repository/commit actually written`. Before the attack, a webhook signed by Org A's registered GitHub App can only legitimately affect Org A's own repositories/stacks. After exploitation, a webhook correctly signed by Org A (using credentials Org A legitimately possesses for its own App) can write a forged commit status onto a commit belonging to Org B's stack, as long as the two repositories share a commit SHA (e.g., forks/mirrors of the same upstream). A forged `success` status can unblock `merge_status`/`branch_status` for that commit in the victim stack, contributing to an **unauthorized deploy or merge** — the impact category explicitly listed as Critical in this engine's threat model.

### Likelihood Explanation
Exploitation requires only: (1) the attacker's own GitHub App is validly registered/installed on some organization tracked by the same Shipit instance (satisfying `verify_signature` for their own org), and (2) the target commit SHA also exists in a stack the attacker does not control (trivially achievable by forking a public repository the victim also tracks, or by any repository relationship that duplicates history). No repository write access, GITHUB_TOKEN, or Shipit session is needed — only the ability to legitimately trigger/craft a `status` webhook for one's own installed app, which is a normal, unprivileged capability for any org that has installed the Shipit GitHub App.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` (and any other handler that mutates state) to the repository identified by the verified `repository_owner`/`full_name`, e.g. `commit.stack.repository.full_name == params.repository.full_name`, rather than matching on SHA alone across the entire installation. More generally, `WebhooksController` should pass the already-verified repository identity into every handler and every handler should assert that the entity being written belongs to that same repository before performing any mutation.

### Proof of Concept
1. Attacker registers/operates their own legitimate GitHub App installation for `OrgAttacker`, which Shipit also tracks (any onboarded customer can do this).
2. Attacker forks (or otherwise obtains a repository sharing commit history with) the victim's tracked repository, so that a specific commit SHA `S` exists both in the victim's Shipit stack and in a repository owned by `OrgAttacker`.
3. Attacker sends a `status` webhook to `/webhooks` with `X-Github-Event: status`, correctly HMAC-signed using `OrgAttacker`'s own `webhook_secret`, and body:
   ```json
   {
     "sha": "S",
     "state": "success",
     "context": "ci/forged",
     "repository": {"owner": {"login": "OrgAttacker"}}
   }
   ```
4. `verify_signature` succeeds because the signature matches `OrgAttacker`'s app config.
5. `StatusHandler#process` runs `Commit.where(sha: "S")`, which returns the victim's commit (belonging to a different stack/organization) and creates a forged `success` status on it via `commit.create_status_from_github!`.
6. The victim stack's `branch_status`/`merge_status` now reflect the forged status, potentially unblocking deploy/merge for that commit.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-18)
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/stack.rb (L286-300)
```ruby
    def merge_status(backlog_leniency_factor: 2.0)
      return 'locked' if locked?
      return 'failure' if %w[failure error].freeze.include?(branch_status)
      return 'backlogged' if backlogged?(backlog_leniency_factor:)

      'success'
    end

    def backlogged?(backlog_leniency_factor: 2.0)
      maximum_commits_per_deploy && (undeployed_commits_count > maximum_commits_per_deploy * backlog_leniency_factor)
    end

    def branch_status
      undeployed_commits.each do |commit|
        state = commit.status.simple_state
```
