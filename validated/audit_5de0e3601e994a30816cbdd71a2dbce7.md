### Title
Unscoped status webhook `Commit.where(sha:)` lookup allows cross-repository CI-status forgery when SHA is shared with a victim repo - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely by `params.sha` across the entire `commits` table with no constraint on the repository/organization that authenticated the webhook, and writes a `Status` for every matching row. If any commit with that SHA exists on a Shipit-tracked stack outside the attacker's own repo/org (e.g., because it was forked from, or merged into, the victim's repo), a signed webhook from the attacker's own organization can flip that victim commit's CI state.

### Finding Description
The broken binding the code should enforce is: `status.repository == commit.stack.repository` (a status must only ever affect the commit belonging to the repository that emitted it). Instead the code enforces only: `params.sha == commit.sha`, with no join or filter on `stack.repository` or `repository_owner`.

Path: `Shipit::WebhooksController#create` parses the JSON body and dispatches to handlers for the `X-Github-Event` header [1](#0-0) . Before dispatch, `verify_signature` computes `repository_owner` from `params.dig('repository','owner','login')` (or `organization.login`) and validates the HMAC signature against the webhook secret configured for **that** organization via `Shipit.github(organization: repository_owner)` [2](#0-1) . This proves only that the request was signed with the secret belonging to the organization named in the payload — an org the attacker legitimately controls (their own fork/org with the Shipit GitHub App installed) — it says nothing about which specific `stack`/`Commit` row the payload is allowed to mutate.

`StatusHandler`'s params schema requires only `sha`, `state`, and optional `context`/`description`/`target_url`/`created_at`/`branches` — there is no `repository` requirement at all [3](#0-2) . `process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [4](#0-3) 
This queries `Commit` globally, matching **every** stack in the database that has ever recorded a commit with that exact SHA, and calls `create_status_from_github!` on each one, which appends a `Status` row and re-evaluates deployability/blocking via `add_status` [5](#0-4) [6](#0-5) . This can flip `deployable?`/`blocked?` and trigger `stack.schedule_merges` for the victim stack [7](#0-6) [8](#0-7) .

Because Git commit SHAs are content-addressed and independent of the remote they are pushed to, a commit an attacker authors and pushes to their own fork (which they then push/PR to the victim's upstream repo, or which is later cherry-picked/merged unchanged) will retain the exact same SHA in both the attacker's own repository and the victim's tracked repository. An attacker who owns a GitHub org/repo with a Shipit GitHub App installation (their own fork or personal org) can trigger a genuine, correctly-signed `status` webhook for that SHA (e.g., their own CI reporting `context: ci/lint`) from their side. `verify_signature` will pass because the signature matches the attacker's own org's `webhook_secret`. `StatusHandler#process` then matches the victim's `Commit` row purely by SHA and writes the forged status onto it, with no check that the emitting organization/repository corresponds to the stack that owns that commit.

Existing guards do not close this gap: `verify_signature` authenticates the org, not the commit's ownership; `drop_unhandled_event` only filters unknown event types; the `ExplicitParameters` schema for `StatusHandler` never requires or validates `repository`; there is no `require_permission!`/`stacks` scope involved since this is an unauthenticated webhook path, not a session-based one.

### Impact Explanation
A successfully forged status write mutates a `Commit`/`Status` belonging to a repository/stack the attacker never authenticated for, satisfying "a payload for one repository mutating another's stack, commit, task or team." This can flip `deployable?` (unblocking a stack for continuous deployment) or `blocked?` (freezing a legitimate deploy), and can call `stack.schedule_merges`, potentially triggering an unauthorized merge/deploy action on the victim stack — a Critical-severity cross-tenant state manipulation. It is repeatable against any victim stack that shares a commit SHA with an attacker-controlled repo (forks, cherry-picked commits, shared history).

### Likelihood Explanation
Preconditions: the attacker needs (1) their own GitHub org/repo with the Shipit GitHub App installed (any user setting up their own installation, or forking into an org where Shipit is already configured) so they can get a genuinely signed `status` webhook delivered, and (2) a commit SHA that is also present as a `Commit` row on a victim's Shipit stack (trivially achieved by forking the victim repo or by the victim merging the attacker's PR — commit SHAs survive across forks/merges unchanged). No Shipit secrets or victim credentials are required. This is a realistic, low-cost, fully repeatable attack pattern in any multi-tenant or fork-based Shipit deployment tracking multiple repositories/orgs.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` (and the analogous `CheckRunHandler`/other SHA-keyed handlers) by the repository that authenticated the webhook, e.g. join through `stack.repository` matching `params.repository.full_name` (or `repository_owner`), and require `repository` in the params schema so a status can only be applied to commits belonging to stacks in the repository that sent it.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (conceptual, minitest)
test "status handler mutates commits across unrelated repositories sharing a SHA" do
  victim_stack = shipit_stacks(:shipit)  # repo_name: 'shopify/shipit-engine'
  shared_sha = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef'

  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: 'victim commit')

  # Equality claimed broken: status.repository (attacker org) != victim_commit.stack.repository
  assert_not_equal 'attacker-org/attacker-repo', victim_stack.github_repo_name

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/lint'
  }

  Shipit::Webhooks::Handlers::StatusHandler.new(nil, payload).process

  victim_commit.reload
  # Victim commit received a status even though the webhook never authenticated
  # against victim_stack's repository/organization.
  assert victim_commit.statuses.exists?(context: 'ci/lint', state: 'success')
end
```
This demonstrates that `StatusHandler#process`'s `Commit.where(sha: params.sha)` writes to a commit irrespective of which repository/organization signed the webhook, confirming the cross-repository mutation described in the question.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```
