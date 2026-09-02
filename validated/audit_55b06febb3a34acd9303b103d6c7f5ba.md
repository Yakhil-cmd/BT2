### Title
Unscoped `Commit.where(sha:)` in `StatusHandler#process` lets any repository's status webhook mutate another repository's commit status - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely by SHA — `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — with no check that the SHA belongs to the repository that authenticated the incoming webhook. Because git SHAs are content-addressed and identical across forks/mirrors, an attacker who controls a GitHub repository (with the Shipit GitHub App installed on it, which is a normal, unprivileged integration setup, not a Shipit-privileged role) can push/mirror a commit that already exists in a victim's tracked repository and then post a `status` event for that SHA with `context: security/scan, state: failure`. GitHub delivers this webhook correctly signed for the attacker's own organization, but `StatusHandler` applies the status to **every** `Commit` record sharing that SHA, including the victim's, changing the victim commit's status group and `deployable?`/merge eligibility.

### Finding Description
The broken binding is: **the party that authenticates a `status` webhook (`repository_owner` in the payload, verified by `GitHubApp#verify_webhook_signature` in `WebhooksController#verify_signature`) MUST equal the party whose commit/stack records are mutated.** This does not hold.

Path:
1. `Shipit::WebhooksController#create` (app/controllers/shipit/webhooks_controller.rb:10-15) parses the payload and dispatches to `Shipit::Webhooks.for_event(event)`, after `verify_signature` (lines 24-49) validates the HMAC using `Shipit.github(organization: repository_owner)` — i.e., the app/secret configured for the *attacker's own* organization, since `repository_owner` is read straight from the attacker-controlled payload (`params.dig('repository','owner','login')`, line 61). This check only proves the webhook truly came from GitHub for that org/repo — it proves nothing about which commit rows may be touched.
2. `StatusHandler#process` (app/models/shipit/webhooks/handlers/status_handler.rb:20-24):
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
There is no filter by `repository`/`stack`, only by `sha`. [1](#0-0) 
3. `Commit#create_status_from_github!` calls `add_status { statuses.replicate_from_github!(stack_id, github_status) }`, using the *matched commit's own* `stack_id` [2](#0-1) . This means the write lands correctly attributed to whichever stack/commit row matched by SHA — the flaw is entirely in *which commits get matched*, not in mis-attributing the stack_id afterward.
4. Since SHAs are content-addressed, an attacker who forks/mirrors a victim's public commit into their own attacker-owned, Shipit-App-integrated repository produces an identical SHA. The attacker then creates (or has GitHub emit) a genuine `status` event for that SHA on their own repo with `context: security/scan, state: failure`. `verify_signature` passes because it's a legitimately signed webhook for the attacker's own org. `StatusHandler#process` then finds and mutates the victim's `Commit` row that happens to share that SHA (e.g., because both stacks track the same open-source dependency/commit, or because the victim's repo was forked).
5. Existing guards fail to stop this: `verify_signature` checks *authenticity of the sender*, not *ownership of the target commit rows*; `drop_unhandled_event` only checks the event type is registered; `ExplicitParameters` in `StatusHandler.params` validates payload shape only (`sha`, `state`, `context`, etc.), not repository scoping; there's no `Repository`/`Stack` scoping check anywhere in `StatusHandler`.

Once the malicious status lands on the victim commit, `security/scan` being in `commit.required_statuses` (via `ci.require` deploy spec) causes `Status::Group`/`Common#required?` to include it, and a `failure` state flips `commit.state`, `Status::Group#failure?`, and downstream `deployable?`/merge-eligibility gating logic [3](#0-2) [4](#0-3) .

### Impact Explanation
This is a cross-tenant/cross-repository state-manipulation bug: a webhook authenticated only for repository A can write `Status` rows and flip `deployable?`/merge state for commits belonging to repository B's stack, with no relationship required between A and B other than a shared commit SHA (achievable cheaply via forking/mirroring public commits, or exploiting shared upstream dependency commits tracked by multiple stacks). This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team." The attacker can repeatedly flip a required status (e.g., `security/scan`) to `failure` to block deploys/merges on an arbitrary victim stack, or flip it to `success` to force-pass a gate it doesn't actually satisfy, undermining `deployable?`/merge-eligibility trust across the whole install.

### Likelihood Explanation
Preconditions: attacker needs a GitHub repository with the Shipit GitHub App/webhook installed (a normal, low-privilege integration action any repo owner or org admin can do, not a Shipit role) and needs a commit SHA that also exists in the victim's tracked `Commit` table (achievable via forking a public repo, mirroring, or targeting a commonly-shared/vendored commit). No Shipit credentials, session, or API token are required. The exploit is fully repeatable against any repository whose commits are discoverable/forkable, making it low-cost and broadly repeatable.

### Recommendation
Scope `StatusHandler#process` (and analogous handlers) to the repository that authenticated the webhook: filter `Commit.where(sha: params.sha)` further by joining `stack.repository` matched against `params.repository.full_name` (or equivalent), e.g. `Commit.where(sha: params.sha).joins(:stack).merge(Stack.where(repo_owner: ..., repo_name: ...))`, ensuring only commits belonging to the authenticated repository are updated.

### Proof of Concept
Minitest plan (no live GitHub):
1. Seed a victim `Stack` with `cached_deploy_spec` containing `'ci' => {'require' => 'security/scan'}`.
2. Create a victim `Commit` (`sha: 'deadbeef...'`) under the victim stack with an existing passing status set so `deployable?` is true.
3. Create a second, unrelated `Stack`/`Repository` ("attacker" repo) and a `Commit` with the *same* `sha` under that attacker stack (simulating a shared/forked SHA).
4. Build `StatusHandler` params: `{ sha: 'deadbeef...', state: 'failure', context: 'security/scan', branches: [] }`, and call `Shipit::Webhooks::Handlers::StatusHandler.new(...).process` (or POST to `/webhooks` with `X-Github-Event: status` and a valid signature for the attacker's org, using `repository.owner.login` = attacker org).
5. Assert:
   - Before: `victim_commit.deployable?` == `true`, `victim_commit.status.state != 'failure'`.
   - After processing: `victim_commit.reload.status.state == 'failure'` and `victim_commit.deployable? == false`, even though the webhook only authenticated for the attacker's repository/org — proving the equality "authenticated repository == mutated repository" is violated. [5](#0-4) [6](#0-5) [2](#0-1)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-28)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
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
      end
    end
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

**File:** app/models/shipit/status/common.rb (L46-52)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end

      def required?
        commit.required_statuses.include?(context)
      end
```

**File:** app/models/shipit/status/group.rb (L24-32)
```ruby
      def initialize(commit, statuses)
        @commit = commit

        visible_statuses = reject_hidden(statuses.to_a.uniq(&:context))
        missing_contexts = required_statuses - visible_statuses.map(&:context)
        visible_statuses += missing_contexts.map { |c| Status::Missing.new(commit, c) }

        @statuses = visible_statuses.sort_by!(&:context)
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
