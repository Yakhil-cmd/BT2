### Title
Cross-repository forged GitHub `status` webhook satisfies another stack's required-status gate - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves target commits by SHA alone across the entire database, `Commit.where(sha: params.sha)`, without checking that the webhook's `repository.full_name` matches the repository/stack that owns the matched commit(s). Any GitHub user who can trigger a genuine, correctly-signed `status` webhook from a repository they control can write a `success` status into a `victim` stack's commit whenever a commit with the same SHA also exists there, flipping that commit's required-status check from "missing" to "allowed".

### Finding Description
The broken binding is: **the repository that authenticated the webhook signature (`payload.dig('repository','owner','login')` used in `WebhooksController#verify_signature`) must equal the repository whose required-status gate is being satisfied**. This binding is violated.

Path:
1. `WebhooksController#verify_signature` [1](#0-0)  only checks that the raw payload was signed by the GitHub App belonging to the organization named in the payload itself (`repository_owner`). It proves the payload really came from GitHub for *that* org/repo — it says nothing about which Shipit stack the referenced commit SHA belongs to.
2. Dispatch calls `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` with the raw, attacker-controlled JSON payload [2](#0-1) .
3. `StatusHandler#process` ignores the payload's `repository` entirely and looks up commits globally: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [3](#0-2) . Compare with the base `Handler` class, which *does* provide a repo-scoped `stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`) that other handlers use [4](#0-3)  — `StatusHandler` never calls it.
4. `Commit#create_status_from_github!` writes the status using the matched commit's own `stack_id` (i.e., the victim stack's ID), not any ID derived from the webhook's declared repository: `statuses.replicate_from_github!(stack_id, github_status)` [5](#0-4) , and `Status.replicate_from_github!` persists it as-is [6](#0-5) .
5. `Status::Group` computes `missing_contexts = required_statuses - visible_statuses.map(&:context)` [7](#0-6) ; once any status row exists for a required context — regardless of which repository actually produced it — the context is no longer reported missing, and `Commit#deployable?`/`CommitChecks`/`UndeployedCommit#deploy_state` will report the Deploy button as allowed instead of missing.

Attacker request: push a commit to a repository they own/control whose SHA is identical to a commit already present in `victim`'s stack (git commit SHAs are content-addressed over tree, parents, author, committer, timestamps and message, so an attacker who observes a `victim` commit — e.g. from a public branch, PR, or shared upstream — can reproduce byte-for-byte and obtain the same SHA in their own repo), then have GitHub (or their own CI) send a `status` event for `attacker/repo` with `state: success` and `context` equal to the context `victim`'s `deploy_spec.required_statuses` expects. This webhook is genuinely signed for `attacker/repo`'s org, so `verify_signature` passes legitimately — the forgery is not in the signature, it is in `StatusHandler` failing to scope the write to the authenticated repository.

None of the existing guards prevent this: `verify_signature` validates payload authenticity per-org but not per-commit ownership; `drop_unhandled_event` only filters unregistered event types; `ExplicitParameters` schema only validates field shapes (`sha`, `state`, `context`, etc.) [8](#0-7) , not repository ownership of the SHA.

### Impact Explanation
An attacker fully controlling their own GitHub repository can, without any Shipit credentials, cause a Shipit-tracked `victim` stack's required CI check to transition from `missing`/pending to `success`, unblocking the Deploy button for code whose real CI on `victim`'s repository never validated that check. This is a cross-tenant write: a payload authenticated for `attacker/repo` mutates state (`Shipit::Status` rows, and downstream `deploy_state`) belonging to `victim`'s stack/commit. This matches the Critical category "a payload for one repository mutating another's stack, commit ... or an unauthorized deploy." It is repeatable against any stack/commit combination where a SHA collision (identical commit content) can be engineered, and does not require compromising any Shipit or GitHub secret.

### Likelihood Explanation
Preconditions: (a) `victim`'s `deploy_spec.yml` lists the target context in `ci.require`/`ci.blocking` [9](#0-8) , and (b) the attacker can reproduce a commit with the exact same tree/parents/author/committer/timestamps/message as a commit already ingested into `victim`'s stack — realistic when commits are cherry-picked between forks/mirrors or when an upstream commit is later imported into `victim`'s tracked branch. Cost to the attacker is minimal: own a GitHub repo, install/point a webhook that GitHub signs normally, and send one `status` payload. No Shipit session, API token, or team membership is required.

### Recommendation
In `StatusHandler#process` (and any other SHA-keyed handler), restrict the commit lookup to commits belonging to stacks of the repository named in the webhook payload, e.g. scope via `stacks.flat_map(&:commits).where(sha: params.sha)` (using the existing `Handler#stacks`/`repository_name` helpers) instead of the global `Commit.where(sha: params.sha)`.

### Proof of Concept
```ruby
test "cross-repo forged status webhook must not satisfy another repo's required status" do
  victim_stack = shipit_stacks(:shipit) # repository e.g. "shopify/shipit-engine"
  victim_stack.cached_deploy_spec.stubs(:required_statuses).returns(['ci/important'])
  victim_commit = shipit_commits(:cyclimse_first) # sha shared, belongs to victim_stack
  victim_commit.statuses.where(context: 'ci/important').delete_all

  undeployed = Shipit::UndeployedCommit.new(victim_commit)
  assert_equal 'missing', undeployed.deploy_state # baseline: blocked/missing

  # Forged payload: signed & authenticated for attacker's own repo, but referencing victim's SHA
  forged_payload = {
    'repository' => { 'full_name' => 'attacker/unrelated-repo', 'owner' => { 'login' => 'attacker' } },
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/important',
  }
  Shipit::Webhooks::Handlers::StatusHandler.call(forged_payload)

  victim_commit.reload
  assert_equal 'allowed', Shipit::UndeployedCommit.new(victim_commit).deploy_state
  # demonstrates victim's required-status gate was satisfied by a status
  # that never authenticated for victim's own repository
end
```

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L23-33)
```ruby
    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
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

**File:** app/models/shipit/deploy_spec.rb (L194-204)
```ruby
    def required_statuses
      (Array.wrap(config('ci', 'require')) + blocking_statuses).uniq
    end

    def soft_failing_statuses
      Array.wrap(config('ci', 'allow_failures'))
    end

    def blocking_statuses
      Array.wrap(config('ci', 'blocking'))
    end
```
