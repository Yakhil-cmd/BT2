Confirmed: `StatusHandler#process` looks up commits purely by sha, with no repository binding check.### Title
`StatusHandler#process` writes a `Status` for a commit sha without validating the payload's repository, enabling cross-repository status forgery that bypasses `Commit#blocked?` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits solely by `params.sha` across the *entire* `commits` table and calls `commit.create_status_from_github!(params)` on every match, with no check that the webhook payload's `repository.full_name` corresponds to the commit's `stack`/`repository`. An attacker who controls any repository with a webhook wired into this Shipit instance (their own GitHub org/repo, installed via a GitHub App whose webhook secret is shared across installations) can reproduce a git commit object with an identical SHA-1 to a victim's blocking-context commit (tree, parent, author/committer identity and timestamps, and message are all public), then trigger a real `status` webhook from their own repo referencing that sha. Because `Commit.where(sha: params.sha)` is unscoped by repository, the forged `success` status is written against the victim's blocking commit, flipping `blocking?` to `false` and letting `deployable?`/`Stack#trigger_continuous_delivery` ship a later, unreviewed commit.

### Finding Description
The broken binding, stated explicitly:
`repository(Status written) == repository(payload.repository.full_name)` — this equality never holds because the left side is never computed.

Code path:
- `WebhooksController#create` parses the raw JSON body and dispatches `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` after `verify_signature`, which authenticates the payload against `Shipit.github(organization: repository_owner)`'s webhook secret [1](#0-0) . This only proves the payload was signed for *some* organization the attacker legitimately controls — it says nothing about which commit sha the payload references being tied to that organization's repository.
- `Handler` provides a `stacks`/`repository_name` helper derived from `payload.dig('repository', 'full_name')` specifically so subclasses can scope lookups to the correct repository [2](#0-1) . Every other handler (`PullRequest::OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `AssignedHandler`, etc.) explicitly `requires :repository do requires :full_name, String end` and scopes its queries through `Shipit::Repository.from_github_repo_name(params.repository.full_name)` before touching any stack/commit [3](#0-2) .
- `StatusHandler`, however, does not even declare a `repository` param, and `process` does a global, unscoped lookup: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [4](#0-3) .
- `Commit#create_status_from_github!` derives the `stack_id` purely from `commit.stack_id` (the commit's own row), never from the payload: `statuses.replicate_from_github!(stack_id, github_status)` [5](#0-4) , and `Status.replicate_from_github!` persists a `Status` keyed on that `stack_id` and the forged `state` [6](#0-5) .
- `Commit#blocked?` gates deploys by scanning `stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)` [7](#0-6) , and `blocking?` is `!success? && commit.blocking_statuses.include?(context)` [8](#0-7) . Flipping the blocking commit's newest status to `success` makes `blocking?` false, so `blocked?` returns false and `deployable?` (`!locked? && (stack.ignore_ci? || (success? && !blocked?))`) becomes true for the later commit [9](#0-8) , which `Stack#trigger_continuous_delivery`/`next_commit_to_deploy` will then ship [10](#0-9) .

Attacker's exact request: POST `/webhooks` with `X-Github-Event: status`, a valid signature for a repository the attacker owns (an org/repo where they control the GitHub App installation or repo webhook config), and a body `{"sha": "<victim blocking commit sha>", "state": "success", "context": "<blocking context>", "repository": {"full_name": "attacker/own-repo"}, ...}`. To obtain a matching sha without any secret, the attacker recreates a git commit object with the same tree, parent, author/committer identity and timestamps, and message as the victim's public blocking commit (all of this is public GitHub data) inside their own repository, producing an identical SHA-1 in an unrelated repo — this is the "cross-repository sha collision" referenced in the question; it is a content-reproduction technique, not a cryptographic SHA-1 break.

Existing guards do not stop this: `verify_signature` only authenticates that the payload came from a legitimate GitHub organization/app installation the attacker actually controls — it never checks that the `sha` inside the payload belongs to that same organization's repository [11](#0-10) . `ExplicitParameters` schema for `StatusHandler` doesn't even require a `repository` field, so there's nothing to validate against [12](#0-11) . No model validation on `Status` or `Commit` cross-checks `stack.repository` against any payload-derived repository.

### Impact Explanation
An attacker who owns an arbitrary repository wired into the Shipit instance can write an arbitrary `Status` (any state: `success`, `failure`, `pending`, `error`) against any commit row in the database, in any other tenant's stack, purely by knowing/reproducing that commit's sha. Concretely, this is a payload for one repository mutating another repository's commit/stack state, which — when the target is a `blocking_statuses` context — silences a safety gate and causes `Stack#trigger_continuous_delivery` to ship a commit that was never actually validated, resulting in an unauthorized deploy. This matches the "Critical" category: a payload for one repository mutating another's stack/commit, causing an unauthorized deploy. The attack is repeatable against any stack/tenant hosted by the same Shipit instance, for any commit whose full metadata (tree, parents, author/committer identity/timestamps, message) the attacker can discover and replicate.

### Likelihood Explanation
Preconditions: victim `Stack#blocking_statuses` non-empty and the target commit currently pending/failing on that context (both are legitimate, common configurations per the README's `ci.blocking` feature). The attacker needs only an unprivileged GitHub account able to own/control a repository with webhooks reaching the shared Shipit host (any public repo with the Shipit GitHub App installed, or any repo configured to POST to the Shipit webhook endpoint), no Shipit session, API token, or app secrets. The nontrivial cost is reproducing an identical SHA-1 commit object in their own repo, which requires exact replication of publicly visible commit metadata (tree sha, parent sha, author/committer name/email/timestamps, message) — feasible since all of this data is public via the GitHub API/UI and git's commit hashing is deterministic over these fields. This is a moderate-effort but fully repeatable, script-automatable attack with no reliance on secrets.

### Recommendation
In `StatusHandler`, require the `repository` object in the params schema (as all other handlers already do), resolve `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, and scope the commit lookup to that repository's stacks: e.g. `Commit.where(sha: params.sha, stack_id: repository.stacks.select(:id))` (or join through `stack: :repository`) before calling `create_status_from_github!`. Reject/ignore statuses whose payload repository does not match the commit's own stack's repository.

### Proof of Concept
Minitest plan (extends the existing `test "#deployable? is false if a blocking status is failing on a previous undeployed commit"` pattern in `test/models/commits_test.rb`, but drives the write through `StatusHandler.call` instead of `commit.create_status_from_github!` directly):

```ruby
test "StatusHandler forges a status across repositories, unblocking a later commit" do
  blocking_commit = shipit_commits(:soc_second)
  blocking_commit.statuses.update_all(state: 'failure')
  assert_predicate blocking_commit, :failure?
  assert_predicate blocking_commit, :blocking?

  commit = shipit_commits(:soc_third)
  refute_predicate commit, :deployable? # binding holds before attack

  # attacker payload claims a foreign repository, but references the victim commit's sha
  foreign_payload = {
    'sha' => blocking_commit.sha,
    'state' => 'success',
    'context' => blocking_commit.statuses.last.context,
    'repository' => { 'full_name' => 'attacker/unrelated-repo' },
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(foreign_payload)

  blocking_commit.reload
  commit.reload

  # equality check: repository(status written) != repository(payload) -- should have been rejected but wasn't
  refute_equal blocking_commit.stack.repository.full_name, foreign_payload['repository']['full_name']
  assert_predicate blocking_commit, :success?   # forged status accepted
  refute_predicate blocking_commit, :blocking?  # gate silently defeated
  assert_predicate commit, :deployable?         # later commit now deployable — vulnerability confirmed
end
```

If the fix is applied (scoping commit lookup by payload repository), the same test should show `StatusHandler.call(foreign_payload)` creating no `Status` on `blocking_commit`, leaving `commit.deployable?` false.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-49)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L33-54)
```ruby
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end

          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-24)
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
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L231-237)
```ruby
    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/status.rb (L23-34)
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
    end
```

**File:** app/models/shipit/status/common.rb (L46-48)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end
```

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```
