### Title
Cross-repository Commit-status corruption via unscoped `Commit.where(sha:)` lookup - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits solely by `params.sha` and writes a status onto every matching `Commit` row, regardless of which repository the status webhook was actually sent for. Because `sha` is not scoped to the `repository` named in the same payload, an attacker who owns any repository can trigger a validly-signed webhook for their own repo and corrupt status data belonging to an unrelated stack/repository whose commit happens to share that SHA.

### Finding Description
The claimed binding is: `REPOSITORY SCOPE`: for every row written from a webhook payload, `Repository.from_github_repo_name(payload.dig('repository','full_name'))` must equal (or contain) the `stack.repository` of the `Commit` being mutated.

Code path:
- `WebhooksController#create` parses the JSON body and dispatches to handlers after `verify_signature`, which only validates that the signature matches the GitHub App keyed by `repository_owner = params.dig('repository','owner','login')` [1](#0-0) . This proves the payload came from *some* org's GitHub App installation, but says nothing about which `Commit` rows the handler may touch.
- `Handler#initialize` stores `payload` and parses `params`; `Handler#stacks`/`repository_name` exist and correctly scope by `payload.dig('repository','full_name')` [2](#0-1) , but `StatusHandler#process` never calls `stacks` or `Repository.from_github_repo_name`.
- `StatusHandler#process` is:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 
This queries `Commit` globally by `sha` with no `stack_id`/`repository` filter, and `Commit#create_status_from_github!` writes a `Status` row for every match [4](#0-3) .

Root cause: `sha` values are attacker-controlled content-addressed identifiers than can collide across unrelated repositories (e.g., shared upstream history between forks, cherry-picked/rebased commits with identical trees, or repositories seeded from the same template/commit). Nothing in `ExplicitParameters` schema, `verify_signature`, or `drop_unhandled_event` constrains which `Commit` rows a given payload may affect — those guards only assert "this payload was signed by *an* org's GitHub App," not "this payload's repository owns the commit being mutated."

Attacker flow:
1. Attacker creates/owns `attacker/repo`, installs the Shipit GitHub App on it (a routine, unprivileged GitHub action), obtaining a legitimately signed webhook channel for that repo/org.
2. Attacker identifies a `sha` that also exists as a `Commit` in a victim stack (e.g., forks the victim's public repo — the fork shares identical commit SHAs with the upstream for all un-rewritten history — or otherwise reproduces content that yields the same SHA1).
3. Attacker pushes/commits in `attacker/repo` at that SHA and causes (or directly POSTs) a `status` event naming `sha` and `repository.full_name = "attacker/repo"`.
4. `verify_signature` passes (signed for `attacker` org). `StatusHandler#process` runs `Commit.where(sha: sha)`, which returns the victim's `Commit` too (same `sha`, different `stack`/`repository`), and writes a forged `Status` (`state`, `description`, `target_url`, `context`) onto it via `add_status`, which also emits `Hook.emit(:commit_status/:deployable_status, ...)` and can trigger `stack.schedule_merges` / continuous delivery evaluation on the victim stack [5](#0-4) .

The forking scenario is the most concrete, low-cost route: any public repository on Shipit can be forked by an unprivileged attacker, and the fork will contain commits with SHAs identical to the upstream repo tracked by Shipit, satisfying the collision precondition without any cryptographic attack.

### Impact Explanation
A payload authenticated only for `attacker/repo` mutates `Status` rows (and downstream deployability/merge-scheduling behavior) belonging to a stack tied to a completely different, victim repository. This is a cross-repository/cross-tenant data-integrity violation: an attacker can flip a victim's commit status to `success`, unblocking that commit for deploy/merge (`Commit#deployable?`, `Commit#blocked?`) or to `failure`, blocking legitimate deploys — without ever authenticating against the victim's repository. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team," is repeatable against any repository whose commits share a SHA with attacker-controlled content (trivially achievable via forking public repos), and the blast radius spans every stack/repository hosted on the same Shipit instance.

### Likelihood Explanation
Preconditions: attacker must be able to install/operate a webhook-emitting GitHub repository they own (routine, unprivileged) and must know a `sha` also present as a `Commit` in the target stack — trivially satisfied by forking a public repository tracked by Shipit, since forks retain identical commit SHAs for shared history. No Shipit secrets, session, API token, or GitHub App private key are required; the attacker's own repo's legitimately signed webhook is sufficient because `verify_signature` only checks the signing org matches the payload's own `repository_owner`, not that the payload's commits belong to that org. This is repeatable at will against any stack sharing SHAs with attacker-accessible content.

### Recommendation
Scope the lookup in `StatusHandler#process` (and the analogous `check_run`/similar handlers if present) to commits belonging to the repository named in the payload, e.g. restrict to `stacks.flat_map(&:commits).where(sha: params.sha)` or join `Commit` through `Stack`/`Repository` using `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, mirroring the existing `Handler#stacks` helper, before calling `create_status_from_github!`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossRepoTest < ActiveSupport::TestCase
        test 'a status payload for repo A must not mutate commits belonging to repo B' do
          shared_sha = 'a' * 40

          victim_stack = shipit_stacks(:shipit)
          victim_commit = victim_stack.commits.create!(sha: shared_sha, message: 'victim commit')

          attacker_repo = Repository.create!(owner: 'attacker', name: 'repo')
          attacker_stack = Stack.create!(repository: attacker_repo, environment: 'production', branch: 'master')
          # Note: attacker does NOT need a Commit row of their own; they only need
          # a webhook payload claiming repository=attacker/repo and this sha.

          payload = {
            'sha' => shared_sha,
            'state' => 'success',
            'context' => 'ci/attacker',
            'repository' => { 'full_name' => 'attacker/repo', 'owner' => { 'login' => 'attacker' } }
          }

          # BINDING UNDER TEST (before):
          # Repository.from_github_repo_name(payload['repository']['full_name']) == 'attacker/repo'
          # Commit.where(sha: shared_sha).map(&:stack).map(&:repository).uniq == [victim_stack.repository]
          repos_before = Commit.where(sha: shared_sha).map { |c| c.stack.repository }.uniq
          assert_equal [victim_stack.repository], repos_before

          StatusHandler.call(payload)

          # BINDING (after): the set of repositories whose commits were mutated
          # must still equal only the repository named in the payload ('attacker/repo').
          # It does not: victim_commit received a status despite belonging to a
          # different, unrelated repository.
          victim_commit.reload
          assert_equal 'success', victim_commit.status.state,
            'victim commit in a different repository was mutated by a payload for attacker/repo'

          repos_touched = Commit.where(sha: shared_sha).map { |c| c.stack.repository }.uniq
          refute_equal [attacker_repo], repos_touched
          assert_includes repos_touched, victim_stack.repository
        end
      end
    end
  end
end
```
This demonstrates that after calling `StatusHandler.call(payload)` with a payload whose `repository.full_name` is `attacker/repo`, the victim repository's `Commit` (a different repository entirely) is mutated, falsifying the `REPOSITORY SCOPE` binding.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L19-38)
```ruby
        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end

        def process
          raise NotImplementedError
        end

        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
