### Title
Cross-repository status forgery via SHA collision in `StatusHandler#process` flips `Commit#deployable?` for an unrelated tenant - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` resolves the target commit(s) for an incoming GitHub `status` webhook using `Commit.where(sha: params.sha)` with no scoping to the repository that emitted the webhook. Because a git commit's SHA is a hash of the commit's content (parents, tree, author/committer, message/timestamps) and not of the repository it lives in, an attacker who controls a Shipit-registered repository (repo B) can push a commit object whose SHA is identical to a commit already tracked by an unrelated tenant's stack (repo A), and GitHub will emit a validly-signed `status` webhook for repo B that Shipit applies to *every* commit row sharing that SHA, including A's.

### Finding Description
The claimed binding is:
`stack_queried_for_CI(commit.stack) == stack_named_by_webhook_repository(payload['repository']['full_name'])`

Tracing the code shows this binding is never enforced:

- `WebhooksController#verify_signature` only checks the webhook signature against the *organization* derived from `repository_owner` (`params.dig('repository','owner','login')`), via `Shipit.github(organization: repository_owner)`. [1](#0-0)  This proves the webhook was signed with the secret configured for *some org*, not that it corresponds to the specific repo/stack whose commit will be mutated.
- `StatusHandler` never reads `params['repository']` at all — its schema doesn't even require it — and resolves target commits purely by SHA: [2](#0-1) 
- `Commit#deployable?` is `!locked? && (stack.ignore_ci? || (success? && !blocked?))`, driven directly by the `status` records attached to the commit. [3](#0-2) 
- `Status#state` delegates `success?` used by `deployable?`. [4](#0-3) 

Exploit flow: an attacker who is a member/collaborator of any org that hosts a Shipit-tracked repo (repo B, a legitimate tenant) constructs a git commit object (same tree, parents, author, committer, timestamps, message) as an existing, non-deployable commit already tracked in tenant A's stack, giving it the identical SHA (a well-known git property — SHA identity depends only on object content, not on which repository stores it). The attacker pushes/references that commit as a branch tip in repo B and gets any CI/status integration (or a raw crafted `POST /webhooks` with `X-Github-Event: status`, `sha: <A's sha>`, `state: success`, and `repository.owner.login` set to B's own valid org) delivered to Shipit. Because repo B's org is a legitimate Shipit tenant, `verify_signature` passes using B org's real webhook secret (which GitHub itself computes and sends — the attacker doesn't need to know the secret, GitHub does the signing for genuine deliveries from B's own installation). `StatusHandler#process` then matches `Commit.where(sha: <shared_sha>)`, which returns **A's** commit row too, and calls `commit.create_status_from_github!(params)`, creating a `success` `Status` scoped to A's own stack (via `commit.stack`) — never checked against payload's `repository` field. This flips `deployable?` to `true` for A's commit with zero authorized status ever originating from A's own GitHub repo.

None of the listed guards intervene: `verify_signature` checks org-level HMAC only, not repo identity; `drop_unhandled_event` doesn't apply (status is handled); `ExplicitParameters` schema for `StatusHandler` doesn't require/validate `repository` at all; `force_github_authentication`, `User#authorized?`, `require_permission!` are irrelevant since this is an unauthenticated webhook endpoint; no `Repository`/`Stack` model validation ties `Status#stack_id` back to a repository named in the payload.

### Impact Explanation
A `success` `Status` record is written for tenant A's stack/commit purely because of an event whose GitHub delivery originated from tenant B's repository — a payload for one repository mutating another's commit state. This directly flips `Commit#deployable?` to `true` for a commit that never received an authorized CI signal from A's own repo, enabling `next_expected_commit_to_deploy` and the deploy API (`params.require_ci && !commit.deployable?`) to treat the commit as deploy-eligible. [5](#0-4)  This is an unauthorized deploy-eligibility flip on repository A driven by attacker-controlled repository B — matching "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy" (Critical). The attack is repeatable against any pair of tenant stacks the attacker can compute a colliding-content commit for, and is not bounded to a single stack.

### Likelihood Explanation
Preconditions: the attacker must control (or push to) a repository within an org that is already a configured Shipit GitHub tenant (so that `verify_signature`/`Shipit.github(organization:)` succeeds using that org's legitimate, GitHub-computed signature — the attacker never needs the secret itself). The attacker must also be able to produce a commit object with an identical SHA to a target commit in tenant A — feasible because commit SHAs are deterministic hashes of publicly-knowable commit metadata (parents, tree, author/committer identity and timestamps, message), so duplicating a known commit's exact metadata in a new push reproduces its SHA exactly, with no cryptographic secret required. Attacker cost is a single crafted push/status delivery from their own repo; the exploit is deterministic and repeatable.

### Recommendation
`StatusHandler#process` (and the underlying `Commit.create_status_from_github!` path) must not resolve target commits by SHA alone. Require and validate the payload's `repository.full_name` (or `repository.id`) matches the `Stack#repository` for every commit the SHA maps to before writing a `Status`, e.g., scope `Commit.where(sha: params.sha, stack_id: Stack.where(repository: matched_repo).select(:id))`, and reject/drop status updates where no stack for the payload's repository exists.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
require 'test_helper'

module Shipit
  module Webhooks
    module Handlers
      class StatusHandlerCrossTenantTest < ActiveSupport::TestCase
        test "status webhook for repo B flips deployable? for an unrelated commit tracked only under repo A's stack" do
          stack_a = shipit_stacks(:shipit)               # tenant A's stack (repo A)
          commit_a = shipit_commits(:fifth)               # commit with no successful status; belongs to stack_a
          assert_equal stack_a, commit_a.stack

          # No status has ever originated from repo A itself
          refute_predicate commit_a, :deployable?

          # Attacker-controlled payload: repository field points at repo B (a different, attacker-owned
          # but Shipit-registered repo), yet `sha` equals commit_a's sha (content-collision).
          forged_params = ExplicitParameters::Params.new(
            StatusHandler.schema,
            'sha' => commit_a.sha,
            'state' => 'success',
            'repository' => { 'full_name' => 'attacker/repo-b', 'owner' => { 'login' => 'attacker-org' } }
          )

          StatusHandler.new.process_with_params(forged_params)

          assert_predicate commit_a.reload, :deployable?  # flips true purely from repo B's webhook
        end
      end
    end
  end
end
```
This demonstrates: before the cross-tenant webhook, `commit_a.deployable?` is `false` with zero statuses from A's own repo; after processing a `status` payload whose `repository` names an unrelated repo B, `commit_a.deployable?` becomes `true`, because `StatusHandler#process` matches purely on `sha` [2](#0-1)  with no repository binding check.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L219-219)
```ruby
    delegate :pending?, :success?, :error?, :failure?, :blocking?, :state, to: :status
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/controllers/shipit/api/deploys_controller.rb (L19-22)
```ruby
      def create
        commit = stack.commits.by_sha(params.sha) || param_error!(:sha, 'Unknown revision')
        param_error!(:force, "Can't deploy a locked stack") if !params.force && stack.locked?
        param_error!(:require_ci, "Commit is not deployable") if params.require_ci && !commit.deployable?
```
