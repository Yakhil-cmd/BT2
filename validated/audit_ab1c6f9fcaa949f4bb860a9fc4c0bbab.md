## Title
`StatusHandler#process` writes a GitHub status to any commit row matching a bare SHA, with no repository/stack scoping - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)` and never checks the `repository` field of the incoming webhook against the commit's stack/repository, unlike every other handler in the same module. Any GitHub `status` event whose HMAC signature verifies for *some* organization known to Shipit can therefore write a `Status` row onto a `Commit` belonging to a completely different repository/stack, as long as the two repositories happen to share a commit SHA (trivial for forks of the same public history).

### Finding Description
The claimed binding is: `stack_id_of_status_target(victim S1) == stack_id_verified_by_webhook_secret(status payload)`. Tracing the code shows this equality is never enforced.

- `WebhooksController#verify_signature` only proves the request is a genuinely-signed GitHub webhook for *some* organization/repo the app knows about, derived from `repository_owner` in the payload — it says nothing about which `Commit`/`Stack` the event is allowed to mutate: [1](#0-0) .
- `Webhooks::Handlers::Handler` provides a `stacks` helper that scopes lookups to `Repository.from_github_repo_name(repository_name)`, and every other handler (`PullRequest::OpenedHandler`, `ClosedHandler`, `LabeledHandler`, etc.) uses exactly that pattern to resolve `repository` before acting: [2](#0-1) [3](#0-2) .
- `StatusHandler`, however, does not `require`/use a `repository` field at all in its params schema, and its `process` method matches purely by `sha` across the entire `commits` table, with no stack/repository filter: [4](#0-3) .
- `Commit` rows `belongs_to :stack`; two different stacks (e.g., a victim's protected repo and an attacker's own repo/fork sharing git history) each have their own `Commit` row for the same SHA. `Commit#blocked?` is scoped to `stack.commits...` but that stack is whichever stack the SHA-matched row belongs to — including the victim's: [5](#0-4) . `Status#blocking?` is derived purely from `state != 'success'` and `commit.blocking_statuses.include?(context)`: [6](#0-5) .

Exploit flow: the attacker only needs write/webhook capability on *any* repository whose organization is already onboarded to the same Shipit instance (or their own fork, if forks can independently register a webhook against the Shipit host using their own org's app installation). They copy/cherry-pick a commit object identical (parents, tree, author/committer, timestamps, message) to one already tracked in the victim's stack — a common, low-cost occurrence for forks of open-source projects sharing history — then post a GitHub commit `status` via the GitHub API for that SHA in their own repo. GitHub delivers a signed `status` webhook to Shipit; `verify_signature` succeeds because it only checks the org-level secret, not which commit/stack is targeted. `StatusHandler#process` then finds and mutates the victim's `Commit` row purely by SHA match, flipping `blocking?`/`blocked?` for the victim's stack.

Existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) do not close this gap because none of them compare the webhook's originating repository to the repository/stack of the commit being mutated — that check simply does not exist in `StatusHandler`.

### Impact Explanation
A write is performed on a `Commit`/`Status` belonging to a repository that did not authenticate the write (the payload's `repository` is never checked). This directly satisfies the Critical category "a payload for one repository mutating another's stack, commit, task, or team": the attacker can set a blocking commit status on the victim's stack, causing `Commit#blocked?` to return `true` and gating/blocking the victim's deploy pipeline (`deployable?` becomes `false`), or conversely mark the victim's commit `success` to unblock a deploy prematurely. The attack is repeatable against any stack whose Commit table contains a SHA the attacker can also produce/control on their side, and the blast radius spans all stacks sharing a Shipit instance and GitHub organization/app configuration.

### Likelihood Explanation
Preconditions: (1) the attacker needs webhook delivery capability with a signature that verifies for `repository_owner` as resolved by `Shipit.github(organization:)` — realistic if the attacker controls any repository within an org already onboarded to Shipit, or their own fork if Shipit's GitHub App/org config permits it; (2) a shared commit SHA between the attacker's repo and the victim's stack, which is inherent and easy to arrange for forked/mirrored repositories (same tree/parent/author/committer/message/timestamp reproduces the identical SHA). No Shipit session, API token, or maintainer role is required. Cost to the attacker is a single `POST /repos/{owner}/{repo}/statuses/{sha}` GitHub API call plus one webhook delivery — low and fully repeatable.

### Recommendation
Scope `StatusHandler#process` by repository/stack the same way other handlers do: require and validate `repository.full_name` in the params schema, resolve `Repository.from_github_repo_name(params.repository.full_name)`, and restrict the `Commit` lookup to `repository.stacks.commits.where(sha: params.sha)` (or equivalently filter `Commit.where(sha: params.sha, stack_id: repository.stacks.select(:id))`) before calling `create_status_from_github!`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
```ruby
test "status webhook does not update commits belonging to a different repository's stack" do
  victim_stack  = shipit_stacks(:shipit)                 # repo: "shopify/shipit-engine"
  attacker_repo_full_name = "attacker/unrelated-fork"     # different repository, same SHA history

  shared_sha = victim_stack.commits.last.sha
  victim_commit = victim_stack.commits.find_by(sha: shared_sha)
  refute_predicate victim_commit, :blocking?

  payload = {
    "sha" => shared_sha,
    "state" => "failure",
    "context" => victim_stack.blocking_statuses.first || "ci/blocking",
    "repository" => { "full_name" => attacker_repo_full_name } # attacker-owned repo
  }

  Shipit::Webhooks::Handlers::StatusHandler.new(payload).process

  victim_commit.reload
  assert_predicate victim_commit, :blocking?,
    "attacker-originated status mutated a commit belonging to a repository/stack it did not authenticate"
end
```
Binding assertions: before the call, `stack_id_of_status_target(victim_commit.stack_id)` should require equality with the stack owned by `attacker_repo_full_name`; after the call, the test shows the write succeeds even though `attacker_repo_full_name != victim_stack.repository.full_name`, proving the equality is not enforced.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
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

**File:** app/models/shipit/commit.rb (L231-237)
```ruby
    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/status/common.rb (L46-48)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end
```
