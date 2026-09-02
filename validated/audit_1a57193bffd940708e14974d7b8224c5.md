## Broken Binding

The code implicitly assumes:

`repository verified by webhook_secret for this request` (i.e. the GitHub organization that signed the request, from `payload.dig('repository','owner','login')`) `== commit.stack.repository.full_name` for every `Commit` row that gets mutated by that request.

Tracing the code shows this equality is **never checked** at the point where the write happens.

## Code path

`WebhooksController#verify_signature` only proves that the request was signed with the webhook secret associated with the *organization* named in the (attacker-supplied, unauthenticated) payload — it does not bind the signature to any specific repository or to the specific commit that will be mutated: [1](#0-0) [2](#0-1) 

`StatusHandler#process` then does **not** consult `payload['repository']` at all when deciding which `Commit` rows to update. It looks up commits purely by `sha`, globally, across every stack/repository/organization in the installation, and writes a `Status` onto every match: [3](#0-2) 

Compare with the base `Handler` class, which *does* expose a `repository_name`/`stacks` helper scoped to `payload.dig('repository','full_name')` — used by every other handler (`CheckSuiteHandler`, `PullRequest::*Handler`) — but `StatusHandler` deliberately bypasses it and queries `Commit` directly: [4](#0-3) [5](#0-4) 

Once the `Status` row is created for stack B's commit, `deployable?` reevaluates purely from state, independent of which org/repo produced it: [6](#0-5) 
and `Status` autonomously fires continuous delivery on create: [7](#0-6) 

I was not able to view `Commit#schedule_continuous_delivery` / `Stack#trigger_continuous_delivery` bodies directly in this session (ran out of tool calls) to confirm the exact `Deploy`/`ContinuousDeliveryJob` creation logic, so that final leg of the chain from `Status#schedule_continuous_delivery` to an actual `Deploy` record is asserted by naming/structure and by existing tests (`test/models/commits_test.rb` shows `create_status_from_github!` driving `deployable_status` hooks and `ProcessMergeRequestsJob`), not directly confirmed by reading `Stack#trigger_continuous_delivery`. This should be verified with a live minitest run before treating impact as fully proven end-to-end.

## Exploit flow

1. Attacker owns/controls repository A, connected to a GitHub App installation on some organization O (any organization onboarded to this Shipit instance — does not need to be the same org as victim stack B).
2. Attacker reproduces the exact commit content (tree, parents, author/committer, message, timestamps) of victim stack B's pending HEAD commit and pushes it into repo A, giving it an identical `sha` (content-addressed, no access to B needed, as the prompt states).
3. Attacker (or GitHub, on a genuine CI run against A) emits a `status` webhook for repository A, `sha` = B's HEAD sha, `context` matching one of B's `stack.required_statuses`, `state: 'success'`. This request is signed with O's real `webhook_secret` for repository A — a completely legitimate signature for A.
4. `WebhooksController#verify_signature` passes, because it only checks that the signature matches org O's secret; it never checks that `sha`/commit actually belongs to a stack backed by a repository in O.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, which matches B's row (a different stack, potentially a different repository, potentially a different organization entirely) purely because the SHA collides.
6. `commit.create_status_from_github!(params)` writes a `success` `Status` onto B's commit, flips `deployable?`, and `Status`'s `after_commit :schedule_continuous_delivery` fires B's continuous delivery using B's own token/deploy environment — without the attacker ever authenticating to, or having any relationship with, repository/stack B.

## Why existing guards fail

- `verify_signature` binds the signature to an **organization**, not to the specific repository/commit being mutated — and the org name used for that lookup is read straight from the unverified JSON body before any check has occurred.
- `StatusHandler` is the one handler in the codebase that skips the `Handler#stacks`/`repository_name` scoping helper used everywhere else, relying solely on `sha` uniqueness — which is explicitly *not* unique across tenants by design (content-addressing).
- No model validation, `ExplicitParameters` schema, or `Commit`/`Stack` code cross-checks `payload['repository']['full_name']` against `commit.stack.repository.full_name` before writing the `Status`.

## Impact

Critical — a payload legitimately authenticated for repository A can mutate/deploy a completely unrelated stack B's commit and trigger `Status`-driven continuous delivery, causing an unauthorized deploy using B's own `GITHUB_TOKEN`/deploy environment. This is cross-tenant blast radius: any two stacks in the same Shipit installation are exposed to each other regardless of GitHub org boundaries, limited only by the attacker's ability to reproduce an identical commit SHA for the target's pending head (a real but non-trivial precondition, feasible when e.g. the victim's PR/commit content is publicly known via GitHub itself).

## Recommendation

In `app/models/shipit/webhooks/handlers/status_handler.rb`, scope the commit lookup by the repository named in the payload (mirroring the base `Handler#stacks` helper), e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or explicitly filter `Commit.where(sha: params.sha).select { |c| c.stack.repository.full_name.casecmp?(repository_name) }`, so a status can only ever be applied to commits belonging to the repository that authenticated the webhook.

## Proof of Concept plan (minitest, ActionDispatch, no live GitHub)

- Set up stack B with a pending commit whose `sha` is fixed/known, `required_statuses` including some context `ci/example`.
- Set up repository A (different owner/org) with its own `webhook_secret`/`GitHubApp` config, distinct from B's.
- Compute a valid `X-Hub-Signature` for a `status` payload where `repository.full_name == "attacker/A"` but `sha == B's pending commit sha`, `state: "success"`, `context: "ci/example"`, using A's real webhook_secret.
- `POST /webhooks` with that body/signature and `X-Github-Event: status`.
- Assert: `commit.statuses.create!` fired for B's commit (`assert_difference 'commit.statuses.count'`), and separately assert that no `Status`/write occurred for any commit actually owned by repository A (proving the binding `repository (A) == commit.stack.repository.full_name (B)` was violated), then assert a `Deploy`/`ContinuousDeliveryJob` was enqueued scoped to stack B.

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status.rb (L18-24)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

    class << self
      def replicate_from_github!(stack_id, github_status)
```
