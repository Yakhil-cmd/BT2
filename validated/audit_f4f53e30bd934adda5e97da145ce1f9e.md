## Title
Unscoped `status` webhook lets one repository's payload write CI status onto commits in every other repository/stack sharing the same SHA - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

## Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` and calls `create_status_from_github!` on every match, with no filter on the repository/stack that the webhook actually originated from. The base `Handler` class provides a `stacks`/`repository_name` helper scoped to `payload.dig('repository', 'full_name')`, but `StatusHandler` never uses it, so a correctly-signed `status` event from repository A can alter CI/status state of commits belonging to a completely unrelated repository B, as long as both share a commit SHA.

## Finding Description
The broken binding is: `commit.stack.github_repo_name == payload.dig('repository', 'full_name')` — this must hold for a status update to be legitimate, but `StatusHandler` never checks it.

Code path: `Shipit::WebhooksController#create` parses the raw JSON body and dispatches to `Shipit::Webhooks.for_event(event)` handlers [1](#0-0) . Before dispatch, `verify_signature` validates the HMAC signature using `Shipit.github(organization: repository_owner)`, i.e. it authenticates that the payload came from GitHub for the claimed *organization/owner*, not that it came from the specific repository referenced in `params.sha` [2](#0-1) . This means any repository under an org (or any personal repo, if the app is installed at user level) that an attacker owns can produce a genuinely-signed webhook.

`StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [3](#0-2) 

This is a bare `sha` lookup across the entire `commits` table, spanning all stacks/repositories, unlike the base `Handler#stacks` helper which scopes lookups via `Repository.from_github_repo_name(repository_name)` [4](#0-3) . `create_status_from_github!` writes a `Status` row tied to `stack_id` and recomputes `deployable?`/CI state via `add_status`, which emits `commit_status`/`deployable_status` hooks and can schedule merges/continuous delivery for that commit's actual stack [5](#0-4) [6](#0-5) .

Exploit flow: attacker owns/controls a repository (or fork) whose GitHub App/webhook secret they can legitimately trigger (their own repo, org membership not required beyond owning a repo the app is installed on). They push a commit whose SHA collides with a SHA already present in a victim stack's `commits` table (trivially achievable for shared ancestor commits, cherry-picks, common initial commits, or monorepo/fork scenarios), then trigger (or fabricate via their own repo's real GitHub event) a `status` webhook with `context` matching the exact string the victim stack lists in `ci.require`, and `state: success`. Because `StatusHandler` never checks which repository issued the event against which stack owns the commit, the victim's commit for that SHA receives the attacker-controlled status and can flip `deployable?` to true, unblocking deploys, or conversely poison it to failing.

Existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema) only validate signature validity and payload shape — none of them tie the SHA to the originating repository, and the `stacks`/`repository_name` helper in `Handler` that would perform this scoping is unused by `StatusHandler`.

## Impact Explanation
A payload legitimately signed for one repository writes CI status records against commits belonging to a different repository's stack — this is a payload-for-one-repository mutating another's commit/CI state, matching the "Critical" category (cross-tenant record mutation not authenticated by the originating repository). The blast radius is every stack/repository whose `commits` table happens to contain a matching SHA, and it directly affects `deployable?`, which gates deploys/merges.

## Likelihood Explanation
Preconditions: attacker needs (1) a repository where they can trigger a genuinely GitHub-signed `status` event (their own repo/fork with the Shipit GitHub App installed), and (2) SHA overlap between their repo's commit and a commit already ingested into a victim stack's `commits` table. SHA collision across repos happens naturally for shared history (forks, cherry-picks, shared root commits, vendored/mirrored repos) and does not require brute force since SHA-1 collision isn't needed — only that the same real commit object exists in both. This makes the attack cheap and repeatable per matching SHA, though it is contingent on such a SHA existing in the target stack's history, which is not fully in the attacker's control in the general case (uncertain how often naturally-occurring collisions are practically obtainable against an arbitrary victim stack chosen by the attacker, versus victim stacks that share history/forks with attacker-controlled repos).

## Recommendation
Scope `StatusHandler#process` to only update commits belonging to the repository the webhook actually reports, mirroring the base `Handler#stacks` helper, e.g. restrict the `Commit.where(sha: params.sha)` query to `stacks.flat_map(&:commits)` (or join through `Stack`/`Repository` via `repository_name`) so a status can only be applied to commits in stacks of the repository identified by `payload.dig('repository', 'full_name')`.

## Proof of Concept
minitest plan (no live GitHub required):
1. Create two `Repository` records for different `full_name`s (e.g. `org/repo-a`, `org/repo-b`), each with a `Stack`.
2. Create a `Commit` with the same `sha` (e.g. `"deadbeef" * 5`) under stack A and another `Commit` with the identical `sha` under stack B.
3. Record baseline: `commit_b.deployable?` before (e.g. false, pending CI) and `commit_b.status.state`.
4. Build a `status` webhook payload referencing repo A (`repository.full_name = "org/repo-a"`), with `sha` = the shared SHA, `state: "success"`, `context` equal to stack B's required context from `ci.require`.
5. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (bypassing controller-level signature checks, per the invariant being tested at the handler level).
6. Assert: `commit_b.reload.status.state == "success"` and `commit_b.deployable? == true`, even though the payload's `repository.full_name` was `org/repo-a`, proving repo A's payload mutated repo B's commit CI state — i.e., assert `commit_a.stack.github_repo_name != commit_b.stack.github_repo_name` while both received the status change from a single payload.

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
