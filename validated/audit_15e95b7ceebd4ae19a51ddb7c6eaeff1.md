### Title
Cross-tenant Commit/Status mutation via unscoped SHA lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits solely by `sha`, with no scoping to the repository/stack that the webhook payload claims to originate from. Because the `commits` table only enforces sha uniqueness per stack, an attacker with a real, validly-signed webhook for a commit status on *their own* repository can cause every `Commit` row sharing that sha in *any* stack (including stacks belonging to repositories they do not control) to receive a new `Status` row and status-change side effects.

### Finding Description
The claimed binding is: for every `commit` mutated by `StatusHandler#process`, `commit.stack.repository.full_name` must equal `payload.dig('repository', 'full_name')`.

Tracing the code:
- `StatusHandler#process` does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [1](#0-0) 

This is the only query in the handler — it filters exclusively by `sha`, never by `stack_id` or the repository derived from the webhook payload.

- The base `Handler` class already exposes the mechanism needed to scope by repository: `repository_name` reads `payload.dig('repository', 'full_name')` and `stacks` resolves `Repository.from_github_repo_name(repository_name)&.stacks`. [2](#0-1) 
`StatusHandler` never calls `stacks` or filters `Commit` by `stack_id: stacks.ids` (or similar), so the repository-binding tool exists in the framework but is unused here.

- `WebhooksController#verify_signature` only verifies that the payload was signed by the GitHub App/organization matching `repository_owner` (`params.dig('repository','owner','login')`); it does not verify that the `sha` in the payload actually belongs to that repository's stack. [3](#0-2) 

So the equality `commit.stack.repository.full_name == payload.dig('repository','full_name')` is **not enforced anywhere** in the reachable path from `WebhooksController#create` → `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` → `StatusHandler.call` → `StatusHandler#process`.

Root cause: the `commits` table's sha uniqueness constraint is scoped per-stack, not globally, so the same sha (e.g. the well-known git empty-tree hash `4b825dc642cb6eb9a060e54bf8d69288fbee4904`, or any coincidentally shared commit sha such as an empty merge commit) can legitimately exist as separate `Commit` rows in multiple, unrelated stacks. `StatusHandler#process` treats sha as if it were a globally unique key and mutates every matching row regardless of which repository actually emitted the webhook.

Exploit flow: attacker owns/controls a repository (stack A) that is a genuine target of Shipit (so their real GitHub-signed status webhooks for stack A are accepted by `verify_signature`). They push/produce a commit with a sha that also exists in some other stack B (victim, e.g. from a shared well-known sha or by crafting a commit that hashes identically at the tree/commit level to a commit already ingested for stack B — trivially guaranteed for the well-known empty-tree/empty-commit shas that many repositories contain). They then have their own repository emit (or fabricate via their own CI/GitHub Action they control) a `status` event referencing that sha. GitHub signs and delivers this webhook normally — no forged signature is needed since it is a legitimate webhook from a repository the attacker legitimately controls. `StatusHandler#process` then updates the `Status` row (and triggers `Hook.emit(:commit_status, ...)`, `Hook.emit(:deployable_status, ...)`, and `stack.schedule_merges`) for the victim's commit in stack B as well as the attacker's own commit in stack A.

### Impact Explanation
A single attacker-controlled, legitimately-signed webhook write-mutates `Status`/`Commit`-state and triggers stack side effects (`Hook.emit(:commit_status, ...)`, `Hook.emit(:deployable_status, ...)`, `stack.schedule_merges`) for one or more victim stacks that the attacker does not own, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." This is repeatable: any sha collision (deliberately arranged by the attacker, or naturally occurring for well-known git shas) between attacker-owned and victim stacks yields cross-tenant writes on every subsequent status webhook the attacker sends. The blast radius scales with the number of stacks sharing the colliding sha, not with the number of repositories the attacker actually controls — it can affect status/deployability state and downstream automatic merge/deploy scheduling (`stack.schedule_merges`) for victim stacks, an unauthorized state change with deploy-relevant consequences.

### Likelihood Explanation
Preconditions are modest: the attacker needs (a) a stack they legitimately control (already required to receive genuinely-signed webhooks), and (b) a sha collision with a victim's stack. Colliding shas are easy to obtain deliberately (attacker crafts a commit/tree in their own repo matching a well-known sha such as the empty tree, or an empty no-op merge commit, both of which are common in real repositories) and require no cryptographic collision — only matching a commit that already, coincidentally, exists in a target stack. No Shipit session, API token, or GitHub secret is required beyond the attacker's own repository access, which they already legitimately have. This is highly feasible and repeatable per the threat model's unprivileged-attacker assumptions.

### Recommendation
Scope the commit lookup in `StatusHandler#process` to the stacks belonging to the webhook's repository, using the same `stacks`/`repository_name` helper already available in the base `Handler` class, e.g. `Commit.where(sha: params.sha, stack_id: stacks.ids)`, so that only commits belonging to stacks whose repository matches `payload.dig('repository', 'full_name')` are mutated.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, out-of-scope path noted only for illustration of the intended assertion, actual test would need to live under `test/`):
1. Create three fixture stacks A, B, C backed by three distinct `Repository` rows with different `full_name`s.
2. Create one `Commit` row in each stack sharing the identical `sha` (e.g. `4b825dc642cb6eb9a060e54bf8d69288fbee4904`).
3. POST a `status` webhook to `/webhooks` with a valid signature for stack A's repository/org, payload `repository.full_name` = stack A's repo, and `sha` = the shared sha.
4. Assert:
   - `stack_a.commits.first.statuses.count` increased by 1 (expected/legitimate write).
   - `stack_b.commits.first.statuses.count` and `stack_c.commits.first.statuses.count` are unchanged (**this assertion currently fails** — both increase by 1 because `commit.stack.repository.full_name` (`stack B`/`stack C`'s repo) does not equal `payload.dig('repository','full_name')` (stack A's repo), yet the row is still mutated), proving the binding is broken.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-39)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
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
