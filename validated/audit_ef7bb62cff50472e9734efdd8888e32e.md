Based on the code traced, the vulnerability is confirmed.

`app/models/shipit/webhooks/handlers/status_handler.rb#process` performs a global lookup `Commit.where(sha: params.sha)` with no scoping by repository or stack, unlike its sibling `PushHandler#process` which properly scopes via `stacks.not_archived.where(branch:)` [1](#0-0) . `WebhooksController#verify_signature` only proves that the payload's signature matches the `webhook_secret` of the org derived from `params.dig('repository','owner','login')` [2](#0-1)  — it never constrains which `Commit`/`Stack` rows the handler is allowed to touch. `StatusHandler#process` then iterates every `Commit` row across the entire database matching `params.sha`, calling `commit.create_status_from_github!(params)` on each, which writes a `Status` scoped to that commit's own `stack_id` [3](#0-2) [4](#0-3) .

### Title
Cross-tenant `Status` write via unscoped `Commit.where(sha:)` lookup in `status` webhook handler - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` matches commits purely by SHA across the entire `commits` table, with no constraint tying the match to the repository/org whose `webhook_secret` authenticated the request. Any attacker who can trigger a `status` event on a repo they own (or fork) can write a `Status` record onto an unrelated victim stack's `Commit`, provided a `Commit` row with the same SHA exists there — which is a realistic scenario for forks or vendored histories that share commit SHAs (git SHAs are content-addressed).

### Finding Description
The broken binding: the org that authenticated the payload (`repository_owner` used in `Shipit.github(organization: repository_owner)` in `verify_signature`) must equal the org owning every `Commit` row mutated in `process`, but no such constraint exists. `WebhooksController#verify_signature` only validates that the raw payload was signed with the `webhook_secret` of `params.dig('repository','owner','login')` [2](#0-1) . It then dispatches to `StatusHandler.call(params)`, whose `process` runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` [3](#0-2)  with no join to `stacks`, `repository_name`, or any org/repo filter — in contrast to `PushHandler#process`, which scopes matches through `stacks.not_archived.where(branch:)` [1](#0-0) . `Commit#create_status_from_github!` then creates a `Status` using the matched commit's own `stack_id` [4](#0-3) , meaning the write always targets the victim stack that actually owns the matching `Commit` row, regardless of which org's webhook_secret verified the request.

### Impact Explanation
An attacker who owns `attacker/repo` can cause `Status` rows (`state`, `description`, `target_url`, `context`) to be written onto any other tenant's `Commit`, as long as that commit's SHA also exists in the attacker's own repo — a realistic condition for forked/shared history since git SHAs are content-addressed. This is a cross-repository write to another tenant's `Status`/`Commit` state, which can flip `deployable?`/CI-gating decisions on the victim stack and is repeatable against any SHA the attacker can discover (e.g., by observing the victim's public commit history) and matches the "payload for one repository mutating another's stack/commit" Critical category.

### Likelihood Explanation
Preconditions: the attacker needs no Shipit credentials, only ownership of a GitHub repo (or fork) whose commit history overlaps SHA-wise with a tracked victim stack, and the ability to fire a `status` webhook event (trivial via any CI integration on their own repo). No Shipit-side secret is required since `verify_signature` only checks the attacker's own `webhook_secret`. This is low-cost and repeatable for every shared SHA.

### Recommendation
Scope `StatusHandler#process` to only touch commits belonging to stacks whose repository matches the verified `repository_owner`/`repository_name` from the payload, e.g. `stacks.joins(:commits).merge(Commit.where(sha: params.sha))`, mirroring the scoping pattern used in `PushHandler`.

### Proof of Concept
Minitest integration test in `test/controllers/webhooks_controller_test.rb`:
1. Create `victim_stack` under org `victim`, with `Commit` `victim_commit` having `sha: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"`.
2. Create `attacker_stack`/org `attacker` (or just an `attacker` org with a registered `webhook_secret`), with no `Commit` for that sha needed by Shipit — only the payload needs `repository.owner.login == "attacker"`.
3. POST `/webhooks` with `X-Github-Event: status`, a JSON body `{ sha: "4b825...", state: "success", repository: { owner: { login: "attacker" } } }`, signed with `attacker`'s `webhook_secret`.
4. Assert `Shipit::Commit.find(victim_commit.id).statuses.count` increased and its latest `Status#state == "success"`, proving the attacker-signed payload mutated the victim's commit state.

### Citations

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
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
