### Title
`Shipit::Webhooks::Handlers::StatusHandler#process` resolves commits by `sha` alone, letting one repository's status webhook reject a merge request in a different tracked repository - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up target commits with `Commit.where(sha: params.sha)` with no constraint tying the lookup to the repository that authenticated the webhook. Because `Commit#sha` is only unique per `stack_id` (git commit hashes are content-addressed and identical across forks/mirrors of the same commit), a validly-signed webhook for repository A can create a `Status` on a `Commit` row that belongs to stack/repository B, flipping `any_status_checks_failed?` for an unrelated `MergeRequest` and driving `reject_unless_mergeable!` to `reject!('ci_failing')`.

### Finding Description
The binding that should hold is: `status.commit.stack.repository == webhook.payload.repository` (the status attached must belong to the same repository that GitHub authenticated the webhook for). The actual code never enforces this: [1](#0-0) 

`Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` is a global query across every `Commit` row in the database, regardless of which `stack`/repository owns it. `create_status_from_github!` then unconditionally records the reported state: [2](#0-1) 

`verify_signature` in `WebhooksController` only proves the payload was genuinely signed by GitHub for the organization named in the payload's own `repository.owner.login` field; it says nothing about which `Commit` rows the payload is allowed to touch: [3](#0-2) 

Exploit flow: if a victim's PR head commit is also present (same sha, e.g. via a fork) as a `Commit` row belonging to a second stack that is tracked by the same Shipit instance (including one the attacker controls, e.g. their own fork added as a stack, or any stack sharing that commit through history), the attacker can trigger (or directly send) a correctly-signed `status` webhook from their own repository reporting `state: 'failure'` for that sha. Because the handler does not scope by repository, this creates a `Status` row against the victim's `Commit` as well. `MergeRequest#any_status_checks_failed?` then evaluates true for the victim's healthy, pending PR: [4](#0-3) 

`ProcessMergeRequestsJob` subsequently calls `reject_unless_mergeable!`, which rejects the victim's merge request with `'ci_failing'` purely due to the cross-repository status write: [5](#0-4) 

No existing guard (`verify_signature`, `drop_unhandled_event`, the `ExplicitParameters` schema in `StatusHandler`) checks that the sha belongs to the repository named in the payload; the schema only requires `sha` and `state` as strings with no repository binding.

### Impact Explanation
A webhook correctly authenticated for repository A can mutate `Status`/rejection state for a `Commit`/`MergeRequest` belonging to repository B, matching the "payload for one repository mutating another repository's commit/task" Critical category: it forces an unauthorized rejection of a legitimate, passing pull request without the victim repository's own CI ever reporting failure. This is repeatable against any stack whose tracked commit sha is shared with a stack the attacker can produce webhooks for, and it directly denies a legitimate merge/deploy action rather than merely affecting availability.

### Likelihood Explanation
Exploitation requires: (1) the victim's PR head sha to also exist as a `Commit` row under a different stack tracked by the same Shipit instance (realistic in fork-based, monorepo-split, or multi-mirror setups, since git commit shas are preserved verbatim across forks/clones), and (2) the attacker to be able to produce a validly GitHub-signed `status` event for that sha from a repository/org they control that Shipit has a `GithubApp` installation for. The attacker needs no Shipit session, API token, or webhook secret - GitHub itself computes and sends the valid signature for the attacker's own repository. The core code defect (unscoped `Commit.where(sha:)` lookup) is unconditional and applies on every incoming `status` webhook.

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and analogous handlers like `CheckSuiteHandler`) by the repository identified in the webhook payload (e.g., join through `stack.repository` matching `params.repository.full_name`/`owner.login`), not by `sha` alone, before calling `create_status_from_github!`.

### Proof of Concept
Minitest plan (models/webhook-level, no live GitHub):
1. Create two stacks/repositories, `stack_a` (victim) and `stack_b` (attacker-controlled), each with a `Commit` row sharing the identical `sha` value.
2. Create a `MergeRequest` on `stack_a` in `pending` state whose `head` is the shared commit, with all required statuses currently `success`.
3. Assert baseline: `merge_request.any_status_checks_failed?` is `false` and `merge_request.reject_unless_mergeable!` returns `false`.
4. Simulate the webhook payload for `stack_b`'s repository with `sha` equal to the shared sha and `state: 'failure'`, and invoke `Shipit::Webhooks::Handlers::StatusHandler.new(params).process` (or POST through `WebhooksController#create` with `verify_signature` stubbed true for `stack_b`'s org, mirroring `webhooks_controller_test.rb`'s pattern).
5. Assert the equality now diverges: `stack_a`'s shared `Commit` gained a `failure` `Status` even though no webhook authenticated for `stack_a`'s repository was sent.
6. Reload `merge_request`, assert `merge_request.any_status_checks_failed?` is now `true`, call `reject_unless_mergeable!`, and assert it returns `true` with `merge_request.rejection_reason == 'ci_failing'` - demonstrating the healthy victim PR was rejected solely by a foreign-repository-authenticated webhook.

### Citations

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

**File:** app/models/shipit/merge_request.rb (L155-162)
```ruby
    def reject_unless_mergeable!
      return reject!('merge_conflict') if merge_conflict?
      return reject!('ci_missing') if any_status_checks_missing?
      return reject!('ci_failing') if any_status_checks_failed?
      return reject!('requires_rebase') if stale?

      false
    end
```

**File:** app/models/shipit/merge_request.rb (L199-202)
```ruby
    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end
```
