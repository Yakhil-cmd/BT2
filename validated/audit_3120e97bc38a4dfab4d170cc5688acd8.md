### Title
StatusHandler#process writes GitHub statuses to commits across unrelated stacks by SHA collision, not scoped to the webhook's authenticated repository - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits solely by `sha` (`Commit.where(sha: params.sha)`) and calls `create_status_from_github!` on every match, without filtering by the `Handler#stacks` scope that is derived from the webhook's `repository.full_name`. This lets a status webhook that is validly signed for the attacker's own GitHub organization write a `Status` record onto a commit belonging to a completely different stack/tenant, as long as the attacker can produce a commit with the same SHA (trivial, since git SHAs are content-addressed and an attacker fully controls the tree/parent/message/timestamps of a commit in their own repo).

### Finding Description
The binding the system needs to hold is: `commit.stack == Repository.from_github_repo_name(payload.repository.full_name).stacks` (i.e., the stack that receives the status write must be the stack owned by the repository named in the verified webhook payload). This binding is broken in `StatusHandler#process`:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

Unlike other handlers, `StatusHandler` never uses the `stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`) that scopes lookups to the repository named in the payload [2](#0-1) . Instead it queries `Commit` globally by `sha`, across every stack/tenant in the installation.

`WebhooksController#verify_signature` only checks that the request signature is valid for `Shipit.github(organization: repository_owner)`, where `repository_owner` is read from the attacker-controlled payload's `repository.owner.login` field [3](#0-2) . An attacker who owns a GitHub org/repo with a Shipit-configured GitHub App can legitimately generate a validly-signed `status` webhook naming their own repository, while setting `sha` to the SHA of a commit that exists in a victim's stack (git SHAs are reproducible; the attacker can construct a commit with identical author/committer/timestamps/message/tree/parents to collide with the victim's commit, since SHA1 content-addressing depends only on those fields, not on which repository stores the blob).

Since `StatusHandler#process` never checks that the commit's `stack.repository` matches the webhook's `repository.full_name`, the attacker's `state: 'success'` status is written onto the victim's commit record via `Commit#create_status_from_github!` → `Status.replicate_from_github!` [4](#0-3)  and [5](#0-4) .

This new `success` status recomputes the commit's state, and because `Commit#blocked?` depends on `stack.commits.reachable.newer_than(...).older_than(self).any?(&:blocking?)`, clearing a previously pending/failing blocking status can flip `blocked?` to `false` for the whole undeployed range, making downstream commits `deployable?` and triggering `Stack#trigger_continuous_delivery` through the `schedule_continuous_delivery` after_commit callback on `Status` [6](#0-5) .

None of the existing guards prevent this: `verify_signature` only authenticates that the payload's *claimed* organization matches the signing secret for that org — it does not bind the processed records to that organization. `drop_unhandled_event` and the `ExplicitParameters` schema only validate shape, not repository ownership. There is no `require_permission!`/`stacks` scoping applied for the `status` event, unlike `push`/`check_suite` handlers which are (or can be) scoped to `Repository.from_github_repo_name(repository_name).stacks`.

### Impact Explanation
An attacker who controls any GitHub organization/repository with Shipit webhook access (i.e., any tenant, not necessarily the victim's) can write arbitrary `Status` records (`state: success/failure/pending/error`, arbitrary `context`, `description`, `target_url`) onto any commit in any other tenant's stack, purely by SHA collision, which they fully control since they mint the source commit. This can clear a blocking status gate (`blocking_statuses`) on a victim stack they never authenticated against, causing `Commit#blocked?` to flip and enabling an unauthorized deploy via `Stack#trigger_continuous_delivery` — this is a payload for one repository mutating another's stack/commit, and an unauthorized deploy, matching the Critical impact category.

### Likelihood Explanation
Preconditions: the victim stack must have `blocking_statuses` configured with an undeployed commit currently in a pending/failing blocking state; the attacker needs their own valid GitHub App/organization registered with Shipit (any tenant) to pass `verify_signature`; and the attacker must be able to reproduce the victim's blocking commit's SHA, which is possible because git commit SHA1s are deterministic from (tree, parents, author, committer, message, timestamps) and none of these are secret — they are visible in the victim's public commit history/PR. This is a moderate-cost but fully reproducible and repeatable attack against arbitrary stacks, requiring no privileged credentials.

### Recommendation
Scope `StatusHandler#process` to the repository named in the verified webhook payload, mirroring the `stacks` helper already available on `Handler`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This ensures a status webhook can only write statuses onto commits belonging to stacks whose repository matches the authenticated payload.

### Proof of Concept
Minitest plan (e.g. in `test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create two stacks/repositories, `victim_repo`/`victim_stack` (with `blocking_statuses` configured, fixture-style like `soc_second`/`soc_third`) and `attacker_repo`/`attacker_stack`.
2. In `victim_stack`, create an undeployed blocking `Commit` with `sha = X` and an initial `Status` `state: 'pending'`, `context:` one of `blocking_statuses`. Assert `commit.blocked?` is `true` (left side of the binding: blocking gate belongs to `victim_stack`).
3. Build a `status` webhook payload with `repository.full_name = attacker_repo.full_name`, `repository.owner.login = attacker_org`, `sha: X`, `state: 'success'`, matching `context`.
4. Stub/allow `GithubHook#verify_signature` (or `Shipit.github(organization: 'attacker_org').verify_webhook_signature`) to return `true`, simulating a legitimately signed request for the attacker's own org.
5. POST the payload to `/webhooks` with `X-Github-Event: status`.
6. Assert a new `Status` (`success`) was created on the `victim_stack`'s commit (`commit.statuses.last.state == 'success'`), assert `commit.reload.blocked?` is now `false` (right side of the binding no longer matches — the stack mutated is not the stack named/authenticated in the payload), and assert `Stack#trigger_continuous_delivery`/deploy job enqueued for `victim_stack`.

### Citations

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
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
