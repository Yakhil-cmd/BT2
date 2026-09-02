### Title
Cross-repository Status injection via unscoped SHA lookup in `StatusHandler#process` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)`, which is not scoped to the repository/stack that the webhook's signature was verified against. Any tenant org configured in Shipit (a legitimate but unrelated repository owner) can therefore write a `Status` row onto a commit belonging to a completely different stack, as long as the two repositories happen to share a commit SHA (trivially achievable via fork, since git preserves SHAs across forks/clones).

### Finding Description
The broken binding, stated as an equality that should hold but does not:

`status.stack_id == stack_owning(payload['repository']['full_name'])`

In reality:
`status.stack_id == commit.stack_id` for **every** `commit` returned by `Commit.where(sha: params.sha)`, with no filter on repository at all.

Code path:
- `WebhooksController#verify_signature` only checks that the payload's signature matches the webhook secret configured for `repository_owner` (`params.dig('repository','owner','login')`) [1](#0-0) . This proves the request came from *some* GitHub App installation Shipit trusts (e.g. the attacker's own, legitimately-configured org), but it says nothing about which *stack/commit* the payload is allowed to mutate.
- `StatusHandler#process` then does:
```
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [2](#0-1) 
The `params` schema only requires `sha`/`state`/etc — `repository` is never part of the schema and is never used to filter or validate which commits may be updated [3](#0-2) .
- `Commit#create_status_from_github!` calls `statuses.replicate_from_github!(stack_id, github_status)`, using the **matched commit's own** `stack_id`, not anything derived from the webhook's repository [4](#0-3)  and [5](#0-4) .
- `Commit#status` then picks `Status::Group.compact`, which returns `Status::Unknown` only when zero statuses exist, and otherwise prioritizes failure/error > pending > success [6](#0-5) . `deployable?` is gated on `success?` [7](#0-6) .

Exploit flow: attacker owns/controls a repository under any org that is a legitimately configured Shipit tenant (multiple independent orgs sharing one Shipit instance is an explicitly supported and tested configuration, see `test/dummy/config/secrets_double_github_app.yml` with `OrgOne`/`OrgTwo`, and fixtures `shopify`/`cyclimse`). Attacker forks or otherwise obtains a commit with the same SHA as an unbuilt commit in `victim/prod` (trivial via fork — git preserves SHAs), then triggers any real GitHub `status` event on their own repo/commit (e.g. by pushing a build with `state: success`). GitHub signs and delivers this webhook using the attacker-org's own valid webhook secret. `verify_signature` passes because the signature *is* valid for the attacker's own org. `StatusHandler#process` then writes a `success` `Status` onto the *victim's* commit (because `Commit.where(sha:)` is table-wide, unscoped by repository), making `victim/prod`'s HEAD `deployable?` before its own CI has posted anything.

None of the existing guards catch this: `verify_signature` authenticates the *sender org*, not the *target stack*; the `ExplicitParameters` schema on `StatusHandler` never includes or checks `repository`; `drop_unhandled_event`/`check_if_ping` are irrelevant; there is no `Repository`/`Stack` scoping anywhere in the status-write path.

### Impact Explanation
This lets a payload originating for one repository/tenant mutate another tenant's commit/stack state, matching the Critical category explicitly listed in scope ("a payload for one repository mutating another's stack, commit, task or team"). Concretely, it can flip an arbitrary victim commit to `success`, making it `deployable?` and triggering `schedule_continuous_delivery`/`ContinuousDeliveryJob`, i.e. an unauthorized deploy of code that has not passed the victim's real CI. The attack is repeatable against any commit whose SHA the attacker can reproduce (fork-based SHA reuse is deterministic and free), across any stack in the same Shipit installation, not just the one the attacker legitimately owns.

### Likelihood Explanation
Requires: (1) a multi-tenant Shipit installation with more than one Shipit-configured GitHub org/App (a supported, tested configuration in this codebase), (2) attacker having ordinary contributor/owner access to a repository under one of those other configured orgs (no privileged Shipit role needed), (3) a SHA collision between attacker's own commit and the victim's commit — trivially achieved by forking the victim repository, since forking preserves commit SHA exactly. No secrets, sessions, or API tokens are required. This is inexpensive and fully repeatable.

### Recommendation
Scope the `StatusHandler` (and any similar handler resolving commits solely by `sha`) to the repository that the webhook's verified signature covers: require and validate `params.repository.full_name` (or the org that `verify_signature` already resolved) against `commit.stack.github_repo_name`/`repository_owner` before calling `create_status_from_github!`, e.g. `Commit.where(sha: params.sha).select { |c| c.stack.github_repo_name == params.repository.full_name }`.

### Proof of Concept
Minitest plan (no live GitHub, uses fixtures):
```ruby
test "cross-repo status forgery mutates an unrelated stack's commit" do
  victim_commit = shipit_commits(:cyclimse_first) # different stack/org than :shipit
  victim_commit.statuses.destroy_all
  victim_commit.reload
  assert_equal 'unknown', victim_commit.state

  # Attacker's own repo (a different, legitimately-configured org) shares this SHA (e.g. via fork)
  forged_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'attacker/ci',
    'repository' => { 'full_name' => 'attacker/unrelated-repo', 'owner' => { 'login' => 'attacker-org' } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.new(forged_payload).process

  assert_equal 'success', victim_commit.reload.state
  assert_predicate victim_commit, :deployable?
end
```
This asserts the binding `status.stack_id == stack_owning(payload.repository.full_name)` fails: the forged payload names `attacker/unrelated-repo` but successfully mutates `victim_commit`, which belongs to an entirely different stack.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status.rb (L24-33)
```ruby
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

**File:** app/models/shipit/status/group.rb (L75-83)
```ruby
      def select_significant_status(statuses)
        statuses = reject_allowed_to_fail(statuses)
        return Status::Unknown.new(commit) if statuses.empty?

        non_success_statuses = statuses.reject(&:success?)
        return statuses.first if non_success_statuses.empty?

        non_success_statuses.reject(&:pending?).first || non_success_statuses.first || Status::Unknown.new(commit)
      end
```
