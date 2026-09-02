### Title
Cross-repository Status webhook mutates victim stack's `ci_enabled` flag via unscoped SHA lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`, `app/models/shipit/status.rb`)

### Summary
`StatusHandler#process` resolves commits solely by SHA (`Commit.where(sha: params.sha)`) with no check that the commit's stack repository matches `payload.repository.full_name`, unlike the base `Handler` class which provides a repository-scoped `stacks` helper that this handler never uses. Because `Status#after_create` calls `enable_ci_on_stack` unconditionally, a validly signed status webhook from an attacker-controlled repository can flip `ci_enabled` on an unrelated victim stack whenever a commit with the same SHA (e.g., a shared ancestor commit from a public upstream history) exists on both.

### Finding Description
The claimed binding is: `payload.repository.full_name == commit.stack.repository.full_name` must hold before a `Status` write is allowed to mutate `commit.stack`. Tracing the code shows this binding is never checked:

- `WebhooksController#verify_signature` only authenticates that the payload was signed by the GitHub App belonging to `repository_owner` (`params.dig('repository','owner','login')`), i.e., it proves the payload originated from *some* legitimate organization/app installation, but this can be the attacker's own org if they own a repository with the Shipit GitHub App installed. It proves nothing about which stack the payload is entitled to mutate. [1](#0-0) 
- The base `Handler` class defines a repository-scoped accessor `stacks`, built from `Repository.from_github_repo_name(repository_name)` where `repository_name = payload.dig('repository','full_name')`. This is the correct scoping primitive other handlers are expected to use. [2](#0-1) 
- `StatusHandler#process` does **not** use `stacks`/`repository_name` at all. It queries `Commit.where(sha: params.sha)` directly across the entire `commits` table, with no repository filter: [3](#0-2) 
- For every matching commit (regardless of which stack/repository it belongs to), `Commit#create_status_from_github!` is invoked, which writes a `Status` via `statuses.replicate_from_github!(stack_id, github_status)`: [4](#0-3) 
- `Status#after_create` unconditionally calls `enable_ci_on_stack`, which calls `commit.stack.enable_ci!` — mutating the victim stack's CI-enablement state as a pure side effect of the insert: [5](#0-4) 

Exploit flow: the attacker forks (or otherwise controls) a public repository whose git history is shared with the victim's tracked repository up to some common ancestor commit — because git commit SHA1s are deterministic content hashes, a commit that exists unmodified in both histories has the identical SHA in both repositories. The victim's Shipit stack already has a `Commit` row for that shared SHA (created when Shipit originally ingested the victim repo's history) with `ci_enabled? == false`. The attacker triggers (or has GitHub emit) a `status` event for that same SHA on their own repository — e.g., via their own CI/Actions run, or any status-setting API call they are entitled to make on their own repo. GitHub signs and delivers this webhook using the webhook secret tied to the attacker's own organization/app installation, so `verify_signature` passes legitimately (no forged signature needed). `StatusHandler#process` then finds the victim's pre-existing `Commit` row purely by SHA match and writes a `Status` on it, flipping the victim stack's `ci_enabled` via the `after_create` callback.

None of the listed guards catch this: `verify_signature` authenticates the sender's own org, not the target stack; `ExplicitParameters` only validates payload shape (`sha`, `state`, etc.), not repository ownership; there is no `stacks`/`repository_name` check in `StatusHandler#process`; and `Status.replicate_from_github!`/`enable_ci_on_stack` perform no cross-check against `payload.repository.full_name`.

### Impact Explanation
A webhook correctly authenticated for repository A can mutate a `Stack` belonging to repository B — this is exactly the "payload for one repository mutating another's stack" Critical category. The mutated state (`ci_enabled`) affects deployability logic (`Commit#deployable?`, `stack.ignore_ci?`), so silently enabling CI gating (or disabling it, depending on direction of the flag and further exploitation via colliding SHAs to inject fake passing/failing statuses) can influence whether deploys/merges are blocked or unblocked on a victim stack the attacker has no relationship to. The attack is repeatable against any victim stack that happens to share a SHA (e.g., any stack tracking a fork of a well-known public repository, or any stack whose initial commits are shared with other forks) and requires no elevated Shipit privileges.

### Likelihood Explanation
Preconditions: (1) the attacker must control a repository/org with a valid GitHub App/webhook installation capable of emitting a correctly signed `status` webhook to the Shipit host — a low bar for anyone who can install the Shipit GitHub App on their own account/org or otherwise have GitHub deliver a status event they triggered; (2) a commit with the identical SHA must already exist as a `Commit` row tied to the victim's stack — realistic for shared/forked git histories, common ancestor commits, or if the victim stack tracks a widely-forked open-source project. This does not require brute-forcing a SHA1 collision; it only requires a shared, unmodified commit, which is routine in fork relationships. Attacker cost is a single webhook delivery; the action is repeatable at will against any stack sharing history with the attacker-controlled repository.

### Recommendation
In `StatusHandler#process` (and any other handler doing raw SHA-based lookups), scope the commit query by the stacks resolved from `payload.repository.full_name` (the `stacks` helper already provided by `Handler`), e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, rather than an unscoped `Commit.where(sha: params.sha)`. Additionally, consider guarding `Status#enable_ci_on_stack` / `Status.replicate_from_github!` to assert the status's originating repository matches the commit's stack repository as defense in depth.

### Proof of Concept
Minitest plan (no live GitHub, uses fixtures/factories and direct handler invocation to simulate a validly-parsed webhook payload):

```ruby
test "StatusHandler#process does not scope by repository, letting an attacker repo's status flip a victim stack's ci_enabled" do
  victim_stack = shipit_stacks(:shipit) # repository e.g. "shopify/shipit-engine", ci_enabled: false
  victim_stack.update!(ignore_ci: true) # ci_enabled? == false precondition
  shared_sha = "a" * 40
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "shared ancestor commit")

  attacker_payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'created_at' => Time.now.iso8601,
    'repository' => { 'full_name' => 'attacker/unrelated-repo', 'owner' => { 'login' => 'attacker' } }
  }

  assert_equal false, victim_stack.reload.ci_enabled?

  Shipit::Webhooks::Handlers::StatusHandler.call(attacker_payload)

  assert_equal true, victim_stack.reload.ci_enabled?,
    "victim stack's ci_enabled flag was mutated by a status webhook naming an unrelated repository"
end
```

Binding checked before/after: `payload['repository']['full_name']` (`"attacker/unrelated-repo"`) vs `victim_commit.stack.repository.full_name` (`"shopify/shipit-engine"` or equivalent) — they differ both before and after the call, yet `victim_stack.ci_enabled?` transitions from `false` to `true`, proving the mutation is not gated on that equality.

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

**File:** app/models/shipit/status.rb (L18-40)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

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
    end

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end
```
