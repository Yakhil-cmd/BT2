### Title
Cross-repository Status forgery via unscoped SHA lookup in `StatusHandler` allows injecting an attacker-controlled `target_url` into a victim stack's commit - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves the target `Commit` purely by `sha` (`Commit.where(sha: params.sha)`), never restricting the query to commits belonging to the webhook's sending repository. Because git commit SHAs are shared across forks/clones of the same history, an attacker who controls any repository sharing a commit with a victim's tracked stack can send a legitimately-signed webhook from their own repo and have Shipit write a `Status` (with an arbitrary `target_url`) onto the victim's `Commit`, which belongs to the victim's `Stack`.

### Finding Description
Binding claimed broken: `CI provider trusted by stack A's operators == origin of target_url stored on A's Status row`. Trace shows this is indeed false — the value is stored verbatim from the attacker's payload with zero host/origin validation, and worse, the lookup that decides *which* commit/stack receives the status is not scoped to the sending repository at all.

- `Shipit::Webhooks::Handlers::Handler` provides a `stacks` helper that scopes lookups to `Repository.from_github_repo_name(repository_name)` [1](#0-0) . `PushHandler` correctly uses this scoping (`stacks.not_archived.where(branch:)`) [2](#0-1) .
- `StatusHandler#process`, however, bypasses `stacks` entirely and queries `Commit.where(sha: params.sha)` globally, across every stack/repository in the Shipit instance [3](#0-2) .
- For every matching commit (regardless of which repository it belongs to), `commit.create_status_from_github!(params)` is called, which uses the *commit's own* `stack_id` — i.e., the victim's stack — to create the `Status` row: `statuses.replicate_from_github!(stack_id, github_status)` [4](#0-3) .
- `Status.replicate_from_github!` performs `find_or_create_by!` keyed on `(stack_id, state, description, target_url, context, created_at)` and stores `github_status.target_url` verbatim with no host allow-list, no scheme check, no relation to the sending repository [5](#0-4) .

Attack flow: the attacker forks (or otherwise shares commit history with) the victim repository — any commit already synced into the victim's tracked stack has an identical SHA in the attacker's fork. The attacker adds/uses their own repository's legitimately configured GitHub App/webhook (satisfying `WebhooksController#verify_signature`, which validates the signature against `repository_owner` taken from the *attacker's own* payload) [6](#0-5) , and triggers (or crafts, since only the signature over the raw body from their own repo's secret is checked) a `status` event containing `sha` = the shared commit's SHA and `target_url` = an attacker-chosen URL. This payload is correctly signed (it originates from a repository/org the attacker legitimately controls), so `verify_signature` passes even though the `sha` it references belongs to a completely different, victim-owned `Stack`. `StatusHandler` then writes the attacker's `target_url` onto the victim's `Commit`/`Stack`.

Existing guards do not stop this: `verify_signature` only checks that the payload was signed by *some* organization matching `repository_owner` in the payload — it says nothing about which `Commit`/`Stack` the payload's `sha` may touch. `ExplicitParameters` only validates types (`String`), not URL host/scheme. No model validation on `Status#target_url` restricts it to a known CI domain.

### Impact Explanation
An attacker can write a `Status` record with an arbitrary `target_url` (and arbitrary `state`/`description`/`context`) onto any victim `Stack`'s commit, as long as that commit's SHA exists in both the victim's synced history and a repository the attacker controls (trivially achieved via forking). This URL is later rendered in the victim stack's operator-facing dashboard as a clickable CI status link, enabling targeted phishing of operators who hold deploy/rollback rights — a cross-repository mutation used as a pivot toward account/credential compromise of a privileged Shipit operator. This matches the "payload for one repository mutating another's stack/commit" Critical category. The attack is repeatable against any stack/repository pair that shares commit history with a repo the attacker controls, and can also spoof `state: success` to affect `deployable?`/CI-gating logic on the victim's commit, not just the UI link.

### Likelihood Explanation
Preconditions: the attacker needs (a) a GitHub repository whose webhook is properly signed for some organization known to Shipit (`Shipit.github(organization: repository_owner)` must resolve, e.g., attacker's own org has the Shipit GitHub App installed or shares a webhook secret configuration), and (b) at least one commit SHA shared with a victim's tracked stack — satisfied automatically by forking the victim repo or any public upstream both repos track. No Shipit session, API token, or GitHub secret of the victim is required. This is low-cost and fully repeatable/scriptable against arbitrary target repositories, limited only by the attacker being able to get a `status` webhook delivered/signed for a repo they control.

### Recommendation
Scope `StatusHandler#process` the same way `PushHandler` does: resolve the target commits only through `stacks`/`Repository.from_github_repo_name(repository_name)` (i.e., `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalent join through the sending repository), never a bare global `Commit.where(sha: ...)`. Additionally, consider validating `target_url` against an allow-listed CI host or at minimum enforcing `http(s)` scheme before storage/render.

### Proof of Concept
Minitest plan (no live GitHub, uses the same style as `test/models/status_test.rb`):
```ruby
test "StatusHandler must not write a status onto a commit belonging to a different repository" do
  victim_stack = shipit_stacks(:shipit)               # tracks repo "shopify/shipit-engine"
  attacker_repo_full_name = "attacker/unrelated-repo" # different Repository/Stack

  shared_sha = victim_stack.commits.last.sha

  payload = {
    "repository" => { "full_name" => attacker_repo_full_name },
    "sha" => shared_sha,
    "state" => "success",
    "target_url" => "https://attacker.example/phish",
    "context" => "ci/attacker",
    "created_at" => Time.now.utc.iso8601,
  }

  # Binding under test, BEFORE:
  # trusted_ci_domain_for(victim_stack) == nil (no attacker-controlled status exists yet)
  assert_nil victim_stack.commits.last.statuses.find_by(target_url: "https://attacker.example/phish")

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  # Binding under test, AFTER:
  # trusted_ci_domain_for(victim_stack) == URI(attacker_status.target_url).host  -- must be false
  injected = victim_stack.commits.last.statuses.last
  assert_equal "https://attacker.example/phish", injected.target_url
  assert_equal victim_stack.id, injected.stack_id
end
```
This demonstrates that a `status` payload whose `repository.full_name` does not match the victim stack's repository still results in a `Status` row written against the victim's `stack_id`/`commit`, with the attacker's `target_url` stored unsanitized.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
