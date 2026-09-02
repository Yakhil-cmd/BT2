### Title
Unscoped `Commit.where(sha: params.sha)` fan-out lets a status webhook from any onboarded organization write a `Status` row into an unrelated stack's commit - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit(s) for an incoming GitHub `status` webhook purely by matching the raw `sha` string against the entire `commits` table, with no repository/stack scoping. Any organization legitimately onboarded to a multi-tenant Shipit instance can therefore cause a `Status` row to be written into a completely different organization's stack whenever a commit sha collides (most reliably via a git fork, where ancestor commit shas are identical by construction).

### Finding Description
The broken binding: *"a `Status` row written under `stack_id = S` == an event authenticated as originating from stack `S`'s own repository"* — this is false in this code path.

`StatusHandler#process` does: [1](#0-0) 
`Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — it never checks `params['repository']` against `commit.stack.repository`. Contrast this with `PushHandler`, which correctly scopes through the tenant-aware `stacks` helper before touching any stack: [2](#0-1) .

Signature verification (`WebhooksController#verify_signature`) only proves the payload was signed by *some* configured organization's GitHub App secret (`Shipit.github(organization: repository_owner)`), not that the sha inside the payload belongs to that organization's repository: [3](#0-2) . Shipit explicitly supports many independent organizations sharing one instance/database via per-org GitHub Apps: [4](#0-3) .

Exploit flow:
1. Attacker owns/forks a public repository that is also tracked (under a different org/stack "Victim") by the same Shipit instance. Because git commit SHAs are content-addressed, all ancestor commits of the fork share identical SHAs with the upstream victim repo.
2. Attacker's own org ("Attacker") is itself a legitimate, separately configured tenant on the same Shipit instance (a normal, documented multi-org setup).
3. Attacker calls GitHub's real Statuses API (`POST /repos/attacker/repo/statuses/:sha`) on their own repo with `state: 'error'` and a `context` chosen to match Victim's `blocking_statuses`, for a sha that is a shared ancestor commit. This requires only write access to their own repo — no Shipit or GitHub secret.
4. GitHub signs and delivers this webhook using Attacker's own installation secret. `verify_signature` passes because it validates against Attacker's own org config, which is correct and legitimate for Attacker's own data.
5. `StatusHandler#process` then matches `Commit.where(sha: ...)` against the *entire* `commits` table, finds Victim's `Commit` row (a different `stack_id`), and calls `commit.create_status_from_github!(params)`, writing a `Status` row with `stack_id = Victim's stack.id` — despite the request never being authenticated for Victim's organization at all: [5](#0-4) .

No existing guard catches this: `verify_signature` checks org-level HMAC only, `drop_unhandled_event`/`ExplicitParameters` only validate shape, and there is no `Repository`/`stack` cross-check anywhere in `StatusHandler`.

### Impact Explanation
An attacker who legitimately controls one tenant/org on a shared Shipit instance can write arbitrary-content `Status` rows (`state`, `context`, `description`, `target_url` all attacker-controlled) into another tenant's `Commit`, under that victim stack's real `stack_id`, without ever authenticating against that victim's repository. This is a payload for one repository mutating another's `stack`/`commit` data — matching the "Critical" category ("a payload for one repository mutating another's stack, commit, task or team"). It is fully repeatable against any commit sha shared by two repositories tracked in the same instance (trivially guaranteed via forking), and the blast radius covers every tenant hosted on the same Shipit deployment.

### Likelihood Explanation
Requires: (1) a multi-tenant Shipit deployment (documented, supported configuration), (2) the attacker's own org already onboarded as a normal, unprivileged tenant, and (3) a sha collision between the attacker's repo and the victim's repo — trivially satisfied for any fork relationship, which is common for open-source or internally-shared repos. Attacker cost is a single legitimate GitHub Statuses API call on a repo they own; no secrets, no elevated Shipit role. Fully repeatable and deterministic once the fork exists.

### Recommendation
Scope `StatusHandler#process` (and any other sha-keyed handler) by repository, e.g. resolve the target stack(s) via the payload's `repository.full_name`/`owner` first (as `PushHandler` does with the `stacks` helper), and only look up commits within that stack, instead of `Commit.where(sha: params.sha)` globally.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "process does not write a Status into an unrelated stack sharing a sha" do
  victim_stack = shipit_stacks(:shipit)
  attacker_stack = create_stack!(repository: shipit_repositories(:other)) # different org/repo

  shared_sha = "abc123deadbeef00000000000000000000000f"
  victim_commit = victim_stack.commits.create!(sha: shared_sha, ...)
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, ...)

  params = {
    'sha' => shared_sha, 'state' => 'error', 'context' => 'ci/attacker',
    'branches' => [{ 'name' => attacker_stack.branch }]
  }

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.new.call(params)
  end
end
```
This asserts the equality that should hold — a webhook scoped to `attacker_stack`'s repository must not write a `Status` whose `stack_id` equals `victim_stack.id` — and demonstrates that, with the current unscoped `Commit.where(sha:)` lookup, that equality is violated (the count changes).

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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
