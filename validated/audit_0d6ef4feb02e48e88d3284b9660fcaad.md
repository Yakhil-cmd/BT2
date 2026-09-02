### Title
Cross-repository sha-collision in `StatusHandler#process` mutates unrelated Stacks' Commits - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` resolves the target `Commit` purely by `sha`, with **no scoping to the repository/stack that emitted the webhook**. In multi-tenant Shipit deployments (`secrets.github` keyed by organization, exercised by `test/dummy/config/secrets_double_github_app.yml`), a legitimately-signed `status` webhook from one tenant's own repository can create a `Status` on a `Commit` belonging to a completely unrelated `Stack`/tenant if the two happen to share a commit sha - which is guaranteed for any fork of a public upstream repository, since forks share the entire initial commit history with the upstream by GitHub's own design.

### Finding Description
The broken binding, stated explicitly: `payload.repository.full_name` (the repo that GitHub signed and delivered the event for) **must equal** `commit.stack.repository.full_name` (the repo whose `Commit` gets mutated) before `create_status_from_github!` is called. `StatusHandler#process` never establishes or checks this equality:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

`Commit.where(sha: params.sha)` is a global, unscoped query across the entire `commits` table — it returns every `Commit` row with that sha regardless of which `Stack`/`Repository` it belongs to. Contrast this with `CheckSuiteHandler#process`, which at least scopes lookups through `stacks.where(branch: ...)` before matching by sha: [2](#0-1) 
even that handler only filters by branch name (also attacker-controlled), not by verified repository identity, but `StatusHandler` has no filter at all.

`WebhooksController#verify_signature` authenticates the *delivering organization*, not the *specific repository* named in the payload, and in multi-org configurations it authenticates strictly by `repository_owner` (`params.dig('repository','owner','login')`): [3](#0-2) [4](#0-3) 

Exploit flow (multi-tenant Shipit instance, i.e., `secrets.github` keyed by multiple orgs as in `test/dummy/config/secrets_double_github_app.yml`):
1. Attacker is a legitimate member/owner of `attacker-org`, which is *also* onboarded to the same Shipit instance with its own `webhook_secret` (attacker legitimately possesses this secret for their own org — this is not a stolen secret).
2. Victim's `upstream-org/repo` is tracked by a `Stack` in the same Shipit instance; some `Commit` with sha `S` exists in that stack (e.g., an old commit shared with a public fork, or any historic sha the attacker can discover, since fork ancestry guarantees shared shas).
3. Attacker forks/owns a repo under `attacker-org` and pushes/labels a commit, or simply crafts and POSTs a `status` event payload to `/webhooks` with `sha: S`, `state: success`, `repository.owner.login: attacker-org`, correctly signed with `attacker-org`'s own legitimate `webhook_secret`.
4. `verify_signature` passes because `attacker-org` is a known, correctly-configured organization — the signature check has no knowledge of *which repository's commit* the sha belongs to.
5. `StatusHandler#process` runs `Commit.where(sha: 'S')`, which matches the **victim's** `Commit` row (and any other tenant's row sharing that sha) with zero regard for which org/repo the webhook came from, and calls `create_status_from_github!(params)` on it, writing a new `Status` and mutating `Commit#state` via `add_status`/`replicate_from_github!`. [5](#0-4) [6](#0-5) 

No existing guard closes this gap: `verify_signature` binds only organization↔secret, not repository↔commit; `ExplicitParameters` schema on `StatusHandler` only validates types, not repo identity; there is no `Repository`/`Stack` filter anywhere in the query.

### Impact Explanation
A `Status` write (state `success`/`failure`/`error`/`pending`) is forged onto an arbitrary victim `Commit`/`Stack` that the attacker's org has no relationship to and no authorization for. `Commit#state`/`Commit#deployable?` depends on this status hierarchy, so forcing a `success` status can make a victim commit appear CI-green and deployable, or forcing `failure` can block deploys — this is "a payload for one repository mutating another's stack, commit" as scoped in the Critical bucket. The write is repeatable against any commit sha the attacker can guess or knows is shared (trivial for any public fork of the tracked upstream), and is exploitable against every tenant sharing the same Shipit instance, giving cross-tenant blast radius.

### Likelihood Explanation
Requires: (a) a multi-tenant Shipit deployment where more than one organization/app is configured under `secrets.github` (demonstrated to be a supported config via `test/dummy/config/secrets_double_github_app.yml`), and (b) the attacker legitimately controlling one such tenant (their own org's webhook secret) while targeting another tenant's `Commit` by sha. Discovering a matching sha is trivial for GitHub forks (shared history) or for public repos whose commit shas are visible. Attacker cost is minimal (a signed HTTP POST using a secret they already legitimately hold); the action is repeatable at will and does not require GitHub delivery specifically — a directly-signed POST to `/webhooks` from any host achieves the same effect.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` (and ideally `CheckSuiteHandler#process`) to the `Repository`/`Stack` identified and authenticated by the inbound webhook's `repository.full_name`/`repository.owner.login`, e.g. `Repository.find_by(...).stacks.joins(:commits).where(commits: { sha: params.sha })`, rather than an unscoped `Commit.where(sha: ...)`. Never trust `sha` alone as a tenant boundary.

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb`, mirrors existing patterns like `":state create a Status for the specific commit"`):
1. Fixtures: create `stack_attacker` under `Repository` `attacker-org/fork` and `stack_victim` under `Repository` `upstream-org/repo`, each with its own `github` config entry (mirroring `secrets_double_github_app.yml`).
2. Create `commit_victim` on `stack_victim` with `sha: "abc123..."`. Create no matching commit on `stack_attacker` (simulating a shared-history sha the attacker doesn't need to own locally).
3. Stub/allow `Shipit.github(organization: 'attacker-org').verify_webhook_signature` to return `true` (representing attacker's own legitimately-known secret for their own org).
4. POST to `/webhooks` with header `X-Github-Event: status`, body `{ sha: commit_victim.sha, state: 'success', repository: { owner: { login: 'attacker-org' } } }`.
5. Assert:
   - `commit_victim.reload.status.state == 'success'` (victim commit mutated) — proves the equality `attacker-org != upstream-org` was never checked.
   - `commit_victim.statuses.count` increased by 1, with no relationship whatsoever between `attacker-org`'s webhook and `stack_victim`/`upstream-org`.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-16)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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
