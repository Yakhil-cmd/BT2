### Title
Cross-repository commit-status forgery lets any org member choose which commit range gets deployed on an unrelated stack - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` resolves target `Commit` records by `sha` alone, with no check that the webhook's authenticated repository/organization actually owns that commit. Signature verification in `WebhooksController#verify_signature` only proves the payload came from *some* repository within a GitHub organization that Shipit trusts (`Shipit.github(organization: repository_owner)`), not that it came from the specific repository that owns the target stack/commit. Since one GitHub App/webhook secret is shared across every repository in an org (`docs/setup.md` "Using Multiple Github Applications" section, keyed per-organization, not per-repo), any member with push/status access to any single repo in that org can legitimately sign a `status` event for a `sha` string belonging to a totally different, unrelated stack in the same org, and Shipit will apply that status to the matching `Commit` row.

### Finding Description
Binding claimed: `Stack#next_commit_to_deploy` (`next_expected_commit_to_deploy` in `app/models/shipit/stack.rb:332-342`) selects a commit `c` such that `c.deployable?` is true **iff** `victim/prod`'s own verified CI produced a `success` status for `c`, i.e. `c.deployable? == (status attached to c came from victim/prod's own repository)`.

Code path:
- `app/controllers/shipit/webhooks_controller.rb:24-30` `verify_signature` only checks `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` — this authenticates "some repo under org X sent this", not "the repo that owns this commit sent this." [1](#0-0) 
- `app/models/shipit/webhooks/handlers/status_handler.rb:20-24` then does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This matches **every** `Commit` row across **every stack in the database** that shares that `sha` string — it is not scoped by `repository_owner`, `repository.full_name`, or the requesting repo at all. [2](#0-1) 
- `Commit#create_status_from_github!` → `add_status` → `Status::Group.compact` recomputes `commit.state`, and `Commit#deployable?` (`app/models/shipit/commit.rb:227-229`) becomes true once a `success` status lands, feeding directly into `Stack#next_expected_commit_to_deploy` (`app/models/shipit/stack.rb:332-342`) and ultimately `trigger_deploy`. [3](#0-2) [4](#0-3) 

Root cause: the `sha` namespace is treated as globally unique for status-matching purposes, but it is only unique per-stack (`Commit` rows are scoped by `stack_id`, and multiple stacks can hold rows with identical `sha` — e.g. two Shipit-tracked repos/forks sharing history, or an attacker's own repo where the attacker submits a status for an arbitrary `sha` string via GitHub's Statuses API, which does not require the sha to correspond to a real commit in that repo).

Attacker's exact request: attacker owns/pushes to any repository under the same GitHub organization Shipit is configured for (a scratch/sandbox repo, a fork, or any repo they have push access to), calls GitHub's `POST /repos/{attacker}/{repo}/statuses/{victim_sha}` with `state=success` for the exact `sha` of the blocked "next" commit in `victim/prod` (readable from Shipit's own public dashboard or GitHub UI). GitHub relays this as a genuinely signed `status` webhook to Shipit's `/webhooks` endpoint, correctly signed with that org's shared `webhook_secret`. `verify_signature` passes because the org is legitimate; `StatusHandler#process` then blindly attaches the forged `success` status to the `Commit` record belonging to `victim/prod`.

Why existing guards fail: `verify_signature` only binds "organization", not "repository", and `StatusHandler` has zero repository binding at all — it never reads `params.dig('repository', 'full_name')` and never compares it against `commit.stack.repository.full_name`.

### Impact Explanation
An unprivileged member of the same GitHub organization (not a maintainer of `victim/prod`, not a Shipit operator) can cause `victim/prod` to select and deploy an arbitrary commit of the attacker's choosing (the "leapfrogged" commit and everything reachable in the same batch, per `maximum_commits_per_deploy` batching in `next_expected_commit_to_deploy`), including commits whose real CI is failing. This is an unauthorized/forged CI signal driving an unauthorized deploy on a foreign stack — matching the Critical category "a payload for one repository mutating another's stack, commit ... or an unauthorized deploy." It is repeatable against any stack/commit combination sharing the org's webhook secret, and blast radius covers every stack configured under that same GitHub organization in the Shipit instance (multi-tenant within one org).

### Likelihood Explanation
Preconditions: `victim/prod` and the attacker's repository must be registered under the same GitHub organization/app installation as configured in Shipit's `secrets.github` (single-org or per-org key in the multi-org config). The attacker needs only ordinary push/status-creation rights on one repo in that org (a very low bar in many real orgs — e.g., a personal sandbox repo) plus knowledge of the target `sha` (visible on Shipit's own commit/stack pages or GitHub). No Shipit session, API token, or secret is required. This is inexpensive, requires no cryptographic break, and is fully repeatable.

### Recommendation
In `StatusHandler#process`, scope the lookup to commits whose owning repository matches the webhook's authenticated `repository.full_name` (and ideally `repository.owner.login`), e.g. `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { name: repo_name, owner: repo_owner }).each { ... }`, mirroring the repository the signature was verified for. Apply the same repository-binding fix to other sha/commit-keyed handlers (e.g. `CheckSuiteHandler`, `PushHandler`) that resolve records purely by identifier without validating the owning repository against the authenticated payload.

### Proof of Concept
Adapt `test/models/commits_test.rb` and `StatusHandler` tests:
1. Set up two distinct stacks/repos: `victim_stack` (repository `victim/prod`) with `cached_deploy_spec` setting `maximum_commits_per_deploy`, and several undeployed commits where the "next" commit (`next_commit`) has no passing status (CI pending/failing).
2. Set up an unrelated `attacker_stack` (repository `attacker/scratch`) under the same configured GitHub organization.
3. Build a payload mimicking a genuine GitHub `status` webhook signed for `attacker/scratch`'s org, with `sha: next_commit.sha`, `state: 'success'`, `repository: { full_name: 'attacker/scratch', owner: { login: <org> } }`.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.new(payload).process` (or POST through `WebhooksController` with `X-Github-Event: status` and a valid signature for the org).
5. Assert the binding:
   - Before: `refute next_commit.deployable?` and `assert_nil victim_stack.next_commit_to_deploy`.
   - After processing the forged payload: `assert next_commit.reload.deployable?` and `assert_equal next_commit, victim_stack.next_commit_to_deploy`, despite the status having been submitted for `attacker/scratch`, not `victim/prod`.
6. This demonstrates `next_commit_to_deploy` changed as a direct result of a status event that never authenticated against `victim/prod`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/stack.rb (L332-342)
```ruby
    def next_expected_commit_to_deploy(commits: nil)
      commits ||= undeployed_commits do |scope|
        scope.preload(:statuses, :check_runs)
      end

      commits_to_deploy = commits.reject(&:active?)
      if maximum_commits_per_deploy
        commits_to_deploy = commits_to_deploy.reverse.slice(0, maximum_commits_per_deploy).reverse
      end
      commits_to_deploy.find(&:deployable?)
    end
```
