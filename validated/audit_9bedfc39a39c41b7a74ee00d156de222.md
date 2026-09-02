### Title
Cross-tenant status forgery via unscoped `Commit.where(sha:)` lookup in webhook `status` handler - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` only proves that a webhook payload was HMAC-signed with the `webhook_secret` configured for the *organization named in the payload* (`repository_owner`), not that the `sha` referenced in the payload belongs to a repository controlled by that organization. `StatusHandler#process` resolves the target commit(s) with a global `Commit.where(sha: params.sha)` query with no scoping to the verified organization/stack, so a signature legitimately produced by an attacker's own org can write a status onto an unrelated victim's `Commit`, using the victim's `stack_id`.

### Finding Description
Binding claimed correct: `stack_id` written by `Status.replicate_from_github!` == `stack_id` of the repository whose `webhook_secret` verified the request. This is broken.

Trace:
1. `WebhooksController#verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` where `repository_owner = params.dig('repository','owner','login')` (attacker-controlled JSON field), and calls `github_app.verify_webhook_signature(signature, raw_post)`, which HMACs the secret configured for *that organization* in Shipit's own config (`lib/shipit/github_app.rb` `verify_webhook_signature`, `lib/shipit.rb` `github_app_config`). [1](#0-0) [2](#0-1) [3](#0-2) 

2. This only proves "the sender knows org A's webhook secret" (which an attacker legitimately does for their own onboarded organization/GitHub App installation). It says nothing about which `sha`/repository the payload body claims to reference.

3. `StatusHandler#process` then does a **global, cross-tenant** lookup by sha alone:
```
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [4](#0-3) 

4. `Commit#create_status_from_github!` writes the status keyed by the **victim commit's own `stack_id`**, not any value derived from the verified organization:
```
def create_status_from_github!(github_status)
  add_status do
    statuses.replicate_from_github!(stack_id, github_status)
  end
end
``` [5](#0-4) 

5. `MergeRequest#all_status_checks_passed?` reads `head.statuses_and_check_runs` for the victim stack's head commit, evaluated against the victim stack's own deploy spec, and can now return `true` because of the injected status: [6](#0-5) 

6. `ProcessMergeRequestsJob#perform` refreshes pending merge requests and calls `merge_request.merge!` once `all_status_checks_passed?` is true: [7](#0-6) [8](#0-7) 

Attacker exploit flow: an attacker administers (or onboards) their own GitHub org/repo `A` into Shipit as a legitimate stack, and therefore genuinely knows/possesses a valid webhook secret for `A` (or can have GitHub sign a real webhook from `A`). The attacker forks the victim's repo (or otherwise produces a commit object bit-for-bit identical to one already tracked as a `MergeRequest#head` in victim stack `S2` — trivial via fork, since forking shares the exact same commit objects/shas as the upstream repository at fork time, satisfying the "cherry-pick/copy the exact commit" premise without any cryptographic hash collision). The attacker then sends (or has GitHub genuinely send, since the sha is real and reachable in their own fork) a `status` webhook whose `repository.owner.login` is their own org `A` and whose `sha` equals the victim's `MergeRequest#head.sha`. `verify_signature` passes (A's own secret is used correctly). `StatusHandler` then matches `Commit.where(sha: ...)` against **every** `Commit` row across every stack sharing that sha — including the victim's `S2` row — and writes a `success` status keyed to `S2`'s `stack_id`.

Existing guards do not prevent this: `verify_signature` validates the sender/org, not the object graph being mutated; `drop_unhandled_event` only filters unknown event types; there is no `ExplicitParameters` constraint tying `sha` to `repository`/`stack`; no model validation on `Status`/`Commit` enforces that the writing organization owns the target stack.

### Impact Explanation
A payload authenticated for one repository/organization (`A`, attacker-controlled) mutates another tenant's stack (`S2`, victim), injecting a fabricated CI "success" status on the victim's merge-request head commit. This can flip `MergeRequest#all_status_checks_passed?` to `true` for a pending PR in `S2` and cause `ProcessMergeRequestsJob` to call `MergeRequest#merge!`, which invokes `stack.github_api.merge_pull_request` against the victim's real GitHub repository — an unauthorized merge triggered entirely from the attacker's own repository/webhook. This matches the Critical category "a payload for one repository mutating another's stack/commit/task/team, or an unauthorized deploy, rollback or merge." The attack is repeatable against any stack whose tracked commit shas are discoverable/reproducible by the attacker (e.g., any fork of a public repo, or any PR the attacker can view), and is not limited to a single victim — it generalizes to all stacks sharing the collided sha value across the whole Shipit instance, since the `Commit.where(sha:)` lookup is global.

### Likelihood Explanation
Preconditions: the attacker must control a Shipit-onboarded repository/organization of their own (a normal, low-privilege capability — any GitHub user able to have their org/repo added to Shipit, or simply able to make GitHub emit a genuinely signed webhook for their own repo). They need a commit whose sha equals the victim `MergeRequest#head.sha`; this is trivially achieved for any public (or attacker-readable) repo by forking it, since forked commits retain identical shas — no actual SHA-1 collision engineering is required. No Shipit secrets, sessions, API tokens, or team membership are needed. This is a single, cheap, repeatable HTTP POST to `/webhooks` per victim PR.

### Recommendation
Scope the webhook `sha`→`Commit` resolution to the verified organization/repository instead of a bare global `Commit.where(sha:)` lookup. Concretely, in `StatusHandler#process` (and similarly `PushHandler`/`CheckSuiteHandler` if they have the same pattern), join through `Stack`/`Repository` and filter by `params.dig('repository','full_name')` (or `owner/login` + `name`) matching the `repository_owner` that was cryptographically verified, e.g. `Commit.joins(stack: :repository).where(sha: params.sha, repository: { full_name: verified_repo_full_name })`. Reject/ignore commits whose stack's repository does not match the payload's authenticated repository.

### Proof of Concept
Add to `test/controllers/webhooks_controller_test.rb` (or a new test file), a minitest asserting the binding both ways:

1. Create two stacks/repos `S1` (attacker-owned, e.g. `attacker/repo`) and `S2` (victim, e.g. `victim/repo`) with distinct `webhook_secret`s configured in `Shipit.github` per-organization config.
2. Create a `Commit` for `S2` with `sha = "deadbeef..."` and a `MergeRequest` in `S2` whose `head` is that commit, currently pending with no passing statuses (`all_status_checks_passed?` == false).
3. Also create a `Commit` for `S1` with the **same** `sha`, simulating the attacker's fork containing the identical commit object.
4. Build a `status` webhook JSON body with `sha = "deadbeef..."`, `state: "success"`, and `repository.owner.login = "attacker-org"` (S1's org).
5. Sign the payload with **S1's** `webhook_secret` only (never S2's), and POST to `/webhooks` with `X-Github-Event: status`.
6. Assert:
   - `assert_response :ok`
   - `assert_difference('S2_commit.statuses.count', 1)` around the POST — proving a status row was written under `S2`'s `stack_id` despite the request only ever authenticating against `S1`'s secret.
   - `S2_merge_request.reload.all_status_checks_passed?` becomes `true` (false before the request).
   - `ProcessMergeRequestsJob.new.perform(S2_stack)` (with `stack.github_api.merge_pull_request` stubbed/expected) results in `S2_merge_request.reload.merged?` being `true`, or at minimum `merge_pull_request` is invoked — proving `#merge!` was reached for a stack whose webhook secret was never used to authenticate the triggering request.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/merge_request.rb (L164-191)
```ruby
    def merge!
      raise InvalidTransition unless pending?

      raise NotReady if not_mergeable_yet?

      stack.github_api.merge_pull_request(
        stack.github_repo_name,
        number,
        merge_message,
        sha: head.sha,
        commit_message: 'Merged by Shipit',
        merge_method: stack.merge_method
      )
      begin
        if stack.github_api.pull_requests(stack.github_repo_name, base: branch).empty?
          stack.github_api.delete_branch(stack.github_repo_name, branch)
        end
      rescue Octokit::UnprocessableEntity
        # branch was already deleted somehow
      end
      complete!
      true
    rescue Octokit::MethodNotAllowed # merge conflict
      reject!('merge_conflict')
      false
    rescue Octokit::Conflict # shas didn't match, PR was updated.
      raise NotReady
    end
```

**File:** app/models/shipit/merge_request.rb (L193-197)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end
```

**File:** app/jobs/shipit/process_merge_requests_job.rb (L21-26)
```ruby
      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
```
