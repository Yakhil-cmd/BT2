This confirms the vulnerability chain. `deployable?` at [1](#0-0)  requires `stack.ignore_ci? || (success? && !blocked?)`, and `success?` is delegated to `status`, which is determined purely by `Status` records attached to the commit — with no verification that those statuses came from the commit's own repository.

`StatusHandler#process` fetches commits by raw sha across the **entire database**, with no scoping to the webhook's originating repository/stack: [2](#0-1) . The `verify_signature` before_action only proves the payload was signed by *some* legitimate GitHub App/organization matching `repository_owner` (derived from the payload's own `repository`/`organization` field) — it does not tie that organization to the specific commit's stack: [3](#0-2) . `verify_webhook_signature` just checks the HMAC of the raw body against the webhook secret configured for `repository_owner`: [4](#0-3) .

Since Git commit SHAs are content-addressed and global identifiers (not scoped to a single repository), and GitHub's Status API (`POST /repos/{owner}/{repo}/statuses/{sha}`) does not require the `sha` to correspond to a commit that actually exists in the poster's repository, an attacker who owns an unrelated repository with a working GitHub App/webhook integration can create a `status` event naming the victim's pending commit sha with `state: success`. This event is genuinely signed by GitHub for the attacker's own (real, unprivileged) organization, so `verify_signature` passes. `StatusHandler#process` then matches `Commit.where(sha: params.sha)` against **every** commit table row with that sha — including the victim's, in a completely different stack/team — and calls `commit.create_status_from_github!(params)` on it, unconditionally.

This satisfies the write path described: `stack.ignore_ci? == false` (operator wants CI-gating) is irrelevant, because `deployable?`'s other branch, `success? && !blocked?`, becomes true once the forged status is attached, regardless of whose CI actually posted it.

### Title
Cross-tenant commit status forgery bypasses CI gating - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits purely by `sha` (`Commit.where(sha: params.sha)`) without any scoping to the repository/stack that authenticated the webhook, so any organization with a legitimate but unrelated GitHub App/webhook integration can attach a fabricated `success` status to another tenant's commit by naming its sha, defeating `ignore_ci?`-based CI gating.

### Finding Description
The broken binding: `commit.success?` (derived from `Status` records) should only be settable by a status posted by the CI/webhook of `commit.stack`'s own repository — i.e. `status.repository_owner == commit.stack.repository.owner` — but the code enforces no such equality at all. `StatusHandler#process` in [2](#0-1)  does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, matching by raw sha across the whole `commits` table regardless of which repository's webhook triggered the request.

The only upstream guard, `WebhooksController#verify_signature` ( [3](#0-2) ), verifies that the payload's HMAC matches the webhook secret configured for `repository_owner`, which is read from the *attacker's own* payload (`params.dig('repository','owner','login')` or `organization.login`). This only proves the request truly came from GitHub for the attacker's own org — it says nothing about which commit sha is legitimate for that org to report on.

Because git SHAs are global, content-addressed identifiers, and GitHub's status API does not require the target sha to be reachable in the reporting repository, an attacker who legitimately controls any repository with a GitHub App/webhook configured in Shipit can call GitHub's real status API against a sha copied from the victim's public commit. GitHub then delivers a genuinely-signed `status` webhook to Shipit naming that sha, which passes `verify_signature` (since it's really from the attacker's org) and is then applied to the victim's `Commit` record in an entirely different stack.

`commit.create_status_from_github!` unconditionally creates a `Status` and updates cached state via `add_status`, feeding into `deployable?` ( [1](#0-0) ): `!locked? && (stack.ignore_ci? || (success? && !blocked?))`. With `ignore_ci? == false` (the victim explicitly wants CI gating), the forged `success?` still flips `deployable?` to `true`, exactly as the question describes.

### Impact Explanation
An attacker who controls an unrelated repository can cause an arbitrary `Commit` belonging to any other tenant's `Stack` to become `deployable?` (or influence merge-queue gating that also checks `success?`/`deployable?`), without ever authenticating to or having any privilege in the victim's organization/repository. This is a cross-tenant write: a payload from repository A mutates repository/stack B's data, enabling an unauthorized deploy or merge — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge." It is repeatable against any commit sha the attacker can observe (e.g., public repos, or PR commits visible before merge), and the blast radius spans every tenant/stack sharing the Shipit instance's `commits` table.

### Likelihood Explanation
Preconditions: attacker needs any repository with a working GitHub App/webhook installation pointed at the Shipit instance (a normal, low-privilege setup any GitHub user/org can configure) and knowledge of the victim's target commit sha (typically public). No Shipit session, API token, or secrets are needed. Cost is a single GitHub API call (`POST /repos/{attacker}/{repo}/statuses/{victim_sha}`) which GitHub will sign and forward as a legitimate webhook. This is fully repeatable and requires no timing race or privileged access, making it highly feasible.

### Recommendation
Scope commit lookup in `StatusHandler#process` (and analogous handlers) to the repository/stack that authenticated the webhook, e.g. resolve `Stack`/`Repository` from `repository_owner`/`params.name` (the `repository.full_name` in the payload) and restrict `Commit.where(sha:, stack: stack_ids_for_that_repository)` before applying the status, rather than matching sha globally across all tenants.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test ":status from an unrelated foreign repository forges success on a victim commit" do
  victim_stack = shipit_stacks(:shipit) # has ignore_ci? == false
  victim_commit = victim_stack.commits.create!(sha: 'a' * 40, author: shipit_users(:shipit), authored_at: Time.now, committer: shipit_users(:shipit), committed_at: Time.now, message: 'victim commit')

  assert_not victim_stack.ignore_ci?
  assert_not victim_commit.deployable?  # no prior statuses -> unknown state

  request.headers['X-Github-Event'] = 'status'
  forged_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'branches' => [{ 'name' => 'master' }],
    'repository' => { 'full_name' => 'attacker/unrelated-repo', 'owner' => { 'login' => 'attacker-org' } }
  }.to_json

  Shipit.stubs(:github).with(organization: 'attacker-org').returns(stub(verify_webhook_signature: true))

  post :create, body: forged_payload, as: :json

  assert victim_commit.reload.deployable?, "victim commit became deployable via forged foreign-repo status"
end
```

### Citations

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
