### Title
Global, repository-unscoped `Commit.where(sha:)` lookup in `StatusHandler` lets a forged webhook from a no-secret org set the CI status of a victim's commit, unlocking merge queue advancement - ([File: app/models/shipit/webhooks/handlers/status_handler.rb](), [File: app/controllers/shipit/webhooks_controller.rb](), [File: lib/shipit/github_app.rb]())

### Summary
`GitHubApp#verify_webhook_signature` returns `true` unconditionally when the resolved organization's config has no `webhook_secret`, so any attacker can forge a signed-looking `status` event by setting `repository.owner.login` to that org name. `StatusHandler#process` never re-validates that the commit being updated actually belongs to the repository named in the payload — it does a bare `Commit.where(sha: params.sha)` — so a forged event naming an unrelated (no-secret) org can still write a `CommitStatus` onto a completely different, victim-owned commit as long as the attacker knows its SHA (public information via GitHub UI/API), advancing that victim's merge queue.

### Finding Description
The broken binding is: **status_update_authorized_for(commit) == (repository_owner_in_payload == commit.stack.repository.owner)**. Before tracing, this equality should hold — a `status` webhook should only be able to mutate commits that belong to the repository/org whose secret verified it. After tracing, it does not hold.

Path:
1. `Shipit::WebhooksController#verify_signature` computes `repository_owner` purely from attacker-controlled JSON: `params.dig('repository', 'owner', 'login')` [1](#0-0) , then calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [2](#0-1) .
2. `GitHubApp#verify_webhook_signature` short-circuits to `true` when `webhook_secret` is blank for that org's config: `return true unless webhook_secret` [3](#0-2) . If any org configured in Shipit lacks a `webhook_secret` (a known misconfiguration precondition named in the question), the whole HMAC check is bypassed for a payload naming that org — with zero relation to the sha/branch/commit actually contained in the body.
3. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler#process`, which does: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [4](#0-3) . This lookup is **global across all stacks/repositories** in the Shipit instance — it does not filter by `params['repository']['full_name']` or by the org used for signature verification at all.
4. Consequently, an attacker sends `POST /webhooks` with `X-Github-Event: status`, a body whose `repository.owner.login` is the no-secret org (to pass step 2), but whose `sha` is the SHA of a commit belonging to an entirely different, victim-owned stack/repository. The forged status (e.g. `state: "success"`, matching context) is written onto the victim's commit via `create_status_from_github!`.
5. Merge queue / mergeability logic (`MergeRequest`/`Stack` merge-status checks) consumes these `CommitStatus` rows to decide if a commit is ready to merge/deploy; forging a passing status for a required context on a victim's queued commit can unblock or advance that victim's queue even though the attacker has no relationship to that repository.

No existing guard closes this gap: `drop_unhandled_event` only checks the event name is registered, not the payload's coherence; `ExplicitParameters` (`StatusHandler.params`) validates `sha`/`state` types but not repository ownership; there is no post-verification cross-check ensuring the commit resolved by `sha` actually belongs to the stack/repository identified by `repository_owner`.

### Impact Explanation
An unprivileged, unauthenticated internet client can write arbitrary `CommitStatus` records for any commit whose SHA they know (SHAs are public via GitHub's UI/API), for any stack/repository configured in the target Shipit instance, without ever proving control of, or a valid secret for, that repository or org — as long as *any* org configured in the Shipit instance is missing a `webhook_secret`. This is a cross-tenant "payload for one repository mutating another's commit/stack" scenario, matching the Critical impact category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge"). It is fully repeatable against arbitrary commits/stacks in the same Shipit install, since each request is independent and the check never gets stronger.

### Likelihood Explanation
Preconditions: (a) the Shipit instance must have at least one GitHub organization configured whose config lacks `webhook_secret` (this is the stated precondition of the question, a real-world plausible misconfiguration since `webhook_secret` is optional per-org in `Shipit.github(organization:)` config), and (b) the attacker must know the target commit SHA (trivially obtainable if the victim repo is public, or leaked via any other channel). No GitHub App private key, no `secret_key_base`, no Shipit session or API token is required — only an HTTP POST to `/webhooks`. This makes the attack cheap, remotely exploitable, and repeatable at will.

### Recommendation
- In `StatusHandler#process` (and any other handler resolving records by attacker-supplied identifiers, e.g. SHA), constrain the lookup to commits belonging to the stack/repository identified by the verified `repository_owner`/`repository.full_name`, e.g. `Commit.joins(:stack).where(sha: params.sha, stacks: { repository_owner: repository_owner, repository_name: repository_name })`.
- Independently, do not allow `verify_webhook_signature` to silently accept unsigned payloads: `webhook_secret` should be mandatory for any organization Shipit is configured to accept webhooks from, or unsigned/no-secret orgs should be explicitly rejected (`head(422)`) rather than treated as automatically verified.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test "status webhook from a no-secret org can set status on a commit belonging to a different, victim stack" do
  # Precondition: configure an org with no webhook_secret
  Shipit.stubs(:github).with(organization: 'no-secret-org').returns(
    Shipit::GitHubApp.new('no-secret-org', { app_id: 1, installation_id: 1, private_key: 'x' }) # no webhook_secret key
  )

  victim_commit = shipit_commits(:first) # belongs to victim stack/repo, e.g. "shopify/shipit-engine"

  request.headers['X-Github-Event'] = 'status'
  forged_body = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/required',
    'repository' => { 'owner' => { 'login' => 'no-secret-org' }, 'full_name' => 'no-secret-org/unrelated-repo' }
  }.to_json

  # No X-Hub-Signature header at all -- attacker cannot compute one
  assert_difference 'victim_commit.statuses.count', 1 do
    post :create, body: forged_body, as: :json
  end

  status = victim_commit.statuses.last
  assert_equal 'success', status.state
  # Equality check: repository_owner in payload ('no-secret-org') != victim_commit's actual owning repo
  assert_not_equal 'no-secret-org', victim_commit.stack.repository.owner
end
```
This demonstrates the divergence: `repository_owner` extracted for signature verification (`no-secret-org`) never matches the actual owner of the mutated commit (`victim_commit.stack.repository.owner`), yet the mutation still occurs — violating the stated invariant that "a forged webhook cannot cause any state change attributed to a repository/org whose secret did not verify it."

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
