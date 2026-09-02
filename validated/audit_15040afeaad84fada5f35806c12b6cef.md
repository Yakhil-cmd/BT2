### Title
`StatusHandler#process` mutates any `Commit` by SHA regardless of which organization's webhook signed the payload - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits solely by `params.sha` via `Commit.where(sha: params.sha)`, with no filter on the requesting repository/organization, while `Handler` base class exposes `repository_name`/`stacks` helpers precisely to scope such lookups but `StatusHandler` never calls them. Any organization with a Shipit-configured `webhook_secret` — even one with zero `Stack` records — can sign a `status` event whose `sha` targets a commit belonging to a completely different tenant, causing a new `Status` to be written onto that victim commit.

### Finding Description
The broken binding: it should hold that `payload.dig('repository','full_name')` (the org that produced a valid `X-Hub-Signature`) `== commit.stack.repository.full_name` for every `Commit` mutated by the webhook. In `StatusHandler`: [1](#0-0) 

`process` never calls the `stacks`/`repository_name` scoping helpers defined on the base `Handler`: [2](#0-1) 

`WebhooksController#verify_signature` only proves that the request was signed with the `webhook_secret` belonging to `repository_owner` (`payload.dig('repository','owner','login')`), it does not verify that the same organization owns the commit whose `sha` is embedded in the JSON body: [3](#0-2) [4](#0-3) 

Attack flow: an attacker who has been granted Shipit access as an org owner for an unrelated/empty GitHub org (or who registers their own org with a `webhook_secret` in Shipit's secrets config) computes `HMAC-SHA1(webhook_secret, raw_body)` over a crafted JSON body: `{"repository": {"full_name": "attacker/empty-repo", "owner": {"login": "attacker"}}, "sha": "<victim-commit-sha>", "state": "success", ...}`. The `repository.full_name`/`owner.login` fields are only used to pick which `webhook_secret` to verify against — they need not correspond to any real Shipit `Stack`. Once signature verification passes, `StatusHandler.call(params)` runs `Commit.where(sha: params.sha)`, which matches the victim's commit regardless of tenant, and calls `commit.create_status_from_github!(params)` on it, writing an attacker-controlled `Status` (state/context/description/target_url) onto a commit the attacker's org never owns.

None of the existing guards prevent this: `verify_signature` authenticates "who holds a secret", not "who owns the target commit"; `drop_unhandled_event` only filters by event type; the `ExplicitParameters` schema in `StatusHandler.params` only validates types/presence of `sha`/`state`, not repository ownership.

### Impact Explanation
An attacker with any onboarded-but-unrelated org's `webhook_secret` can write arbitrary `Status` rows against any other tenant's `Commit`, provided they can obtain/guess the target commit SHA (commit SHAs are often publicly visible on GitHub or via the Shipit UI, so "guessing" is really "reading a public value"). Since `Status`/commit state can influence CI-status-gated merges and deploy readiness, this is a cross-tenant write ("a payload for one repository mutating another's ... commit"), matching the Critical severity bucket. Repeatable per commit/per request, with unlimited blast radius across any tenant whose commit SHAs the attacker can observe.

### Likelihood Explanation
Requires only that some organization (which can be the attacker's own, empty, no-stack org) is configured in Shipit's secrets with a `webhook_secret` and can reach `POST /webhooks`. No Shipit session, API token, or victim-org secret is needed. Obtaining a victim commit SHA is trivial for public repos and often knowable even for private ones (e.g., via PR notifications, CI logs). This is low-cost and fully repeatable against arbitrary commits.

### Recommendation
In `StatusHandler#process`, scope the commit lookup to the requesting organization's stacks, mirroring the `stacks`/`repository_name` helper already defined on `Handler`, e.g. restrict to `stacks.flat_map(&:commits).where(sha: params.sha)` or otherwise verify `commit.stack.repository.full_name == repository_name` before calling `create_status_from_github!`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "status webhook signed by an unrelated org with zero stacks can still mutate a victim commit" do
  victim_stack = shipit_stacks(:shipit)
  victim_commit = victim_stack.commits.create!(sha: 'a' * 40, message: 'victim', author: shipit_users(:walrus))

  # attacker org has a webhook_secret configured in Shipit but owns no Stack
  Shipit.stubs(:github).with(organization: 'attacker-org').returns(
    Shipit::GitHubApp.new('attacker-org', webhook_secret: 'attacker-secret')
  )
  assert_equal 0, Stack.where(repo_owner: 'attacker-org').count

  payload = {
    'repository' => { 'full_name' => 'attacker-org/empty-repo', 'owner' => { 'login' => 'attacker-org' } },
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'attacker-context'
  }.to_json
  signature = 'sha1=' + OpenSSL::HMAC.hexdigest('sha1', 'attacker-secret', payload)

  assert_difference -> { victim_commit.statuses.count }, 1 do
    post shipit.webhooks_path, params: payload,
      headers: { 'X-Github-Event' => 'status', 'X-Hub-Signature' => signature, 'Content-Type' => 'application/json' }
  end
  # LHS (claimed binding): attacker-org owns victim_stack.repository -> false
  # RHS (observed): victim_commit.statuses.count increased -> mutation occurred
  # LHS != RHS => binding broken
end
```

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
