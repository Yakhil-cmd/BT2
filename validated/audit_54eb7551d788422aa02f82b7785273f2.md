### Title
Cross-organization webhook confusion allows attacker's org signature to authorize `sync_github` on a victim's `Stack` - ([File: app/models/shipit/webhooks/handlers/push_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to verify against using `params.dig('repository','owner','login')`, while `Handler#stacks` (used by `PushHandler#process`) looks up the target `Repository`/`Stack` using the independently-controlled `payload.dig('repository','full_name')` field from the same attacker-supplied JSON body. Because these two fields are never checked for consistency, an attacker who owns (or controls a secret-less) organization can forge a POST body whose `repository.owner.login` matches their own org (passing signature verification) while `repository.full_name` names a victim's repository, causing `stack.sync_github(expected_head_sha: params.after)` to run against the victim's `Stack`.

### Finding Description
The broken binding: `repository_owner` used in `WebhooksController#verify_signature` (`params.dig('repository','owner','login')`, app/controllers/shipit/webhooks_controller.rb:59-62) MUST equal the owner portion of `repository_name` used in `Handler#stacks` (`payload.dig('repository','full_name')`, app/models/shipit/webhooks/handlers/handler.rb:36-38) for the signature check to actually authorize the repository being mutated. This equality is never enforced. [1](#0-0) [2](#0-1) 

Flow:
1. `WebhooksController#create` parses `request.raw_post` and dispatches to handlers with the raw JSON as `payload`. `verify_signature` (a `before_action`) independently reads `params.dig('repository','owner','login')` from the same raw body to pick which org's `GitHubApp` (and thus which `webhook_secret`) to verify the HMAC signature against: `Shipit.github(organization: repository_owner)` → `github_app.verify_webhook_signature(...)`. [3](#0-2) 
2. `verify_webhook_signature` explicitly bypasses verification `return true unless webhook_secret` for any org that has no `webhook_secret` configured. [4](#0-3) 
3. `PushHandler#process` calls `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }`, where `stacks` comes from `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, a field the attacker fully controls and which is never cross-checked against `repository_owner`. [5](#0-4) 

Attacker request: attacker POSTs to `/webhooks` with `X-Github-Event: push`, a signature computed with the (no/self-controlled) secret for their own org `attacker-org`, and a body:
```json
{
  "repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo"},
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>"
}
```
`verify_signature` computes `repository_owner = "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and — if that org is secret-less or the attacker knows its secret because they own it — the signature check passes. `PushHandler#process` then resolves `repository_name = "victim-org/victim-repo"`, finds the real `victim-org/victim-repo` `Repository`, and calls `sync_github(expected_head_sha: <attacker-chosen sha>)` on its (non-archived, branch-matching) `Stack`, which enqueues `GithubSyncJob` for a stack the attacker does not own. [6](#0-5) 

None of the existing guards catch this: `drop_unhandled_event` only checks the event type; `verify_signature` only checks the HMAC against the org keyed by `repository.owner.login`, never comparing it to `repository.full_name`; the `ExplicitParameters` schema for `PushHandler` only requires `ref`/`after` are present, with no repository/owner validation; there is no `force_github_authentication`, `current_user`, or `require_permission!` check anywhere in this webhook path, since webhooks are meant to be authenticated purely by signature.

### Impact Explanation
An attacker who controls (or can register/get onboarded into) any organization known to Shipit — particularly one without a configured `webhook_secret`, or one where they legitimately control the secret — can trigger `sync_github(expected_head_sha: <attacker-controlled sha>)` against any other tenant's `Stack` by simply naming that repository in the `full_name` field of a forged webhook body. This results in `GithubSyncJob` being enqueued for the victim's stack with an attacker-chosen `expected_head_sha`, i.e., a payload authenticated for one organization's repository mutating another tenant's `Stack`/commit-ingestion state — matching the Critical category "a payload for one repository mutating another's stack/commit/task". This is fully repeatable against any repository present in Shipit's database, for every push to `/webhooks`, and does not require any Shipit session, API token, or knowledge of the victim's secret.

### Likelihood Explanation
Preconditions: the attacker needs an organization known to `Shipit.secrets.github` config (their own org, e.g. an onboarded self-service org) that either has no `webhook_secret` set or whose secret they know (since they own it). Given the referenced webhooks_controller.rb finding establishes that such secret-less/self-owned org signature bypass is reachable by an unprivileged attacker, the additional step here (mismatching `owner.login` vs `full_name` in the same JSON body) requires no additional secrets — only crafting an arbitrary JSON body, which is trivial for anyone who can POST to `/webhooks`. This makes the finding highly likely to be exploitable wherever the referenced signature-bypass precondition holds.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler`), derive the organization used both for signature verification and for repository lookup from a single, consistently-parsed value, and explicitly assert that `payload.dig('repository','owner','login')` (or `payload.dig('organization','login')`) equals the owner segment of `payload.dig('repository','full_name')` before processing; reject the webhook (422) on mismatch. Alternatively, have `Handler#stacks` re-verify that the resolved `Repository#owner` matches the organization actually used to authenticate the request.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test 'push webhook cannot sync a stack belonging to another organization' do
  victim_repo = shipit_repositories(:shipit) # owner: "shopify" or similar, per fixtures
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(branch: 'master')

  attacker_org = 'attacker-org'
  # stub Shipit.github_app_config to return a config for attacker_org with no webhook_secret
  Shipit.stubs(:github_app_config).with(attacker_org).returns({}) # no webhook_secret => verify returns true

  forged_sha = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
  body = {
    repository: { owner: { login: attacker_org }, full_name: victim_repo.github_repo_name },
    ref: 'refs/heads/master',
    after: forged_sha
  }.to_json

  Shipit::Stack.any_instance.expects(:sync_github).with(expected_head_sha: forged_sha)

  post shipit.github_webhooks_path,
    params: body,
    headers: {
      'X-Github-Event' => 'push',
      'X-Hub-Signature' => 'sha1=irrelevant', # accepted because attacker_org has no webhook_secret
      'CONTENT_TYPE' => 'application/json'
    }

  assert_response :ok
end
```
This asserts that a signature validated for `attacker-org` (via `repository.owner.login`) is accepted, while the actual `Stack` mutated belongs to a different, non-owned repository named only in `repository.full_name` — demonstrating the equality `repository_owner (verified) == owner(repository.full_name) (mutated)` is violated.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-30)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/stack.rb (L612-614)
```ruby
    def sync_github(expected_head_sha: nil)
      GithubSyncJob.perform_later(stack_id: id, expected_head_sha:)
    end
```
