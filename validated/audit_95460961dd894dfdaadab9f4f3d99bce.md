### Title
Webhook signature verification bypassed when `webhook_secret` is blank - (File: lib/shipit/github_app.rb)

### Summary
`GitHubApp#verify_webhook_signature` returns `true` unconditionally when the configured `webhook_secret` is blank, treating "no secret configured" as "signature verified." This lets any unauthenticated attacker send an unsigned `POST /webhooks` push event that is accepted as authentic for any organization configured without a `webhook_secret`, triggering `GithubSyncJob` for that org's stacks.

### Finding Description
The broken binding: `verified == (request signature cryptographically matches organization's webhook_secret)` is claimed by `WebhooksController#verify_signature`, but the actual code computes `verified == (webhook_secret.blank? || secure_compare(...))`.

Code path: `WebhooksController#verify_signature` calls `Shipit.github(organization: repository_owner).verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)` [1](#0-0) . In `GitHubApp#verify_webhook_signature`, the very first line is `return true unless webhook_secret`, so when `@webhook_secret` (set from `@config[:webhook_secret].presence` in `initialize`) is `nil`, the method short-circuits to `true` before any HMAC comparison happens [2](#0-1) . `verify_signature` then does `head(422) unless verified` — since `verified` is `true`, no 422 is returned, and the request proceeds to `create`, which dispatches to `Shipit::Webhooks.for_event(event)` handlers, including `PushHandler#process`, which calls `stack.sync_github` for every matching stack, which enqueues `GithubSyncJob` [3](#0-2) .

`drop_unhandled_event` only filters unrecognized event types and does not check signatures [4](#0-3) ; it does not prevent this. `repository_owner` is read directly from the attacker-controlled JSON body (`params.dig('repository', 'owner', 'login')`) [5](#0-4) , so the attacker fully controls which org's `GitHubApp` instance is used for verification, and needs only to pick/target an org whose config omits `webhook_secret`. This configuration is explicitly permitted (not required) by the docs and shown as `nil` in example config, confirming it's a realistic supported state rather than a hypothetical misconfiguration.

Attacker request: `POST /webhooks` with header `X-Github-Event: push`, no `X-Hub-Signature` header, and a JSON body containing `repository.owner.login` set to the targeted org and a valid `ref`/`after` field. No secret, session, or API token is required.

### Impact Explanation
An unauthenticated, unprivileged attacker can forge a GitHub push webhook and have it accepted as authentic for any Shipit-configured organization that lacks a `webhook_secret`. This triggers `GithubSyncJob` enqueuing for every non-archived stack on that org matching the spoofed branch, causing the deploy pipeline to sync/fetch state driven entirely by attacker-supplied, unauthenticated input. This is an authentication bypass (forged webhook accepted) affecting all stacks under the misconfigured org — repeatable on every request, with blast radius scaling to however many orgs/tenants are configured without a secret. This matches the Critical category: "authentication bypass (forged webhook accepted)."

### Likelihood Explanation
Precondition: at least one org in `Shipit.github(...)` configuration must have a blank/missing `webhook_secret`. This is a config choice, not a code bug that the attacker introduces, but it is explicitly permitted by the setup docs and shown as a valid (if discouraged) configuration in example secrets files, so it is a realistic operational state rather than a purely theoretical one. Given that precondition, the attack costs nothing (a single unauthenticated HTTP POST, no secrets/tokens needed) and is trivially repeatable.

### Recommendation
Fail closed instead of open: if `webhook_secret` is blank for an org, `verify_webhook_signature` should return `false` (reject) rather than `true`, or the application should refuse to boot/configure an org for webhook handling without a required `webhook_secret`. At minimum, log/alert loudly and reject webhooks for any org lacking a configured secret.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (proof sketch)
test "push webhook without webhook_secret configured is accepted and enqueues GithubSyncJob" do
  Shipit.stubs(:github).with(organization: 'someorg').returns(
    Shipit::GitHubApp.new('someorg', { app_id: 1, installation_id: 1, private_key: 'x' }) # no webhook_secret key
  )
  stack = shipit_stacks(:shipit) # or a stack whose repository owner is 'someorg', branch 'master'

  assert_enqueued_with(job: GithubSyncJob) do
    post shipit.github_webhooks_path,
      params: {
        ref: "refs/heads/#{stack.branch}",
        after: 'deadbeef',
        repository: { owner: { login: 'someorg' }, full_name: stack.repo_name }
      }.to_json,
      headers: { 'X-Github-Event' => 'push', 'Content-Type' => 'application/json' }
      # deliberately no 'X-Hub-Signature' header
  end

  assert_response :ok # not 422, proving verify_signature did not reject
end
```
Both sides of the binding diverge: expected `verified == false` (no signature exists to validate against attacker's unsigned request), actual `verified == true` because `return true unless webhook_secret` in `lib/shipit/github_app.rb` line 77.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit/github_app.rb (L44-83)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
    end

    def login
      raise NotImplementedError, 'Handle App login / user'
    end

    def api
      client = (Thread.current[:github_client] ||= new_client(access_token: token))
      client.access_token = token if client.access_token != token
      client
    end

    def api_status
      conn = Faraday.new(url: 'https://www.githubstatus.com')
      response = conn.get('/api/v2/components.json')
      parsed = JSON.parse(response.body, symbolize_names: true)
      parsed[:components].find { |c| c[:id] == API_STATUS_ID }
    end

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
