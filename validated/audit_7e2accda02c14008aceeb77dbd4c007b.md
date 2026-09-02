This is confirmed as an actual, reachable vulnerability in the code as written — this is not a hypothetical.

The binding claimed broken: `webhook_secret.present?` must be `true` for `repository_owner` to gain any authentication. Tracing `verify_webhook_signature`:### Title
`GitHubApp#verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank, allowing unauthenticated webhook forgery - (File: lib/shipit/github_app.rb)

### Summary
`GitHubApp#verify_webhook_signature` starts with `return true unless webhook_secret`, so any GitHub organization configured under `secrets.github` without a `webhook_secret` skips HMAC verification entirely. Since `WebhooksController#verify_signature` selects the `GitHubApp` instance purely from the attacker-controlled `repository.owner.login` field in the JSON body, an unauthenticated attacker can post arbitrary webhook events naming that organization's login and have them processed as authentic.

### Finding Description
The intended binding is: a webhook is authenticated for organization `O` only if `Shipit.github(organization: O).verify_webhook_signature(signature, raw_body)` returns `true`, and that method should only return `true` when `SecureCompare.secure_compare(signature, HMAC(webhook_secret, raw_body))` holds. In `lib/shipit/github_app.rb`:

```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
``` [1](#0-0) 

`@webhook_secret = @config[:webhook_secret].presence` [2](#0-1)  means any org configured without `webhook_secret` has `webhook_secret` be `nil`, so the equality `webhook_secret.present? == true` is false for that org, and the method vacuously returns `true` without inspecting the `signature` or `message` argument at all.

The controller resolves which `GitHubApp` (and thus which secret policy) applies solely from attacker-supplied JSON:
```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
``` [3](#0-2) 
```
def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [4](#0-3) 

Exploit flow: attacker sends `POST /webhooks` with `X-Github-Event: push`, no (or garbage) `X-Hub-Signature`, and a body whose `repository.owner.login` names an org configured in `secrets.github` with `webhook_secret` unset (a documented optional field, and the default/legacy single-org config path via `github_default_organization`/`secrets.github` also has no forced secret). `verify_signature` looks up that org's `GitHubApp`, calls `verify_webhook_signature`, which returns `true` unconditionally, so `head(422)` is never invoked, and `create` dispatches to `Shipit::Webhooks.for_event(event)` handlers, e.g. `PushHandler`, which enqueues `GithubSyncJob` for the matching stack — with no proof the request originated from GitHub.

None of the other guards intercept this: `drop_unhandled_event` only screens by event name, not authenticity [5](#0-4) ; `check_if_ping` is unrelated; the `GithubOrganizationUnknown` rescue only fires for orgs absent from config, not for configured-but-secretless orgs [6](#0-5) ; and there is no model validation on `Repository`/`Stack` that re-checks webhook provenance downstream.

### Impact Explanation
For any org listed in `secrets.github` that omits `webhook_secret`, an unauthenticated internet attacker can forge arbitrary GitHub webhook payloads (push, status, check_suite, membership, pull_request, etc.) attributed to that org's repositories. This directly triggers real side effects without authentication, e.g. `GithubSyncJob` enqueue on `push`, commit `Status` writes, `Team`/`Membership` mutations on `membership` events — i.e., a payload for an unauthenticated caller mutating a stack/commit/team's real state. This matches the Critical category: authentication bypass (forged webhook accepted) and unauthorized state changes on a legitimate org's stacks. Blast radius is scoped per-organization: only orgs whose admin left `webhook_secret` blank are affected, but any repository/stack under such an org is reachable, and this is fully repeatable per request.

### Likelihood Explanation
This requires no privilege at all beyond network access to `POST /webhooks`, matching the "unprivileged internet attacker" threat model exactly. The precondition is that a Shipit operator configured an organization in `secrets.github` without setting `webhook_secret` — documented as optional in `docs/setup.md`, so this is a realistic and even encouraged misconfiguration for operators who don't realize the security implication. Given that precondition, the attack costs a single crafted HTTP POST with a known org login (which is public, e.g. visible in the Shipit UI/URLs) and is trivially repeatable.

### Recommendation
Do not allow `verify_webhook_signature` to vacuously succeed when no secret is configured. Either enforce `webhook_secret` as mandatory at `GitHubApp` initialization (raise/fail fast if missing) or change `verify_webhook_signature` to return `false` (reject) when `webhook_secret` is blank instead of `true`, so unsecured orgs cannot receive processed webhooks at all until properly configured.

### Proof of Concept
Minitest plan (webhooks_controller_test.rb style):
```ruby
test "does not accept unsigned webhook for org with no webhook_secret configured" do
  Shipit.stubs(:github).with(organization: 'unsecured-org').returns(
    Shipit::GitHubApp.new('unsecured-org', { app_id: 1, installation_id: 1, private_key: 'x' }) # no webhook_secret key
  )

  payload = JSON.parse(payload(:push_master))
  payload["repository"]["owner"]["login"] = "unsecured-org"

  request.headers['X-Github-Event'] = 'push'
  # no X-Hub-Signature header set at all

  assert_no_enqueued_jobs do
    post :create, body: payload.to_json, as: :json
  end
  assert_response :unprocessable_entity
end
```
Before the fix: `GithubSyncJob` is enqueued and response is `200 OK` (the equality `webhook_secret.present? == true` is false, yet `verified` is `true`). After the fix: response is `422` and no job is enqueued, restoring the equality.

### Citations

**File:** lib/shipit/github_app.rb (L50-50)
```ruby
      @webhook_secret = @config[:webhook_secret].presence
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

**File:** app/controllers/shipit/webhooks_controller.rb (L39-49)
```ruby
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```
