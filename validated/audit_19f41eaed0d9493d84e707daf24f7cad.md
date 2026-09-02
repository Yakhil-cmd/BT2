### Title
Webhook Signature Verification Is Scoped to `repository.owner.login`, But Handlers Act on an Unrelated `repository.full_name` / Commit `sha` — Cross-Organization Forgery of Push/Status Events - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and which `webhook_secret`) to validate a webhook against using `repository.owner.login` (or `organization.login`) taken from the JSON body. Once that check passes, the *entire* raw payload — including a completely independent `repository.full_name` field, or in the case of the `status` event a completely unscoped commit `sha` — is handed to the event handlers, which use those other fields to decide which `Stack`/`Commit` to mutate. Nothing ties the organization whose secret validated the signature to the repository/commit that is actually acted upon.

### Finding Description
`verify_signature` computes the signing organization purely from payload content: [1](#0-0) [2](#0-1) 

The resolved `GithubApp` may have no `webhook_secret` configured at all — a documented, legitimate configuration (`webhook_secret: nil`) — in which case verification is a no-op: [3](#0-2) 

Example of this legitimate but insecure default appearing in shipped config: [4](#0-3) 

Multi-organization installs are explicitly supported, each with its own independent `webhook_secret`: [5](#0-4) 

After the (possibly no-op) signature check, `WebhooksController#create` dispatches the **unmodified, full** JSON body to every registered handler: [6](#0-5) 

Handlers determine which `Stack`/`Repository` to mutate using `repository.full_name`, an entirely separate JSON field from the `repository.owner.login`/`organization.login` used for signature-org selection: [7](#0-6) [8](#0-7) 

Even worse, `StatusHandler` doesn't scope by repository at all — it matches purely on a global commit `sha` across the entire database, with no relationship whatsoever to the field used for signature verification: [9](#0-8) 

**The broken equality:** the engine implicitly assumes
`organization authenticated by verify_signature (repository.owner.login) == repository/commit written by the handler (repository.full_name / sha)`
but no code enforces this. An unprivileged network attacker who can reach `/webhooks` can pick any `repository.owner.login` value that maps to an organization/app configuration with no `webhook_secret` set (or is simply the sole configured org in a single-org, no-secret install — the documented default), and independently set `repository.full_name` (for push events) or `sha` (for status events) to target any stack/commit in the Shipit installation, including ones nominally protected by a different, secret-bearing GitHub App.

### Impact Explanation
This crosses the "unauthorized deploy" boundary called out in the rules:
- Forged `push` events invoke `stack.sync_github(expected_head_sha:)` for any targeted stack the attacker names via `repository.full_name`, regardless of which org's (lack of) secret was checked.
- Forged `status` events call `commit.create_status_from_github!(params)` for **any commit in the database** matched purely by `sha` — letting an attacker mark an otherwise-undeployable commit as CI-green, which can feed into deployability checks and, on stacks with `continuous_deployment` enabled, precipitate an automatic, unauthorized deploy.
- No `ApiClient` token, no session, no `webhook_secret`, and no privileged GitHub credential are required by the attacker — only knowledge of an organization name that resolves to a no-secret (or unset-secret) `GithubApp` configuration, which is a documented/default configuration, not an attacker-obt

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/dummy/config/secrets.test.json (L7-13)
```json
  "github": {
    "domain": null,
    "app_id": 42,
    "installation_id": 43,
    "bot_login": "shipit[bot]",
    "webhook_secret": null,
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S\n73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG\nM0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv\nibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu\npQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s\nGu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1\nu0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM\nTZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b\nqicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og\nqRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI\nRsn3r6ajlpwzpwvsJFU2Txq7xBTzGQMFmy/Pnjk83kP2cogxB2+tRyjITGqTwD8b\ngg9PFCkCgYEA+7u8A0l0C ... (truncated)
```

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
