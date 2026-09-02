### Title
Webhook signature verification key is selected from an unauthenticated payload field, decoupling it from the repository the event actually writes to - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: lib/shipit/github_app.rb], [File: lib/shipit.rb])

### Summary
In multi-organization deployments, `WebhooksController#verify_signature` picks which organization's `webhook_secret` to verify the HMAC signature against using `repository.owner.login`/`organization.login` from the untrusted JSON body, while the event handlers that actually act on the payload resolve the target `Repository`/`Stack` from a *different* field, `repository.full_name`. Because these two fields are never cross-checked, and because signature verification is skipped entirely (`return true`) when the resolved organization has no `webhook_secret` configured, an attacker can pick any unconfigured organization name to short-circuit verification and simultaneously point `repository.full_name` at any other tracked (victim) repository/stack.

### Finding Description
`WebhooksController#verify_signature` derives the signing organization from the request body itself: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up the per-organization config keyed by that attacker-controlled login and instantiates a `GitHubApp` with whatever `webhook_secret` (or lack thereof) is configured for it: [3](#0-2) 

Crucially, `GitHubApp#verify_webhook_signature` unconditionally passes when that organization has no `webhook_secret` set: [4](#0-3) 

This is a supported, documented configuration state — the shipped test secrets template even ships `webhook_secret: null` for an org: [5](#0-4) 

Once `verify_signature` passes, `create` forwards the *entire* attacker-controlled JSON body to the registered handlers unmodified: [6](#0-5) 

Every handler resolves its target repository from a **different** field than the one used for signature routing — `repository.full_name`, not `repository.owner.login`/`organization.login`: [7](#0-6) 

For example, `PushHandler` uses that repository lookup to enqueue a sync job with an attacker-chosen commit SHA for any not-archived stack matching the branch: [8](#0-7) 

**Broken binding:** `organization authenticated (repository.owner.login / organization.login, used to pick the verification secret) == repository written (repository.full_name, used by handlers to select the Repository/Stack acted upon)`. The engine never enforces this equality; an attacker fully controls both fields independently in the JSON payload, and can make the left side reference an organization with no configured secret (bypassing verification) while making the right side reference any other tracked victim repository.

### Impact Explanation
This lets an unauthenticated remote attacker (no Shipit session, no `ApiClient` token, no possession of any real `webhook_secret`, no GitHub App key) drive Shipit's internal GitHub-event pipeline for a **victim** repository/stack that they have no relationship to. Concretely, a forged `push` event can enqueue `GithubSyncJob` with an attacker-chosen `expected_head_sha` for the victim's tracked branch, and other handlers (`MembershipHandler`, `StatusHandler`, `CheckSuiteHandler`, pull-request handlers) can be similarly triggered against the victim stack — a cross-repository/cross-tenant write and unauthorized action against a repository the attacker never authenticated for. This matches the Critical impact bar ("cross-repository writes... unauthorized deploy").

### Likelihood Explanation
Exploitability only requires: (1) the engine configured in the multi-organization `secrets.github` schema (a supported, documented mode distinguished via `TOP_LEVEL_GH_KEYS` in `lib/shipit.rb`), and (2) at least one onboarded organization without a `webhook_secret` set (a state explicitly present in the shipped config template). No credentials, sessions, or secrets are needed by the attacker — only the ability to send an HTTP POST to the public `/webhooks` endpoint with a crafted JSON body.

### Recommendation
Bind the signature-verification organization to the same repository object the handlers act on: require `Repository.from_github_repo_name(payload.dig('repository','full_name'))` to belong to the organization resolved for signature verification (and reject if it doesn't), or verify the signature using a secret tied to the resolved target `Repository`/`Stack` rather than an attacker-suppliable login string. Additionally, do not implicitly trust-by-default (`return true unless webhook_secret`) — treat a missing `webhook_secret` for a configured organization as "verification impossible," and reject the webhook rather than accepting it unauthenticated.

### Proof of Concept
1. Configure Shipit with the multi-org `secrets.github` schema; onboard organization `unconfigured-org` with no `webhook_secret`, and separately track stack `victim-org/victim-repo` (branch `main`) under organization `victim-org` (which does have a secret configured).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "unconfigured-org" }
  }
}
```
No `X-Hub-Signature` header is required to be valid — `repository_owner` resolves to `unconfigured-org`, whose `webhook_secret` is `nil`, so `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-77`).
3. `PushHandler#process` resolves the stack via `repository.full_name` = `victim-org/victim-repo` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`) and enqueues `GithubSyncJob` with `expected_head_sha: "deadbeef..."` for that victim stack, despite the request never being authenticated against `victim-org`'s secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
