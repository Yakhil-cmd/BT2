### Title
Webhook signature verification is keyed on `repository.owner.login` while event handlers act on `repository.full_name` from the same unauthenticated JSON body - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects *which* GitHub organization's secret to use for HMAC verification from `params.dig('repository', 'owner', 'login')`, but every webhook `Handler` resolves the repository/stack to actually mutate from a different field in the same body, `payload.dig('repository', 'full_name')`. These two fields are never cross-checked. In a multi-organization Shipit install where any one organization is configured without a `webhook_secret` (an explicitly supported/optional configuration), signature verification for that organization always succeeds regardless of the request body or signature header. An attacker who only needs to know that such a secret-less organization exists can submit a POST to `/webhooks` whose `repository.owner.login` matches the secret-less org (to pass `verify_signature` trivially) while `repository.full_name` names a completely different, unrelated repository/stack that Shipit tracks. Handlers then operate on that unrelated repository.

### Finding Description
The authentication check: [1](#0-0) 
selects the `GithubApp` instance via `Shipit.github(organization: repository_owner)` where [2](#0-1) 
`repository_owner` is `params.dig('repository', 'owner', 'login')`.

Signature verification itself is a no-op when the resolved organization has no configured secret: [3](#0-2) 
`return true unless webhook_secret` — and `webhook_secret` is optional/nullable per-organization configuration (confirmed nullable in the sample secrets file): [4](#0-3) 

Once `verify_signature` passes, `create` dispatches the *entire raw payload* to handlers: [5](#0-4) 

Every handler resolves the target repository from a *different* payload field than the one used for authentication: [6](#0-5) 
`repository_name` comes from `payload.dig('repository', 'full_name')`, not from `repository.owner.login`. For example, `PushHandler` uses this to find and sync arbitrary stacks: [7](#0-6) 

Because `repository.owner.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the repository actually acted on) are independent, unrelated JSON fields with no cryptographic binding between them, an attacker only needs one organization in the Shipit installation to be configured without a `webhook_secret` to forge a payload that is "authenticated" as belonging to that org while it actually targets any other tracked repository's stack. This breaks the equality that should hold: `organization whose secret validated the request == organization that owns the repository being mutated`.

### Impact Explanation
This allows an unprivileged network attacker (no Shipit session, no `ApiClient` token, no GitHub App private key, no `webhook_secret` for the *targeted* repository — only knowledge that some other configured org has no secret) to trigger the `push` handler's `stack.sync_github(expected_head_sha: ...)` on an arbitrary tracked stack belonging to a different, unrelated repository/organization. This is a cross-repository write / unauthorized action performed on behalf of an organization the attacker has no relationship with, satisfying the "cross-repository writes" / "unauthorized deploy" high-impact criteria, since `sync_github` drives commit ingestion that downstream feeds deploy eligibility and continuous deployment decisions for the victim stack.

### Likelihood Explanation
Likelihood is contingent on deployment configuration: it requires the Shipit installation to host multiple GitHub organizations where at least one has no `webhook_secret` configured — a state the code and shipped sample config explicitly allow (`webhook_secret: null`). Given Shipit's design goal of supporting many teams/orgs behind one instance, and that webhook secrets are optional rather than mandatory, this is a realistic operational configuration rather than a purely theoretical one.

### Recommendation
Bind the authentication decision to the same identity that handlers use to select the target: verify the webhook using the organization/repository derived from `repository.full_name` (or explicitly re-check that `repository.owner.login` matches the owner segment of `repository.full_name`) before dispatching, and consider making `webhook_secret` mandatory (reject requests when no secret is configured for an organization instead of implicitly trusting them).

### Proof of Concept
1. Shipit is configured with two organizations in `secrets.yml`: `org-safe` (no `webhook_secret`) and `org-victim` (has `webhook_secret`, tracks `org-victim/app`).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "org-safe" },
    "full_name": "org-victim/app"
  }
}
```
No valid `X-Hub-Signature` is required because `Shipit.github(organization: "org-safe").verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-83`).
3. `WebhooksController#create` dispatches to `Shipit::Webhooks::Handlers::PushHandler`, which resolves `repository_name` from `full_name` = `"org-victim/app"` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`) and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) — despite the request only ever having been "authenticated" for `org-safe`. [8](#0-7) [3](#0-2) [6](#0-5) [7](#0-6)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
