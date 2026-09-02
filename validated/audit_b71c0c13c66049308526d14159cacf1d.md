This confirms the multi-tenant GitHub App config structure: `Shipit.github(organization:)` looks up per-organization config via `github_app_config`, and each organization can independently configure (or omit) `webhook_secret` [1](#0-0) . In `GitHubApp#verify_webhook_signature`, if `webhook_secret` is blank for that org, verification is skipped entirely and `true` is returned unconditionally [2](#0-1) .

### Title
Webhook signature verification is bound to `repository.owner.login`/`organization.login` while event handlers act on the independent `repository.full_name` field, allowing cross-organization webhook forgery to trigger unauthorized syncs on victim stacks - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which `webhook_secret`) to use for HMAC verification based on `repository_owner`, derived from the attacker-supplied JSON body's `repository.owner.login` or `organization.login` field [3](#0-2) [4](#0-3) . Event handlers, however, resolve which repository/stack to act on using a *different* field in the same payload: `repository.full_name` [5](#0-4) . These two fields are never cross-validated against each other, so the organization whose credentials authenticate the request is not bound to the repository that is actually written to.

### Finding Description
This mirrors the API3 report's root cause: a value is trusted for one purpose (there, "is this timestamp stale"; here, "which organization's secret should authenticate this payload") without validating it against the field actually acted upon (there, an unchecked future timestamp; here, an unrelated `repository.full_name` used for real state changes).

Concretely:
1. `verify_signature` computes `repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` and calls `Shipit.github(organization: repository_owner)` to fetch that org's `GitHubApp` [3](#0-2) .
2. `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that organization's `webhook_secret` is blank/unset: `return true unless webhook_secret` [2](#0-1) .
3. Shipit supports multiple independently configured GitHub App organizations, each with its own optional `webhook_secret` [6](#0-5) [7](#0-6) . It is a documented, valid configuration for `webhook_secret` to be `nil` (the shipped test/dummy config even ships with `"webhook_secret": null`) [8](#0-7) .
4. Once `verify_signature` passes (trivially, for the no-secret org), `create` parses the raw body and dispatches to handlers for the declared `X-Github-Event`, passing the *entire* attacker-controlled JSON body unchanged: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [9](#0-8) .
5. Handlers such as `PushHandler` locate the target `Stack` purely from `payload.dig('repository', 'full_name')` [5](#0-4)  and then call `stack.sync_github(expected_head_sha: params.after)` for every matching, non-archived stack on the target branch [10](#0-9) .

An attacker who knows (or can configure, if they have low-privilege visibility into) any organization in the Shipit deployment that has no `webhook_secret` configured can POST a forged payload with:
```json
{
  "repository": { "owner": { "login": "org-with-no-secret" }, "full_name": "victim-org/victim-repo" },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>"
}
```
`verify_signature` resolves to the secret-less org and passes unconditionally, but the `PushHandler` acts on `victim-org/victim-repo`'s real stacks, triggering `GithubSyncJob`/`stack.sync_github` with an attacker-chosen `expected_head_sha` for a repository the attacker was never authenticated against.

### Impact Explanation
This breaks the binding "the organization that authenticated the webhook == the repository that is written to," matching the review criteria explicitly. The practical outcome is an unauthenticated, cross-organization trigger of stack synchronization/task jobs (`GithubSyncJob`, `RefreshCheckRunsJob`, commit `Status` creation, review-stack archive/unarchive, `merge` webhook handling) against a victim repository's stacks the attacker was never granted webhook credentials for. Depending on which handler is targeted, this can force syncing to an attacker-chosen commit SHA, flip commit statuses, or archive/unarchive review stacks on a repository the attacker does not control — an unauthorized state change on a deployment pipeline, without any GitHub write access, valid signature for the target org, `ApiClient` token, or session.

### Likelihood Explanation
Exploitability depends entirely on operator configuration: it requires at least one organization in the Shipit deployment's multi-tenant GitHub App config to have `webhook_secret` unset (nil/blank), which is an explicitly supported and shipped default configuration [8](#0-7) . In any deployment where that condition holds — including any org onboarded before a `webhook_secret` was set, or intentionally left unset — this is trivially exploitable by an anonymous, unauthenticated internet client with no prerequisites at all.

### Recommendation
Bind the field used to select the verification secret to the field used for authorization/processing: require `repository.owner.login` (or `organization.login`) used for secret selection to equal the owner segment of `repository.full_name`, and reject the webhook if they diverge. Additionally, treat a missing `webhook_secret` for a configured organization as a hard misconfiguration (reject the request) rather than silently trusting it, since `return true unless webhook_secret` in `GitHubApp#verify_webhook_signature` [11](#0-10)  converts an operator oversight into a full authentication bypass.

### Proof of Concept
1. Deploy Shipit with two organizations configured under `secrets.github`: `secure-org` (with a `webhook_secret`) and `insecure-org` (with `webhook_secret: nil`), each managing at least one Shipit `Stack` for a corresponding GitHub repository.
2. As an unauthenticated attacker, POST to `/github/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "repository": { "owner": { "login": "insecure-org" }, "full_name": "secure-org/victim-repo" },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-40-char-sha>"
}
```
Omit or set any arbitrary `X-Hub-Signature` header value.
3. `verify_signature` resolves `Shipit.github(organization: "insecure-org")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` regardless of the header/body.
4. `PushHandler` resolves `stacks` via `Repository.from_github_repo_name("secure-org/victim-repo")` and enqueues `GithubSyncJob`/`stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` for `secure-org`'s real stack, despite the request never being authenticated by `secure-org`'s credentials.

### Citations

**File:** lib/shipit.rb (L63-63)
```ruby
  TOP_LEVEL_GH_KEYS = [:app_id, :installation_id, :webhook_secret, :private_key, :oauth, :domain].freeze
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
