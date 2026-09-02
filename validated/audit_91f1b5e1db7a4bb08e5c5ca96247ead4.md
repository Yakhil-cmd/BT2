This confirms the vulnerability chain. `Shipit::WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) selects which GitHub App/organization config to use for HMAC verification based on `repository_owner`, which is read straight from the **unverified** JSON body (`params.dig('repository', 'owner', 'login')`, line 61) before any signature check occurs. In a multi-tenant Shipit deployment (`Shipit.github(organization:)` in `lib/shipit.rb:170-181`, keyed per-organization via `github_app_config`), each org's `webhook_secret` is independently optional (documented as optional in `docs/setup.md:30` and `config/secrets.development.example.yml:11`). If `webhook_secret` is blank for org, `GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`) trivially `return true unless webhook_secret` — verification is skipped entirely for that org.

Downstream, event handlers such as `PushHandler#stacks` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`, `app/models/shipit/webhooks/handlers/push_handler.rb`) resolve the target repository via `Repository.from_github_repo_name(payload.dig('repository','full_name'))` — the **same unverified JSON body**, not the organization used for signature verification. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

### Title
Webhook signature verification org is selected from an unauthenticated payload field, decoupling "who authenticated" from "what repository is written" - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks the GitHub App (and its `webhook_secret`) used to authenticate an inbound webhook based on `repository.owner.login` taken from the raw, not-yet-verified request body. In a multi-org Shipit deployment where at least one configured organization has no `webhook_secret` set (an explicitly supported/optional configuration), an attacker can submit a forged webhook whose `repository.owner.login` names the unsecured organization (bypassing verification, since `verify_webhook_signature` short-circuits to `true` when no secret is configured) while `repository.full_name` names an arbitrary repository belonging to any other, properly secured organization tracked by the same Shipit instance. Every default handler (`PushHandler`, status handler, `pull_request` handlers, etc.) resolves the acted-upon repository purely from `repository.full_name` in that same forged, unauthenticated payload — never re-checking that the org used for signature verification matches the org owning the target repository.

### Finding Description
The binding that should hold is: `organization whose webhook_secret authenticated the request == organization owning the repository being written to`. Both sides of this equality are drawn from the same untrusted JSON body before it is authenticated:

- Authentication side: `repository_owner` (`app/controllers/shipit/webhooks_controller.rb:59-62`) is used to fetch `Shipit.github(organization: repository_owner)` (line 25), which resolves per-org secrets via `github_app_config` (`lib/shipit.rb:196-200`).
- Write side: every handler's `repository_name`/`stacks` helper (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) and per-handler `repository` methods (e.g. `PushHandler`, `PullRequest::ClosedHandler`, `LabeledHandler`) resolve the target `Repository`/`Stack` from `payload.dig('repository', 'full_name')` — a completely independent field of the same unauthenticated body.

Because `GitHubApp#verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank (`lib/shipit/github_app.rb:76-83`), and `webhook_secret` is documented and configured as optional per-organization (`docs/setup.md:30`, `config/secrets.development.example.yml:9-11`, `test/dummy/config/secrets_double_github_app.yml`), an attacker only needs one org in the Shipit instance's multi-tenant config (`Shipit.github_organizations`, `lib/shipit.rb:190-194`) to lack a webhook secret. They then set `repository.owner.login` to that unsecured org's name to sail through `verify_signature`, while setting `repository.full_name` to any tracked repository belonging to a different, fully secured organization. The signature check never validates that the "owner" claimed for authentication purposes matches the "full_name" repository actually processed.

### Impact Explanation
This breaks the equality "organization that authenticated == repository that is written," letting an unprivileged attacker forge trusted GitHub events (push, status, check_suite, pull_request, membership, etc.) for a repository/stack they do not control, as long as any other organization on the same Shipit instance has no webhook secret configured. Concretely this can trigger unauthorized `GithubSyncJob` runs, fabricate commit `Status` records that gate deploy eligibility (`ci.require`), or manipulate `PullRequest`/`ReviewStack` lifecycle (archive/unarchive, provisioning) for a fully-secured repository — i.e., an unauthorized influence over the deploy pipeline of a repository the attacker has no legitimate access to, satisfying the "unauthorized deploy" class of impact.

### Likelihood Explanation
High for any Shipit instance configured with `Shipit.github` for multiple organizations (a documented, supported deployment shape — see `docs/setup.md` "multiple Github applications" and `test/dummy/config/secrets_double_github_app.yml`) where even one org omits `webhook_secret` (explicitly called out as "optional" in setup docs). No credentials, session, or repository access are required — only knowledge of the target repository's `full_name` and one unsecured org's `login`, both public GitHub information.

### Recommendation
Do not let `verify_signature` derive its authentication organization from the same unverified payload that determines the write target. Instead:
1. Enforce that every configured organization has a mandatory, non-empty `webhook_secret` (reject boot/config if any org's secret is blank), removing the `return true unless webhook_secret` bypass in `GitHubApp#verify_webhook_signature`.
2. After verifying the signature for `repository_owner`, additionally verify that `repository.full_name`'s owner segment matches `repository_owner` (or better, resolve `Repository`/`Stack` scoped to the verified organization only) before dispatching to any handler.

### Proof of Concept
1. Configure Shipit with two organizations: `secure-org` (with `webhook_secret` set) and `open-org` (with `webhook_secret` left blank), as is explicitly supported (`test/dummy/config/secrets_double_github_app.yml`).
2. Attacker sends `POST /webhooks` with header `X-Github-Event: push`, no valid `X-Hub-Signature`, and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha>",
  "repository": { "owner": { "login": "open-org" }, "full_name": "secure-org/victim-repo" }
}
```
3. `verify_signature` calls `Shipit.github(organization: "open-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` without checking any HMAC.
4. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("secure-org/victim-repo")` (unrelated to `open-org`) and triggers `sync_github` for that stack's branch, effectively injecting a forged push event into `secure-org/victim-repo`'s pipeline despite never possessing `secure-org`'s webhook secret.

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
