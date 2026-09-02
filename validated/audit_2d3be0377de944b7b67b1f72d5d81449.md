### Title
Webhook signature verification keyed on `repository.owner.login` while handlers act on `repository.full_name` allows spoofed CI status / stack sync when any configured GitHub organization has no `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and therefore the secret) used to authenticate an inbound webhook based on `repository.owner.login` (or `organization.login`) taken directly from the unauthenticated JSON body, but every event handler that subsequently mutates state (`StatusHandler`, `PushHandler`, etc.) resolves its target `Repository`/`Stack` from a *different* field of the same body: `repository.full_name`. Nothing binds these two fields together, and nothing prevents `verify_webhook_signature` from short-circuiting to `true` when the resolved organization has no `webhook_secret` configured. This is the same class of bug as the Dojo report: a value used for the trust/authorization decision (`repository.owner.login` → secret lookup) is not checked for consistency with the value the write path actually acts on (`repository.full_name`).

### Finding Description
`verify_signature` computes the signing organization solely from the payload: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves per-organization config, and `verify_webhook_signature` **trivially returns `true` whenever the resolved organization has no `webhook_secret` configured** — i.e., no cryptographic check occurs at all: [3](#0-2) [4](#0-3) 

Shipit explicitly supports multiple GitHub Apps/organizations configured simultaneously (`github_organizations`, `github_app_config`), and the test fixtures for this exact feature show one organization configured with `webhook_secret: # nil`: [5](#0-4) 

Once `verify_signature` passes (trivially, because the attacker names an organization whose app has no secret, or because that organization simply isn't configured with one by an operator), the request body is dispatched unmodified to the handlers: [6](#0-5) 

Every handler resolves the target stack(s) via `Handler#repository_name`, which reads `repository.full_name` — a completely independent field from `repository.owner.login` used for the auth decision: [7](#0-6) 

Concretely:
- `StatusHandler` writes a `CommitStatus` for **any** commit SHA present in the database, matched only by `sha`, with no repository scoping at all beyond what `Commit.where(sha:)` returns: [8](#0-7) 
- `PushHandler` triggers `stack.sync_github(expected_head_sha:)` for stacks resolved from `repository.full_name`: [9](#0-8) 

Because `repository.owner.login` (checked) and `repository.full_name` (acted upon) are never cross-validated, an attacker who knows (or can arrange for) any configured organization to have a blank/unset `webhook_secret` can send a forged webhook naming that organization as the owner while pointing `repository.full_name` — and thus the actual mutated `Stack`/`Commit` records — at a completely different, target repository's stack.

### Impact Explanation
This breaks the equality "organization whose signature is verified == repository/stack that is written to." The most damaging concrete effect is forging a `status` event to set an arbitrary commit's CI/deploy-safety status (`create_status_from_github!`) via `StatusHandler`, which can be used to satisfy `ci.require` checks that gate deploys, and forging `push` events to trigger `sync_github` on arbitrary stacks. This qualifies as "unauthorized deploy" enablement (High/Critical per the given rubric), since the CI-gating status used by Shipit to permit deploys can be spoofed without possessing any real webhook secret for the targeted repository/stack.

### Likelihood Explanation
Exploitability depends entirely on operator configuration: it requires that at least one configured GitHub organization in `secrets.github` has `webhook_secret` unset (as demonstrated by Shipit's own multi-org test fixture), or that the deployment uses the single-app schema without a webhook secret. Given `verify_webhook_signature` is explicitly designed to no-op when a secret is absent, and Shipit natively supports multi-organization configurations where administrators may reasonably omit a secret for a lower-trust org, this is a realistic, unprivileged (no session, no token, no repo access) misconfiguration-triggered path rather than a purely theoretical one.

### Recommendation
Bind the value used for authorization to the value acted upon: derive `repository_owner` used in `verify_signature` from the same `repository.full_name`/`owner` pair that handlers use to resolve the `Stack`, and require that the resolved `Stack`'s configured GitHub App/organization always has a non-blank `webhook_secret` (reject events, rather than accept them, when no secret is configured) — do not treat "no secret configured" as automatically verified. Additionally, consider validating that `repository.owner.login` matches the owner segment of `repository.full_name` before dispatching to handlers.

### Proof of Concept
Given a Shipit deployment configured with two GitHub organizations, e.g.:
```yaml
github:
  OrgOne:
    webhook_secret: real-secret
    ...
  OrgTwo:
    webhook_secret: # blank/unset
    ...
```
and a target `Stack` belonging to `orgone/victim-repo` with `Commit` `sha=deadbeef` gating a deploy on CI status:

1. Attacker sends `POST /webhooks` with header `X-Github-Event: status` and no valid `X-Hub-Signature` (or an arbitrary bogus value), body:
```json
{
  "repository": { "owner": { "login": "OrgTwo" }, "full_name": "orgone/victim-repo" },
  "sha": "deadbeef",
  "state": "success",
  "context": "ci/required-check"
}
```
2. `verify_signature` calls `Shipit.github(organization: "OrgTwo")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` immediately without checking the signature.
3. `StatusHandler#process` runs `Commit.where(sha: "deadbeef").each { |c| c.create_status_from_github!(params) }`, creating a passing status for `orgone/victim-repo`'s commit, independent of `OrgTwo` having any relationship to that repository.
4. If this status satisfies `ci.require` for the stack, the attacker has spoofed a required CI check for a repository/stack they have no legitimate signing credential for, potentially unblocking an unauthorized deploy.

Note: verifying the full exploit chain through to an actual triggered deploy (confirming `ci.require` gating logic consumes `CommitStatus` created this way) would require running the app; this was not executed in this read-only investigation, so the final deploy-trigger step is inferred from the documented `ci.require` behavior rather than directly observed.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
