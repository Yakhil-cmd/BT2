### Title
Webhook signature check binds to `repository.owner.login`, but every event handler acts on `repository.full_name` — a multi-tenant Shipit deployment lets a valid webhook secret for one GitHub org sign a payload that mutates stacks belonging to a different org's repository - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp`/secret to validate the HMAC signature against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` (or the `organization.login` fallback) [1](#0-0) [2](#0-1) . Every default event handler, however, resolves *which repository/stacks to mutate* using a completely different JSON field, `repository.full_name`, via `Shipit::Webhooks::Handlers::Handler#stacks`/`#repository_name` [3](#0-2) . In a multi-tenant Shipit install (`Shipit.github(organization:)` supports one `GitHubApp`/secret per organization key under `secrets.github`) [4](#0-3) , these two fields are never cross-checked against each other, so a signature that is valid for organization A's webhook secret does not guarantee the acted-upon repository actually belongs to organization A.

### Finding Description
The binding the engine relies on is: `organization whose secret validated the HMAC signature == organization owning the repository the handlers write to`. Rules text calls this out explicitly ("an organization that authenticated versus the repository that is written").

Concretely:
1. `verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` and fetches `Shipit.github(organization: repository_owner)`, then calls `verify_webhook_signature(signature, raw_post)` on that org-specific `GitHubApp` [1](#0-0) .
2. `GitHubApp#verify_webhook_signature` HMAC-verifies the *entire raw body* against that org's configured `webhook_secret` [5](#0-4) . This proves only that the payload was signed by whoever holds organization A's secret — i.e., anyone who legitimately owns/administers a GitHub App installation or webhook for org A (a real, low-privilege tenant boundary in a multi-org Shipit deployment).
3. `Shipit::Webhooks::Handlers::Handler#repository_name` and `#stacks` read `payload.dig('repository', 'full_name')` — a sibling field in the same JSON body, independent from `repository.owner.login` — to locate the `Repository`/`Stack` that will actually be mutated (e.g. `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` on stacks scoped by that repository) [3](#0-2) [6](#0-5) .
4. Nothing in the controller or in `ExplicitParameters`-based handler param definitions asserts `repository.full_name.split('/').first == repository.owner.login`. An attacker who legitimately controls org A's GitHub App/webhook configuration (knows org A's `webhook_secret`) can therefore submit a raw POST body where `repository.owner.login = "org-a"` (so the signature check picks and passes org A's secret) while `repository.full_name = "org-b/some-repo"` (so the handler mutates a stack that belongs to organization B, which the attacker does not control).

This is analogous to the Sherlock finding's pattern in kind, not in mechanism: the audited contract checked one field/derived value (`TotalVotingPower`-based threshold) while the actually consequential action (`propose()`/vote tallying) used a different, decoupled quantity that could diverge from the intended guard. Here, the "guard" (signature-selecting org) and the "acted-upon" value (mutated repository's owner) are two independent fields inside one payload with no equality enforced between them.

### Impact Explanation
This breaks the deployment-trust binding "organization that authenticated versus the repository that is written." In a Shipit instance configured for multiple GitHub organizations (each with its own App/`webhook_secret` under `secrets.github`), a party who is only authorized within organization A's GitHub App/webhook settings can forge webhook events that cause the engine to act on organization B's stacks/repositories — e.g. `push` events triggering `stack.sync_github(expected_head_sha:)`, or `pull_request`/`status`/`check_suite` handlers mutating `PullRequest`, `Commit`, and CI status state for a repository they do not own. This is a cross-organization/cross-repository write performed without any credential belonging to the target organization, which matches the Critical "cross-repository writes" impact bucket.

### Likelihood Explanation
Requires a Shipit deployment configured with more than one GitHub organization (multi-tenant `secrets.github` keyed by org) — a documented, supported configuration per `Shipit.github_organizations`/`github_app_config` [7](#0-6) . Any actor who can configure/own a webhook delivery for one tenant org (an "unprivileged" party with respect to the *other* tenant) can exploit this with no GitHub App private key, no `api_clients_secret`, and no direct write access to the victim's repository — they only need their own org's already-known webhook secret, which they are entitled to have as the admin of their own tenant's GitHub App configuration.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), assert that the organization used to select/validate the webhook secret matches the owning organization of `repository.full_name` before dispatching to handlers — e.g., require `repository.full_name.split('/').first.casecmp?(repository_owner)` and reject (422) on mismatch, or resolve the handler's target `Repository` scoped to `repository_owner` rather than trusting `repository.full_name` alone.

### Proof of Concept
1. Configure Shipit with two orgs in `secrets.github`: `org-a` (secret `SECRET_A`, known to attacker) and `org-b` (secret `SECRET_B`, unknown to attacker), per `lib/shipit.rb#github_app_config`.
2. Attacker builds a `push` webhook JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen sha>",
     "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(SECRET_A, raw_body)>` using the secret they legitimately know for `org-a`.
4. `WebhooksController#verify_signature` computes `repository_owner = "org-a"`, fetches `Shipit.github(organization: "org-a")`, and `verify_webhook_signature` succeeds because the signature matches `SECRET_A` over the full raw body [1](#0-0) .
5. `Shipit::Webhooks::Handlers::PushHandler#process` (via `Handler#stacks`) resolves the target repository from `payload.dig('repository', 'full_name') == "org-b/victim-repo"`, and calls `stack.sync_github(expected_head_sha:)` on `org-b`'s stack — mutated using only `org-a`'s credentials [3](#0-2) [6](#0-5) .

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
