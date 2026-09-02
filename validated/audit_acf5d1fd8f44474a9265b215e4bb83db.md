Critical finding: `StatusHandler` at [1](#0-0)  does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — it matches purely by `sha` **across the entire installation**, with no scoping to the repository the webhook claims to originate from at all. Combined with the signature-selection bug below, this is directly exploitable.

### Title
Webhook signature is verified against an attacker-chosen organization while the acted-upon repository/commit is taken from unverified payload fields - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's secret to use for HMAC verification from a payload field the attacker fully controls, then hands the same raw JSON to handlers that act on a *different, unbound* set of fields (`repository.full_name` for stack lookup, or bare `sha` for status). This is the same accounting-mismatch pattern as the referenced report: one field is used for the "authorization" decision, while a different field is what is actually acted upon, and nothing ties them together.

### Finding Description
`verify_signature` derives the signing organization from the untrusted body itself: [2](#0-1) [3](#0-2) 

Shipit explicitly supports multiple GitHub Apps/organizations, each with its own independent `webhook_secret`, selected by this same attacker-controlled key: [4](#0-3)  and documented in `docs/setup.md` "Using Multiple Github Applications" / `config/secrets.development.example.yml`.

Once `verify_signature` succeeds (using OrgA's secret because `repository.owner.login` == "OrgA"), the raw body is dispatched unchanged to handlers: [5](#0-4) 

Handlers do not re-check that `repository.owner.login`/`organization.login` (the field the signature was keyed on) matches the repository they actually act on:
- `Handler#repository_name`/`#stacks` resolve targets purely from `repository.full_name`, an independent JSON field never tied to the signing org: [6](#0-5) 
- `StatusHandler#process` is even weaker: it matches `Commit.where(sha: params.sha)` with **no repository scoping at all**, across every stack in the Shipit instance: [1](#0-0) 
- `PushHandler#process` resolves stacks via `stacks` (i.e. `Repository.from_github_repo_name(payload['repository']['full_name'])`), also independent of the org used for signature verification: [7](#0-6) 

**The broken equality:** `organization that authenticated the request` (`repository.owner.login`/`organization.login`, verified via HMAC against OrgA's `webhook_secret`) ≠ `repository/commit that is actually written to` (`repository.full_name` / bare `sha`, fully attacker-controlled and never covered by that binding). Since the signature only proves "this body's HMAC matches OrgA's secret," and OrgA's secret verifies OrgA's *own* legitimate webhook traffic, any tenant/organization that legitimately possesses one configured `webhook_secret` can craft an HTTP POST whose `repository.owner.login`/`organization.login` equals their own org (so verification passes) while `repository.full_name` (or `sha`, for `status` events) targets a completely different tenant's repository/stack.

### Impact Explanation
In a multi-organization Shipit deployment (an explicitly documented/supported configuration), a party holding a legitimate `webhook_secret` for one configured GitHub organization can forge cross-tenant events:
- Forge `status` events for any `sha` in the database (no repo scoping), injecting fake commit statuses (e.g. `state: success`) on another tenant's commits — this can satisfy `ci.require`/merge-queue and `deployable?` gating used by `MergeRequest#all_status_checks_passed?` / continuous deployment, contributing to an **unauthorized deploy or merge** on a repository the forging party has no access to.
- Forge `push` events against another tenant's stack (matched purely by branch name via `repository.full_name`), triggering `stack.sync_github` on arbitrary target stacks.
- Forge `check_suite`/`pull_request`/`membership` events against arbitrary repositories/stacks resolved only from body fields never covered by the verified org binding.

This crosses the "unauthorized deploy/merge" and "escalation" thresholds since it lets one tenant/organization act on another tenant's stack state without any legitimate relationship to that repository.

### Likelihood Explanation
Requires the attacker to be a legitimate holder of *some* configured `webhook_secret` in a multi-org Shipit instance (i.e., an org administrator of one tenant, not a privileged Shipit user, GITHUB_TOKEN holder, or someone with Shipit repository write access) — this is an "unprivileged" boundary crossing relative to *other tenants'* stacks, matching the required threat model of breaking a deployment-trust binding between orgs. Single-org deployments are not affected since there is only one secret to verify against.

### Recommendation
Bind the field used to select/verify the signing secret to the field(s) actually acted upon: after selecting `github_app` via `repository_owner`, re-verify that `params.dig('repository','full_name')` (and any `sha`/commit lookups in handlers such as `StatusHandler`) belongs to a repository owned by that same verified organization before dispatching to handlers, rather than trusting `full_name`/`sha` independently.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with distinct `webhook_secret`s (per `docs/setup.md`'s multi-org example).
2. As the legitimate holder of `OrgA`'s `webhook_secret`, craft a `status` webhook payload:
```json
{
  "sha": "<sha belonging to a commit on OrgB's private stack>",
  "state": "success",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/some-repo" }
}
```
3. Sign the raw body with `OrgA`'s `webhook_secret` and send it with `X-Github-Event: status`.
4. `verify_signature` resolves `Shipit.github(organization: "OrgA")` from `repository.owner.login`, verifies successfully.
5. `StatusHandler#process` executes `Commit.where(sha: params.sha)` — matching OrgB's commit — and creates a forged `success` status on it, with no check that this commit belongs to `OrgA`. [1](#0-0)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
