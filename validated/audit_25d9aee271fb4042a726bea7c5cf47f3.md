### Title
Webhook signature verified against `repository.owner.login` while stack dispatch is keyed on the unvalidated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
This maps to the same bug class as the Solana `M-9` report: two places in the same operation are supposed to refer to the same authorized entity, but the code lets them diverge because one is verified while the other is trusted blindly. In the Solana case, the account marked `mut` in the on-chain program (`destination_program_pda`) didn't match the account marked writable in the transaction builder (`destination_program`). In shipit-engine, the GitHub organization whose secret is used to **verify** the webhook HMAC (`repository.owner.login`, taken from the JSON body) is a different field than the repository identifier that handlers actually **act on** (`repository.full_name`, taken from the same JSON body) — and nothing ties the two together.

### Finding Description
`Shipit::WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate the signature against using: [1](#0-0) [2](#0-1) 

using `params.dig('repository', 'owner', 'login')` (or `organization.login`). But every webhook handler resolves the target `Repository`/`Stack` using a *different* field of the very same payload, `repository.full_name`: [3](#0-2) 

The signature is computed over the full raw request body (`request.raw_post`), so it does authenticate the payload's bytes, but the code never asserts that `repository.owner.login` (used to pick the verifying secret) is the same organization/repo referenced by `repository.full_name` (used to find the `Stack` to mutate). In a Shipit instance configured for multiple GitHub organizations (`Shipit.github(organization:)`, `github_app_config`), each organization has its own independently-configured `webhook_secret`: [4](#0-3) [5](#0-4) 

This is exactly the equality binding that should hold but doesn't: `organization whose secret authenticated the request == organization/repository whose stack is written`.

### Impact Explanation
If it can be exploited, an attacker who legitimately controls the GitHub App/webhook delivery for **one** configured organization (Org A) could craft a payload where `repository.owner.login`/`organization.login` = `OrgA` (so it is verified with Org A's secret) but `repository.full_name` = `OrgB/some-repo`, causing writes against Org B's Stack (e.g. triggering `GithubSyncJob`, closing/archiving/unarchiving review stacks, labeling PRs, posting commit statuses) — none of which belong to Org A. This would be a cross-repository/cross-organization write performed with credentials scoped to a different tenant, which matches the "cross-repository writes" Critical impact category. This is architecturally the same class of bug as `M-9`: the entity actually verified is not the entity actually acted upon.

### Likelihood Explanation
This can only be exercised by someone who is already able to produce a validly-signed webhook body for at least one configured organization (i.e., someone with delivery access to a GitHub App/webhook endpoint for Org A). This is a materially different, narrower prerequisite than "install the GitHub App as the target org," and is realistic in genuinely multi-tenant Shipit deployments (`test/dummy/config/secrets_double_github_app.yml` demonstrates this configuration is supported and tested) where different customer organizations are onboarded to the same Shipit instance and are expected to be isolated from one another. Under the rules given, this does not require an `ApiClient` token, a Shipit session, `github_access_token`, or `api_clients_secret` — it only requires being one of the (mutually distrusting) onboarded GitHub organizations, so it is not automatically excluded as "requiring privileged access to this deployment."

### Recommendation
In `WebhooksController`, after resolving the payload and the organization used for verification, cross-check that the `repository.full_name`'s owner matches the same `repository_owner` value used to select the verifying secret before dispatching to handlers, e.g. reject the request (or route to the handler) only if `params.dig('repository','full_name')&.split('/')&.first&.casecmp?(repository_owner)`.

### Proof of Concept
Conceptual (not runnable without a live multi-org Shipit deployment):
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. As the entity able to produce valid webhook deliveries for `OrgA` (e.g. via `OrgA`'s installed GitHub App), send a `push` event with body:
```json
{
  "ref": "refs/heads/main",
  "after": "<sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
signed with `OrgA`'s `webhook_secret` over `X-Hub-Signature`.
3. `verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the HMAC check passes because it was legitimately signed with `OrgA`'s secret.
4. `PushHandler`/other handlers then resolve `Repository.from_github_repo_name("OrgB/victim-repo")` via `payload.dig('repository','full_name')` and enqueue `GithubSyncJob`/mutate `OrgB`'s stack — despite the request never being authenticated by `OrgB`.

Note: I was unable to fully trace every webhook `Handlers::*` class in this session (only a subset — `PullRequest::OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `LabelCapturingHandler`, the base `Handler`, and the `push`/`status` test fixtures — was inspected) to confirm that *no* handler independently re-derives or re-validates the organization from `repository.owner.login`. If a handler elsewhere in `app/models/shipit/webhooks/handlers/**` does perform such a cross-check, this finding would not hold; a full audit of that directory is recommended.

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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```
