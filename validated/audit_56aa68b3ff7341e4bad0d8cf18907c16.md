### Title
Webhook signature verification is scoped to `repository.owner.login`, while the acted-upon repository is selected from `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which organization's* `webhook_secret` to use for HMAC validation based on `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`). Every webhook `Handler` subclass, however, resolves the repository whose `Stack`s get mutated using a *different* field of the same JSON body: `payload.dig('repository', 'full_name')` (`app/models/shipit/webhooks/handlers/handler.rb`). Nothing forces `full_name`'s owner segment to match `owner.login`. In a multi-organization Shipit deployment (`config/secrets.*.yml` supports multiple `github:` orgs, each with its own `webhook_secret`, as shown in `config/secrets.development.shopify.yml`), whoever legitimately knows Org A's `webhook_secret` can sign an arbitrary payload with that secret while setting `repository.full_name` to point at an Org B repository, causing Shipit to act on Org B's stacks despite the signature only proving knowledge of Org A's secret.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
The secret used to validate the HMAC is chosen dynamically from the *unauthenticated* body itself (`repository.owner.login`), via `Shipit.github(organization:)` → `Shipit.github_app_config(organization)` (`lib/shipit.rb:170-200`), which looks up `secrets.github[organization]`.

Every event handler, however, is built on `Shipit::Webhooks::Handlers::Handler`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```
(`app/models/shipit/webhooks/handlers/handler.rb`). `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb`) uses this `stacks` scope to call `stack.sync_github(expected_head_sha: params.after)` for every matching, non-archived stack on the matching branch.

The equality that should hold but doesn't:
`organization whose webhook_secret validated the signature == organization that owns the repository being mutated`

Because the controller derives the "authenticated organization" from `repository.owner.login` and the handler derives the "repository to mutate" from the independent `repository.full_name` field, an actor who legitimately possesses one org's `webhook_secret` (e.g., the person who configured the GitHub App for Org A, per the setup instructions in `docs/setup.md` — "keep it in clear on the side, you'll need it later") can produce a validly-signed request where:
- `repository.owner.login = "orgA"` (so `verify_signature` selects and validates against Org A's secret), and
- `repository.full_name = "orgB/some-repo"` (so the `push` handler resolves and mutates Org B's `Stack`s).

`Repository.from_github_repo_name` (`app/models/shipit/repository.rb:53-56`) parses `full_name` independently and has no relationship to `repository.owner.login`; there is no cross-check anywhere in `verify_signature` or `Handler` binding the two fields together.

### Impact Explanation
This lets a party who only holds credentials/secrets for their own organization (Org A) reach into another organization's stacks (Org B) hosted on the same shared Shipit instance, forcing `Stack#sync_github` to run with an attacker-chosen `expected_head_sha` for Org B's repository/branch. Depending on stack configuration (e.g., `continuous_deployment: true`), this cross-tenant sync can drive Org B's `Stack` to resynchronize/deploy an attacker-selected (but pre-existing, real) commit SHA, effectively causing cross-repository/cross-organization state changes and potentially an unauthorized deploy — without ever possessing Org B's webhook secret, GitHub App credentials, or repository access. This matches the High-severity class "escalation... unauthenticated read/write of stack state... unauthorized deploy" from the rules, via a credential/organization-scoping confusion analogous to the `rejectRequest()` binding break (the entity authorized for one scope acting on a different scope's resource).

### Likelihood Explanation
Requires only that Shipit is deployed in the documented multi-organization mode (explicitly supported and documented — `config/secrets.development.shopify.yml`, `Shipit.github_organizations`, `TOP_LEVEL_GH_KEYS`) and that the attacker legitimately administers a GitHub App/webhook for at least one of the configured organizations (a realistic scenario for shared/SaaS-style Shipit deployments serving multiple GitHub orgs). No GitHub-side forgery is needed at all — the attacker POSTs directly to the `/webhooks` endpoint with a self-computed HMAC using their own known secret, so this doesn't depend on intercepting GitHub's traffic.

### Recommendation
Bind the two lookups together: after verifying the signature, re-derive `repository_name` from the same payload and confirm that `Repository.from_github_repo_name(repository_name)`'s `owner` matches (or is provisioned under) the very organization (`repository_owner`) whose secret validated the signature — reject the webhook if they diverge. Alternatively, look up the `Repository`/`Stack` first, derive its authoritative owning organization from the Shipit-side `Repository` record (not from attacker-supplied payload fields), and use that to select the `webhook_secret`, rather than trusting `repository.owner.login` from the untrusted body to select the verification key.

### Proof of Concept
1. Deploy Shipit configured with two organizations, e.g. `orgA` (secret `S_A`) and `orgB` (secret `S_B`), each with existing `Repository`/`Stack` records (`orgA/repo-a` and `orgB/repo-b`), `orgB/repo-b` with `continuous_deployment: true`.
2. As an actor who only knows `S_A` (e.g. the person who set up `orgA`'s GitHub App per `docs/setup.md`), build a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<existing commit sha on orgB/repo-b>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgb/repo-b"
  }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac_sha1(S_A, raw_body)>` and POST to `/webhooks` with header `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"orgA"`, fetches `Shipit.github(organization: "orgA")`, and validates the signature successfully using `S_A`.
5. `PushHandler#process` calls `stacks` → `Handler#repository_name` → `payload.dig('repository','full_name')` = `"orgb/repo-b"`, resolving `orgB`'s `Repository`/`Stack`, and invokes `stack.sync_github(expected_head_sha: ...)` — mutating `orgB`'s stack despite the request only being authenticated against `orgA`'s secret. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
