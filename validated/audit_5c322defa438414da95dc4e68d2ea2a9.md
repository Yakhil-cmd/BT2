### Title
Webhook signature verified against `repository.owner.login`, but write target selected by unbound `repository.full_name` — cross-organization forged webhooks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-tenant deployments, `Shipit.github(organization:)` selects a per-organization `webhook_secret` from `secrets.github[org]`. `WebhooksController#verify_signature` picks the secret to check using `repository_owner`, taken from the same untrusted payload it's about to verify. All downstream handlers then act on `repository.full_name`/`repository.name`, a *different, independently attacker-controlled* payload field. Since HMAC only proves "some org's registered secret signed this exact body," and the attacker fully controls the body content before signing it with their own org's secret, they can forge a webhook that authenticates as their own (legitimate, low-privilege) organization while writing to a stack that belongs to a different organization/repository entirely.

### Finding Description
`verify_signature` derives the signing organization from the payload itself and uses it purely to pick which stored secret to check against: [1](#0-0) [2](#0-1) 

The engine supports one `webhook_secret` per organization, resolved by `Shipit.github(organization:)` → `github_app_config(organization)`: [3](#0-2) 

Once the signature check passes, every handler resolves the actual target repository/stack from a *different* payload field — `repository.full_name` — via `Repository.from_github_repo_name`, with no re-check that this repository's owner matches the organization whose secret validated the request: [4](#0-3) [5](#0-4) [6](#0-5) 

Because the entire request body (including both `repository.owner.login` and `repository.full_name`) is chosen and signed by the attacker with their own organization's secret, this is not a MAC-integrity break — it's a confused-deputy binding failure: the value used to *authenticate* the request (`repository.owner.login`, mapped to a webhook secret) is never required to equal the value used to *select the write target* (`repository.full_name`). An org admin who legitimately owns/configures Org A's GitHub App (and therefore knows Org A's `webhook_secret`) can set `repository.owner.login: "orgA"` (so `verify_signature` loads and validates against Org A's secret) while setting `repository.full_name: "orgB/victim-repo"` (so the handler acts on Org B's stack).

This lets that attacker drive `PushHandler` to call `stack.sync_github(expected_head_sha: ...)` on Org B's stacks (forcing a specific "synced" HEAD SHA on a repository they don't own), or drive the `pull_request`/`status`/`check_suite`/`membership` handlers against Org B's repositories and teams — all cross-tenant, using only their own tenant's credentials.

### Impact Explanation
This crosses the "cross-repository writes" boundary explicitly called out as Critical impact: an attacker authenticated only as Org A can manipulate deploy-relevant state (synced SHA, PR/label-driven review-stack lifecycle, CI status records, team/user membership) belonging to Org B's stacks, which downstream can influence what gets deployed/rolled back for a repository the attacker has no legitimate access to.

### Likelihood Explanation
Requires the Shipit instance to be configured for multiple organizations (the standard multi-tenant `secrets.github` schema supported by `github_app_config`), and requires the attacker to control (be an admin of) at least one of the onboarded organizations' GitHub App/webhook configuration — a materially lower bar than requiring a Shipit session, API token, or GitHub write access to the *target* repository. Likelihood is Medium: it only applies to multi-org deployments, but for those it is directly and repeatably exploitable by any onboarded-but-unrelated tenant.

### Recommendation
After `verify_signature` selects an organization and validates the HMAC, re-derive `repository_owner`/organization strictly from that same resolved value, and reject (or scope) any handler processing where `payload.dig('repository', 'owner', 'login')` (or `full_name`'s owner segment) does not match the organization whose secret validated the signature. Alternatively, bind repository lookups to `(organization, full_name)` pairs rather than trusting `full_name` alone across tenant boundaries.

### Proof of Concept
1. Shipit configured with two organizations in `secrets.github`: `orga` (attacker-administered) and `orgb` (victim), each with distinct `webhook_secret`s, per `github_app_config`.
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<arbitrary_sha_attacker_wants_synced>",
  "repository": { "owner": { "login": "orga" }, "full_name": "orgb/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(orga_webhook_secret, body)` — they legitimately know `orga`'s secret because they administer that org's GitHub App.
4. POST to `/webhooks`. `verify_signature` resolves `repository_owner => "orga"`, calls `Shipit.github(organization: "orga")`, and the HMAC check succeeds.
5. `PushHandler#process` uses `payload.dig('repository', 'full_name') => "orgb/victim-repo"` to look up `Repository.from_github_repo_name` and calls `stack.sync_github(expected_head_sha: "<arbitrary_sha>")` on Org B's stack, with no verification that `orgb` matches the authenticating organization `orga`.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
