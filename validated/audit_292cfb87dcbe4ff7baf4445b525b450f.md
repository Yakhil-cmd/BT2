### Title
Cross-Organization Commit Status Forgery via Webhook Signature/Write-Target Mismatch - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
The webhook signature check authenticates which *organization* sent a payload, but the `status` event handler writes to any `Commit` in the entire database whose SHA matches an attacker-controlled field, with no verification that the commit belongs to a repository owned by the authenticated organization. An admin who legitimately controls one organization's webhook secret can forge a signed `status` payload that writes a fabricated CI status onto a commit belonging to a completely different organization's stack.

### Finding Description
`WebhooksController#verify_signature` selects which secret to use for HMAC verification based on `repository_owner`, itself read straight out of the incoming JSON body: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves a per-organization config (and thus a per-organization `webhook_secret`) from `secrets.github`: [3](#0-2) 

This design assumes multiple organizations, each with its own independent `webhook_secret`, can be onboarded onto a single shared Shipit instance (`docs/setup.md`/`github.oauth.teams` confirm per-org GitHub App config). Because the HMAC is computed over the raw JSON body, an attacker who legitimately knows *their own* organization's `webhook_secret` can freely construct any JSON payload they like and sign it validly — the signature only proves "some org's secret was known," it does not constrain which repository/commit the payload can reference.

The `status` handler then dispatches purely on the SHA value taken from that same attacker-controlled payload, without any scoping to the repository/organization that was authenticated: [4](#0-3) 

Unlike other handlers (e.g. `PushHandler`, which at least scopes via `Repository.from_github_repo_name(repository_name)`), `StatusHandler` does not call `stacks`/`repository_name` at all — it queries `Commit.where(sha: params.sha)` across the whole table, and any commit anywhere in the database matching that SHA gets a new status record created via `commit.create_status_from_github!(params)`, using attacker-supplied `state`, `context`, `target_url`, and `description`.

This breaks the equality: **organization authenticated by the webhook signature == repository/commit actually written to**. The signature only guarantees "Organization A's secret was used," while the actual write target (which commit, therefore which stack/organization) is determined entirely by unauthenticated payload content (`sha`), with no cross-check against the organization that was verified.

### Impact Explanation
Shipit gates deploys on CI status via `ci.require` in `shipit.yml`, refusing to deploy unless required status contexts report `success` for the commit being deployed (per `README.md`). By forging a `status` webhook using Organization A's known secret, but targeting a real commit SHA belonging to Organization B's stack (SHAs are frequently public/observable, e.g. via GitHub's public API or a collaborator on B's repo), an attacker can inject a fabricated `success` status with the exact `context` name Organization B's stack requires. This can satisfy CI gating and enable or unblock a deploy on a stack the attacker has no access to at all — an unauthorized deploy triggered by data forged by an unrelated tenant. This matches the Critical impact category "an unauthorized deploy."

### Likelihood Explanation
Exploitation requires only knowledge of one organization's `webhook_secret` (something a legitimate, low-privilege customer/org-admin already has by design in a multi-tenant Shipit deployment) plus knowledge of a target commit SHA and the required CI context name for another organization's stack — both of which can be public information (e.g., public GitHub repos, or values visible on Shipit's own public-ish status/deploy pages). No GitHub App private key, `GITHUB_TOKEN`, or Shipit session/API token is needed; only an already-provisioned org's webhook secret, which is the intended credential of a much narrower trust boundary (one org) is reused to affect a much broader one (any stack in the database).

### Recommendation
Scope `StatusHandler` (and any other webhook handler that resolves records purely by payload-controlled identifiers) to only the repository asserted by the same organization that was cryptographically verified: derive the target `Repository`/`Stack` from `repository.full_name`/`repository.owner.login` in the payload, and additionally assert that this owner equals the `repository_owner` used to select the verifying `webhook_secret` in `WebhooksController#verify_signature`. Reject the webhook if the two do not match, rather than looking up commits/statuses by SHA alone across the entire table.

### Proof of Concept
1. Attacker is a legitimate administrator of Organization A, configured in Shipit's `secrets.github` with its own `webhook_secret_A` (a supported, documented multi-org config per `lib/shipit.rb#github_app_config`).
2. Attacker observes (via GitHub's public API, or as an outside collaborator) a commit SHA `S` belonging to Organization B's repository, which Shipit already tracks as a `Commit` for one of B's stacks, and learns the CI `context` name required by B's `shipit.yml` (`ci.require`).
3. Attacker crafts a `status` event JSON payload:
```json
{
  "sha": "S",
  "state": "success",
  "context": "<B's required CI context>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgA/anything" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(webhook_secret_A, raw_body)` themselves (they know `webhook_secret_A`), and POSTs it to `/webhooks` with `X-Github-Event: status`.
5. `WebhooksController#verify_signature` resolves `repository_owner = "OrgA"`, fetches `webhook_secret_A`, and the signature verifies successfully [1](#0-0) .
6. `StatusHandler#process` runs `Commit.where(sha: "S")`, finds Organization B's commit, and creates a forged `success` status on it using attacker-controlled `context`/`state` [4](#0-3) , potentially satisfying B's `ci.require` gate and enabling an unauthorized deploy of Organization B's stack.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
