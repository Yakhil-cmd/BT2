### Title
Cross-organization webhook forgery via `repository.owner.login`/`repository.full_name` mismatch in multi-tenant webhook signature verification - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In multi-organization Shipit deployments, `WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate an incoming webhook against by reading `repository.owner.login` (or `organization.login`) directly out of the **unverified** raw request body, then verifies the HMAC of the *entire* body against that org's secret. The handlers that subsequently act on the payload (`PushHandler`, `CheckSuiteHandler`, via `Handler#repository_name`) identify the target repository using a **different** field in the same untrusted body: `repository.full_name`. Nothing ties these two fields together, so an attacker who legitimately controls one tenant organization's GitHub App webhook secret (org A) can sign an arbitrary payload with org A's secret while setting `repository.full_name` to a repository belonging to a completely different tenant (org B) configured on the same shared Shipit instance.

### Finding Description
`verify_signature` derives the signing organization purely from attacker-supplied JSON, before any cryptographic check: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization app config (secret, app_id, etc.) using exactly that untrusted value: [3](#0-2) 

Signature verification itself only checks that the HMAC of the raw body matches the secret picked in the previous step — it never checks that the *content* of the body actually belongs to that organization: [4](#0-3) 

Once `head(422)` is skipped (signature valid for whichever secret matched `repository_owner`), `WebhooksController#create` dispatches the same raw JSON to handlers: [5](#0-4) 

Handlers determine the target `Stack`/`Repository` using `repository.full_name`, an independent JSON field from the same body: [6](#0-5) 

`PushHandler` then triggers a GitHub sync on any matching stack using an attacker-controlled `after` (target sha): [7](#0-6) 

`CheckSuiteHandler` similarly refreshes check runs for arbitrary stacks: [8](#0-7) 

**Binding broken (equality that should hold but doesn't):**
`organization_used_to_verify_signature (repository.owner.login) == organization_of_repository.full_name_acted_on_by_handler`

Before the PR/attack: for legitimate GitHub-originated webhooks, `repository.owner.login` and the owner segment of `repository.full_name` are always the same, because GitHub itself constructs both fields from the same repository object.

After the attack: because Shipit signs/verifies the *raw body* against a secret chosen from one field but the handlers consume a second, independently-attacker-controlled field, an attacker who owns org A's webhook secret (docs explicitly describe this as a "somegithuborg"/"someothergithuborg" multi-tenant setup, see `config/secrets.development.shopify.yml` and `docs/setup.md` "Using Multiple Github Applications") can produce a validly-signed body where these two fields diverge, causing org A's credentials to authorize an action against org B's repository/stack. [9](#0-8) [10](#0-9) 

### Impact Explanation
This is a cross-tenant/cross-repository trust-boundary bypass: an entity trusted only for organization A's webhooks can force Shipit to act on organization B's stacks (forcing `GithubSyncJob` with an attacker-chosen `expected_head_sha`, or forcing check-run refreshes) without ever holding org B's webhook secret, GitHub App credentials, or a Shipit session/ApiClient token for org B. This matches the "cross-repository writes" / unauthorized cross-tenant action impact category, since the forged event causes writes (sync jobs, commit/check-run state changes) scoped to a repository the attacker was never authorized to affect.

### Likelihood Explanation
Exploitability requires the attacker to be a legitimate holder of one tenant's webhook secret in a multi-org Shipit deployment (i.e., they administer or have delivery access to org A's GitHub App configured on the shared Shipit instance) — this is a realistic scenario in any Shipit instance handling multiple organizations, as documented in `docs/setup.md`. No access to org B's credentials, session, or ApiClient token is required, which is the essence of the escalation.

### Recommendation
After verifying the HMAC in `verify_signature`, cross-check that the organization used to select the webhook secret matches the owner of every repository referenced by the payload that the corresponding handler will act on (e.g., re-derive `repository.owner.login` and `repository.full_name`'s owner segment and require them to be equal, rejecting the request with 422 otherwise). More robustly, resolve the target `Repository`/`Stack` first, then verify the signature using the secret configured for that repository's *known* owner (from the Shipit database), not from attacker-supplied payload fields.

### Proof of Concept
1. Deploy Shipit in multi-org mode with `OrgA` and `OrgB` both configured (as in `config/secrets.development.shopify.yml`), each with their own `webhook_secret`.
2. Attacker has legitimate delivery access to `OrgA`'s webhook secret (e.g., they administer `OrgA`'s installed GitHub App).
3. Attacker crafts a JSON body:
```json
{
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/target-repo"
  },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>"
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(body, OrgA_webhook_secret)>` and sends it with header `X-Github-Event: push` to `/webhooks`.
5. `WebhooksController#verify_signature` computes `repository_owner = "OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the signature verifies successfully (it was signed with OrgA's secret).
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgB/target-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on a stack belonging to `OrgB`, even though the attacker never held any credential for `OrgB`.

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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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
