### Title
Webhook signature is validated against the organization named in `repository.owner.login`, but handlers act on the unrelated `repository.full_name` field, letting an attacker authenticated as one GitHub org write to a Stack belonging to another org - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App secret to use for HMAC verification based on `repository.owner.login`, an attacker-controlled field inside the very payload being verified. [1](#0-0)  Once the signature passes, the actual event handlers never re-check that field - they instead resolve the target `Repository`/`Stack` using `repository.full_name`, a sibling JSON field that is not covered by the org-selection logic and not cross-validated against `owner.login`. [2](#0-1)  Because Shipit supports hosting multiple independent GitHub App installations (multiple orgs, each with its own `webhook_secret`), an attacker who legitimately controls one configured org's GitHub App can forge a webhook whose `owner.login` matches their own org (so it authenticates with their own known secret) while `full_name` points at a repository belonging to a different, unrelated org configured on the same Shipit instance.

### Finding Description
The binding that should hold is: **organization that authenticated == repository that is written**. Instead:

1. `verify_signature` derives `repository_owner` from the untrusted body (`params.dig('repository', 'owner', 'login')` or the fallback `organization.login`) and uses it purely to select which per-org secret to HMAC-verify against: `Shipit.github(organization: repository_owner)`. [1](#0-0) [3](#0-2) 
2. The signature check (`verify_webhook_signature`) is a standard HMAC-SHA1 over the entire raw body using that selected secret - it proves the request was signed by *some* org's app installation, but does not bind that org identity to any specific field inside the payload beyond the fact that whoever crafted the payload also knew that secret. [4](#0-3) 
3. `Shipit.github` selecting per-org apps and secrets is a documented, supported multi-org configuration. [5](#0-4) [6](#0-5) 
4. Every default handler (`Handler#stacks`, and pull-request handlers) resolves the target repository using `payload.dig('repository', 'full_name')` - a separate JSON key from `owner.login` used above, never re-validated against it - via `Repository.from_github_repo_name`. [2](#0-1) [7](#0-6) 
5. `PushHandler`, using this resolution, calls `stack.sync_github(expected_head_sha:)` on whatever stacks match, and pull-request handlers archive/unarchive review stacks, update labels, and mutate `PullRequest` records for the resolved repository. [8](#0-7) 

Because JSON objects allow arbitrary independent key values, `repository.owner.login` (used only for secret selection) and `repository.full_name` (used only for target resolution) can be set to describe two entirely different repositories in a single, validly-signed payload. Signature verification therefore proves nothing about which repository is actually being acted upon.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" boundary explicitly called out as in-scope. Any tenant/org owner who legitimately runs their own GitHub App installation on a shared Shipit instance (a documented, supported configuration) can:
- Trigger `GithubSyncJob`/`sync_github` on another org's stack via a forged `push` payload.
- Archive/unarchive another org's review stacks, or mutate their `PullRequest` records, via forged `pull_request` webhook payloads, using only their own org's webhook secret.

This is a cross-repository/cross-tenant write achieved without any credential belonging to the victim organization - matching the "cross-repository writes" Critical impact category, since state belonging to a repository/org the attacker was never authorized against can be mutated.

### Likelihood Explanation
Exploitability requires:
- The Shipit instance to be configured with more than one GitHub organization/App (the documented "Using Multiple GitHub Applications" setup). [5](#0-4) 
- The attacker to control (or be an admin of) at least one of those configured GitHub App installations - which is a normal, low-privilege tenant capability in a shared/multi-org Shipit deployment, not an out-of-scope "already privileged" condition against the *victim* org.

Given multi-org support is a first-class, advertised feature, this is a realistic deployment shape, making the likelihood moderate-to-high wherever that feature is used.

### Recommendation
Bind the two fields together: after selecting the verifying organization via `repository.owner.login` (or `organization.login`), re-verify inside `verify_signature`/`create` that `repository.full_name` actually belongs to that same owner (e.g., `full_name.split('/').first.casecmp?(repository_owner)`) before dispatching to handlers, and reject the webhook (422) if they disagree. More robustly, resolve the target `Repository`/`Stack` using the authenticated organization rather than trusting `full_name` outright.

### Proof of Concept
1. Shipit is configured with two GitHub orgs, `attacker-org` and `victim-org`, each with its own `webhook_secret` (per `docs/setup.md`'s multi-app configuration).
2. Attacker knows `attacker-org`'s webhook secret (they administer that GitHub App installation) and crafts a `push` event payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s webhook secret over this exact body and sends it to `/github/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` (from `owner.login`), verifies the HMAC successfully against `attacker-org`'s secret, and lets the request through. [1](#0-0) 
5. `PushHandler` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` (from `full_name`) and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on the victim org's stack - despite the request never being signed by anything belonging to `victim-org`. [2](#0-1) [8](#0-7)

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-63)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L181-209)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L48-54)
```ruby
          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
