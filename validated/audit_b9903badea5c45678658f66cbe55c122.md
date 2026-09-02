### Title
Webhook signature verification keys off `repository.owner.login`, but event processing acts on the independently-attacker-controlled `repository.full_name`, allowing cross-organization webhook forgery in multi-app deployments - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate the HMAC signature against using `repository_owner`, computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) . Once the signature is accepted, `create` dispatches the *entire* unauthenticated-for-repo-identity payload to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [2](#0-1) . Handlers, however, resolve the target repository/stacks from a *different* JSON field, `payload.dig('repository', 'full_name')` [3](#0-2) . Nothing cross-checks that `repository.full_name` belongs to the same organization as `repository.owner.login`/`organization.login` used for signature-key selection.

### Finding Description
In a multi-organization Shipit deployment (`config.github.<org>` schema, see `Shipit.github_app_config` / `Shipit.github`) [4](#0-3) , each organization has its own GitHub App and its own `webhook_secret`. The bug-class analog to the Rubicon finding is: the engine authenticates a signature against organization X (the value it "verified"), but then performs the privileged write/action against a repository field that is never bound to that same organization (the value it "acts on").

Concretely:
- `verify_signature` picks `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` comes from `repository.owner.login` (falling back to `organization.login`) [5](#0-4) .
- The HMAC covers `request.raw_post` (the whole body), so the signature is only proof that *someone holding org X's `webhook_secret`* produced this exact byte string — it says nothing about which org's repositories the payload's `repository.full_name` field claims to reference.
- `Handler#repository_name` (used by every handler, e.g. `PushHandler`) independently reads `payload.dig('repository', 'full_name')` to resolve `Repository.from_github_repo_name(repository_name)` and thus the `stacks` that get acted on [3](#0-2) [6](#0-5) .
- `Repository.from_github_repo_name` simply splits `owner/name` from that field and looks up the DB record, with no re-check against the org identified during signature verification [7](#0-6) .

Because `repository.owner.login`/`organization.login` (used to pick the verification secret) and `repository.full_name` (used to pick the acted-upon repository/stacks) are two separate, independently-settable JSON fields inside the same request body, an entity that legitimately controls **one** configured organization's GitHub App (and therefore knows that org's `webhook_secret`, which they set themselves when installing/configuring their own app in Shipit) can craft a payload where:
- `repository.owner.login = "attacker-org"` (so `verify_signature` selects attacker-org's `GitHubApp` and the signature — computed by the attacker using their own known `webhook_secret` — validates), while
- `repository.full_name = "victim-org/victim-repo"` (so the handler resolves and acts on a repository/stack belonging to a completely different, unrelated organization).

This breaks the binding: `organization authenticated == organization written`.

### Impact Explanation
If successful, this lets a party who only administers one configured GitHub App organization inject forged, "signature-verified" webhook events (`push`, `pull_request`, `commit_status`, `deployable_status`, `merge_status`, membership, etc.) that are processed as if they came from GitHub for a stack/repository belonging to a different organization in the same Shipit instance. Depending on which handler fires, this can trigger unauthorized `stack.sync_github`, fabricate commit/deployable statuses that gate deploys, or manipulate PR/merge-status-driven state for a repository the attacker does not own — an unauthorized deploy/rollback-adjacent action performed via a forged, "verified" webhook, matching the "authenticated organization vs. repository/ref actually acted on" binding break called out in scope.

### Likelihood Explanation
This is only exploitable in the multi-organization GitHub App configuration schema (`config.github.<org>: {...}` with more than one org configured) [8](#0-7) , and requires the attacker to be a legitimate administrator/owner of at least one of the configured organizations (so they know that org's `webhook_secret`) while targeting a *different* configured organization's repositories — i.e., it requires an existing, narrower trust relationship (control of one org's app) to escalate into acting on another org's stacks. In single-org deployments (`github_default_organization.nil?`), `Shipit.github` ignores the `organization:` argument entirely and always returns the single configured secret [9](#0-8) , so the cross-org confusion described here specifically requires the multi-tenant config.

### Recommendation
After verifying the signature, re-derive the organization actually acted upon from `repository.full_name` (or each handler's resolved repository owner) and reject/short-circuit if it does not match the organization whose `webhook_secret` was used for verification. Concretely, in `WebhooksController#verify_signature`/`create`, compare the owner segment of `params.dig('repository', 'full_name')` against `repository_owner` and `head(422)` on mismatch, rather than trusting the two fields independently.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` and `victim-org`, each with its own GitHub App and `webhook_secret` (multi-org schema as in `test/dummy/config/secrets_double_github_app.yml`).
2. As the legitimate owner of `attacker-org`'s GitHub App, know/control its `webhook_secret`.
3. Craft a `push` event payload:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "deadbeef",
     "repository": {
       "owner": { "login": "attacker-org" },
       "full_name": "victim-org/victim-repo"
     }
   }
   ```
4. Compute `X-Hub-Signature: sha1=<hmac using attacker-org's webhook_secret over the raw body>`.
5. POST to `/github/webhooks` with `X-Github-Event: push`.
6. `verify_signature` resolves `repository_owner = "attacker-org"`, fetches `attacker-org`'s `GitHubApp`, and the HMAC validates successfully [5](#0-4) .
7. `PushHandler#process` resolves `repository_name = "victim-org/victim-repo"` via `Handler#repository_name`, finds `victim-org`'s `Repository`/`stacks`, and calls `stack.sync_github(expected_head_sha: ...)` on a stack the attacker does not administer [3](#0-2) [6](#0-5) .

Note: I was unable to fully verify whether higher-impact handlers (e.g., merge/deploy-triggering ones) perform additional owner/org consistency checks beyond `Handler#repository_name`, since only `PushHandler` and the base `Handler` class were inspected in depth; a full audit of `app/models/shipit/webhooks/handlers/**` would be needed to enumerate every affected event type.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-10)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
```
