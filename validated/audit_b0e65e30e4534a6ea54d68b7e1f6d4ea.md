### Title
Webhook authentication is bound to `repository.owner.login`/`organization.login` while the acted-upon repository is selected from an independent `repository.full_name` field, letting an org configured without a `webhook_secret` be used to spoof events for any other tracked repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which `webhook_secret`) is used to validate an incoming webhook based on `repository.owner.login` (or `organization.login`). The handlers that actually process the payload (`Shipit::Webhooks::Handlers::Handler#repository_name`, used by e.g. `PushHandler`) resolve the target `Repository`/`Stack` from a *different* field of the same untrusted JSON body: `repository.full_name`. Because `GitHubApp#verify_webhook_signature` unconditionally returns `true` when no `webhook_secret` is configured for the selected organization, an attacker who knows of any configured GitHub organization lacking a secret can send a completely unsigned/unauthenticated request whose `owner.login` matches that org (to sidestep the check) while its `repository.full_name` names any other repository tracked by Shipit - causing that repository's stacks to process the forged event.

### Finding Description
The verification and the action operate on two independent fields of the same unauthenticated payload:

- Authentication field: `repository_owner` derived in `app/controllers/shipit/webhooks_controller.rb`: [1](#0-0) 
This selects the `GitHubApp` instance via `Shipit.github(organization: repository_owner)`, which loads that org's config, including its `webhook_secret`: [2](#0-1) 

- The signature check itself is a no-op when the resolved org has no secret configured: [3](#0-2) 
`return true unless webhook_secret` means any payload passes verification for that organization regardless of the `X-Hub-Signature` header content.

- Action/target field: the handler layer resolves the repository to operate on from a *different* JSON key, `repository.full_name`, not `repository.owner.login`: [4](#0-3) 
This is used by handlers such as `PushHandler`, which calls `stack.sync_github(expected_head_sha: params.after)` for every non-archived stack on the matched branch: [5](#0-4) 

Multi-organization configuration, with an optional/blank `webhook_secret` per organization, is a first-class, documented feature of the engine: [6](#0-5) 
The example config templates explicitly show `webhook_secret: # nil` as an acceptable per-org value: [7](#0-6) 

**Equality broken:** `organization authenticated` (`repository.owner.login`, used to pick the `GitHubApp`/secret) ≠ `repository that is written` (`repository.full_name`, used to resolve the `Repository`/`Stack` acted upon). Because these are independent keys of the same unauthenticated JSON body, and verification degenerates to `true` whenever the org key resolves to a secret-less `GitHubApp`, the attacker can freely choose the second field's value.

### Impact Explanation
Once an unauthenticated attacker identifies (or guesses) any configured GitHub organization in the Shipit instance that has no `webhook_secret` set (a state the engine itself documents and permits per-organization), they can POST an arbitrary, unsigned `push` (or other handled event, e.g. `status`, `check_suite`, `membership`) payload with:
- `repository.owner.login` = the secret-less organization (to make `verify_webhook_signature` return `true` unconditionally),
- `repository.full_name` = the full name of any other repository actually tracked by Shipit (potentially belonging to an organization that *does* have a properly configured secret).

This causes Shipit to run the corresponding handler against stacks of a repository the attacker has no relationship to, e.g. `PushHandler` invoking `stack.sync_github(expected_head_sha: ...)` for arbitrary attacker-chosen branches/SHAs, or the `status`/`check_suite`/`membership` handlers mutating commit/team state, without ever presenting a valid GitHub-issued signature for the targeted repository's app. Depending on how CI/CD is configured on those stacks (e.g. auto-deploy on green CI), this can be leveraged toward triggering unwanted syncs/deploys or CI/CD state changes for repositories that are otherwise correctly secured - an unauthorized action performed on a repository/stack the attacker was never authenticated against.

### Likelihood Explanation
Exploitability requires: (1) the target Shipit instance to configure multiple GitHub organizations (documented and supported), and (2) at least one of those organizations to have a blank `webhook_secret` (also documented and permitted by the config schema/templates). This is a realistic, engine-endorsed configuration state rather than a deviation from documented mounting/setup. No credentials, tokens, or session are required by the attacker - only knowledge of the org name lacking a secret and the target repository's `owner/name`, both of which are typically public GitHub information.

### Recommendation
Bind the field used to select the verifying `GitHubApp`/secret to the same field used to resolve the acted-upon repository. Concretely:
- In `WebhooksController#verify_signature`, and in `Shipit::Webhooks::Handlers::Handler#repository_name`, derive the organization/owner and the repository full name from the *same* JSON path (e.g. always from `repository.full_name`, splitting it, rather than `repository.owner.login` in one place and `repository.full_name` in another).
- Do not allow `verify_webhook_signature` to silently pass (`return true unless webhook_secret`) when the payload's implied repository does not belong to the exact organization whose secret was checked; require an explicit, non-bypassable secret for every organization that has repositories tracked in Shipit, or reject events when the resolved organization for verification differs from the resolved organization for the acted-upon repository.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `OrgNoSecret` (no `webhook_secret`) and `OrgVictim` (has a `webhook_secret` and a tracked repository `OrgVictim/app` with a Shipit stack).
2. As an unauthenticated attacker, send:
```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything
Body:
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgNoSecret" },
    "full_name": "OrgVictim/app"
  }
}
```
3. `WebhooksController#verify_signature` resolves `repository_owner` = `"OrgNoSecret"`, loads that org's `GitHubApp` (no `webhook_secret`), and `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb` line 77), regardless of the bogus `X-Hub-Signature`.
4. `PushHandler` (via `Handler#repository_name`) resolves `repository.full_name` = `"OrgVictim/app"`, looks up the real `Repository`/`Stack` for `OrgVictim/app`, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` - fully bypassing the intended per-repository webhook authentication.

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
