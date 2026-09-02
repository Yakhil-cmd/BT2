### Title
Webhook signature verification is keyed on an attacker-controlled organization field that is independent of the repository actually acted upon - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary

### Finding Description
`WebhooksController#verify_signature` decides *which* GitHub App / webhook secret to validate the incoming request against using `repository_owner`, which is read directly out of the untrusted, attacker-supplied JSON body: [1](#0-0) [2](#0-1) 

That org name is then used to look up the corresponding `GitHubApp` instance and its `webhook_secret`: [3](#0-2) 

Crucially, `GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever the selected org's `webhook_secret` is blank: [4](#0-3) 

The webhook secret is explicitly documented as **optional** per organization, and multi-organization configuration (`secrets.github` keyed by org name) is a supported, documented setup: [5](#0-4) [6](#0-5) 

However, after the (possibly-bypassed) signature check passes, the actual event handlers resolve the `Repository`/`Stack` to act on using a *different* field of the same attacker-controlled JSON body: `repository.full_name`, not `repository.owner.login`: [7](#0-6) 

Since `create` re-parses `request.raw_post` and dispatches to handlers using the full JSON payload: [8](#0-7) 

there is no code path enforcing that `repository.owner.login` (the field the signature/app-selection decision is bound to) equals the owner segment of `repository.full_name` (the field that determines which real repository/Stack is mutated). These are two independent JSON keys fully controlled by the request body of an unauthenticated POST to `/webhooks`.

This is the same class of bug as the reported `ecrecover` issue: a verification step is bound to one value (`s` in the report; here, `repository.owner.login`/`organization.login`) while a different, attacker-controllable value is the one actually consumed downstream (the recovered signer's effective identity in the report; here, `repository.full_name` used to select the Stack that gets mutated).

### Impact Explanation
If a Shipit deployment is configured with more than one GitHub organization (a documented, supported configuration) and at least one of those organizations has no `webhook_secret` set (also explicitly documented as optional), an unauthenticated attacker can:

1. POST a forged JSON body to `/webhooks` with `repository.owner.login` (or `organization.login`) set to the unprotected/no-secret organization — causing `verify_webhook_signature` to trivially return `true`.
2. Set `repository.full_name` in the same body to `victim-org/victim-repo`, i.e. any repository Shipit actually tracks (belonging to a different, protected organization).
3. Have the request routed to real handlers (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, membership handlers, etc.), which resolve the target `Stack`/`Repository` purely from `repository.full_name`:
   - `PushHandler` will enqueue `stack.sync_github(expected_head_sha: params.after)` for the victim stack with an attacker-chosen `after` SHA [9](#0-8) .
   - `StatusHandler` will create a forged commit status (`state`, `context`, `description`) against an arbitrary victim commit `sha` [10](#0-9) , which factors into CI/deployability decisions used elsewhere in the app.

This lets an unprivileged, unauthenticated network attacker forge GitHub-originated events for repositories they do not control and were never signed by the legitimate organization's GitHub App, meeting the "unauthorized deploy"/authentication-bypass class of impact.

### Likelihood Explanation
Exploitability is conditioned on the deployment operator's configuration: it requires (a) a multi-organization `secrets.github` setup, and (b) at least one configured organization lacking a `webhook_secret`. Both are explicitly supported/documented as valid, non-privileged configurations rather than misuse of the engine, so this is a plausible real-world deployment shape, not a hypothetical one requiring the host app to deviate from documented usage.

### Recommendation
Bind the signature verification decision to the same repository identity that handlers act on, and stop treating a missing `webhook_secret` as an implicit "always trust" for arbitrary events: 
- Compare `repository.owner.login`/`organization.login` against the owner segment of `repository.full_name` and reject on mismatch.
- Consider requiring a non-blank `webhook_secret` for every configured organization instead of allowing silent bypass, or fail closed rather than returning `true` in `GitHubApp#verify_webhook_signature` when `webhook_secret` is blank in a multi-org configuration.

### Proof of Concept
Given a Shipit instance configured with two orgs, `attacker-org` (no `webhook_secret`) and `victim-org` (tracked stack `victim-org/victim-repo`):

```
POST /webhooks HTTP/1.1
X-Github-Event: push
Content-Type: application/json

{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```

`verify_signature` selects `Shipit.github(organization: "attacker-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` without checking any HMAC. `PushHandler#process` then resolves the stack via `payload.dig('repository', 'full_name')` == `"victim-org/victim-repo"` and enqueues a sync/deploy-relevant job against the real victim stack, despite the request never being signed by `victim-org`'s GitHub App.

**Note:** I was not able to fully trace how `check_suite`/merge-request handlers consume `full_name` for merge/deploy authorization decisions (only `status_handler.rb` and `push_handler.rb` were inspected in depth) due to remaining tool budget; a Devin session with full repo access would be needed to enumerate every handler's blast radius precisely.

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

**File:** lib/shipit.rb (L170-181)
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

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
