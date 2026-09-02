### Title
Webhook signature verified against the organization named in the payload's `repository.owner.login`, but the acted-upon repository is taken from the same payload's `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization Shipit deployments, `WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate a webhook against using a field read out of the **unverified** JSON body (`repository.owner.login`), while the downstream webhook handlers determine **which repository/stack to act on** using a different field from the same unverified body (`repository.full_name`). Nothing binds these two fields together. This breaks the equality `organization that authenticated == organization whose repository is written to`, letting a party who controls one configured organization's webhook secret forge events against any other organization's stacks configured on the same instance.

### Finding Description
`verify_signature` computes the org used for signature verification purely from request JSON, before the signature has been checked: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up the app config (and its `webhook_secret`) purely by this attacker-supplied string: [3](#0-2) 

`verify_webhook_signature` only proves the raw body was HMAC-signed with *that* organization's secret; it says nothing about which repository the body's fields refer to: [4](#0-3) 

Once the signature check passes, `create` dispatches the same raw payload to handlers: [5](#0-4) 

Every handler resolves the target stack from `repository.full_name`, a completely independent field from the one used to pick the verifying secret: [6](#0-5) [7](#0-6) 

Because `owner.login` (used for authentication) and `full_name` (used for authorization/action target) are both attacker-controlled and never cross-checked against each other, a webhook correctly signed with Org A's secret can carry `repository.full_name = "OrgB/some-repo"` and be processed as if it legitimately originated from Org B's GitHub App, for any org configured in `secrets.github` (see the documented multi-org schema): [8](#0-7) [9](#0-8) 

This is the same class of defect as the analog report: a value that gates a computation/authorization decision is taken from the same untrusted input whose integrity that gate is supposed to protect, and the timing/identity of "what was verified" diverges from "what gets acted upon."

### Impact Explanation
An attacker who is an authorized user of Org A's GitHub App installation (i.e., can generate a validly-signed webhook for Org A, which any GitHub org admin can do since GitHub signs deliveries with the app's own webhook secret) can forge webhook events that Shipit will process as belonging to Org B's repository. Depending on handler:
- `StatusHandler` writes attacker-controlled `state`/`description`/`target_url` directly into `Commit#statuses` for Org B's commits, which can be used to satisfy deploy readiness checks and enable an **unauthorized deploy**.
- `MembershipHandler` can create/append/remove `Team`/`Membership` records, escalating into `Shipit.github_teams` authorization for an org the attacker does not control.
- `PushHandler`/pull-request handlers can trigger sync/merge related jobs against Org B's stacks.

This crosses the "organization that authenticated versus the repository that is written" trust boundary and lands in the Critical/High impact categories (cross-repository writes, escalation into `Shipit.github_teams` authorization).

### Likelihood Explanation
Requires the target Shipit instance to be configured with more than one GitHub organization (the documented multi-org `secrets.github` schema) and requires the attacker to control (or have push access to trigger deliveries from) at least one of those configured orgs' GitHub Apps — a normal, unprivileged-relative-to-the-victim-org capability, not requiring any Shipit credentials, session, or API token.

### Recommendation
After signature verification succeeds, re-derive/validate that the organization whose secret matched is the same organization that owns `repository.full_name` (e.g., compare `repository.full_name.split('/').first` case-insensitively against the verified organization key) before dispatching to handlers, and reject (422) on mismatch.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` and `OrgB`, each with distinct `webhook_secret`s, both having stacks tracked (per `test/dummy/config/secrets_double_github_app.yml`).
2. As someone with access to `OrgA`'s webhook secret (e.g., an OrgA admin), craft a JSON body:
   ```json
   {
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" },
     "sha": "<victim commit sha>", "state": "success",
     "target_url": "https://attacker.example", "description": "forged"
   }
   ```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(OrgA_webhook_secret, body)>` and POST to `/github/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `Shipit.github(organization: "OrgA")` from `repository.owner.login`, verifies successfully against OrgA's secret.
5. `StatusHandler` (via `Handler#repository_name` = `repository.full_name` = `"OrgB/victim-repo"`) writes a forged status onto OrgB's commit, despite the request never being authenticated by anything OrgB controls.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-6)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
