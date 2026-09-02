### Title
Webhook signature verification selects the GitHub App/secret using an attacker-controlled `repository.owner.login` field that is never bound to the `repository.full_name` actually acted upon by event handlers - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which `GitHubApp` (and therefore which `webhook_secret`) to validate an inbound webhook against by reading `repository.owner.login` (or `organization.login`) straight out of the untrusted, unauthenticated JSON body [1](#0-0) [2](#0-1) . Once the HMAC check passes, every event handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, the `pull_request` handlers, etc.) resolves the target `Stack`/`Repository` using a completely different, independent field: `repository.full_name` [3](#0-2) . Nothing ties these two fields together, so an attacker who legitimately knows the `webhook_secret` for one configured GitHub organization (e.g. `OrgOne`, the multi-org config style documented and fixtured in this engine [4](#0-3) [5](#0-4) ) can forge signed webhook events whose `repository.full_name` targets a Stack that belongs to a completely different organization (`OrgTwo`) configured on the same Shipit instance.

### Finding Description
`Shipit.github(organization:)` resolves a distinct `GitHubApp` instance (with its own `webhook_secret`) per configured organization [6](#0-5) . `verify_signature` uses `repository_owner`, derived only from `repository.owner.login`/`organization.login` in the raw JSON body, to select this app before the signature is even checked [7](#0-6) .

The equality the engine implicitly (and incorrectly) assumes is:
`repository.owner.login` (used to select the verifying secret) == `repository.full_name`'s owner segment (used by every `Handler` to resolve which `Stack`/`Repository` gets acted upon).

Because the entire payload is attacker-supplied (this is a public unauthenticated endpoint gated only by the HMAC check), nothing enforces that equality. `Handler#stacks`/`#repository_name` reads `payload.dig('repository', 'full_name')` independently of whatever value was used to pick the verifying secret [3](#0-2) , and the same disjoint pattern repeats in `PushHandler` (`stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(...) }`) [8](#0-7)  and in the PR handlers that resolve `Repository.from_github_repo_name(params.repository.full_name)` [9](#0-8) .

### Impact Explanation
An attacker who is merely an admin/owner of any one GitHub organization configured on a shared, multi-org Shipit deployment (a supported and documented configuration) can:
1. Compute a valid `X-Hub-Signature` using the `webhook_secret` for their own org (`OrgOne`), setting `repository.owner.login = "OrgOne"` so `verify_signature` selects and validates against that known secret.
2. Set `repository.full_name = "OrgTwo/victim-repo"` in the same payload, pointing every downstream handler at a `Stack` that belongs to an organization the attacker has no access to.
3. Trigger `PushHandler`, which calls `stack.sync_github(expected_head_sha:)`, enqueuing `GithubSyncJob` for `OrgTwo`'s stack using Shipit's own `OrgTwo` GitHub App credentials—capable of driving continuous-deployment stacks to deploy, or forging `status`/`check_suite` events that influence merge-queue/CI-gating logic for repositories the attacker does not own.

This is a cross-organization authentication bypass that lets an unprivileged (relative to the victim org) attacker cause unauthorized deploys/syncs against another organization's stacks, matching the "cross-repository writes" / "unauthorized deploy" and "authentication bypass" impact classes.

### Likelihood Explanation
Requires only that the Shipit instance be configured with more than one GitHub organization (an officially documented and supported deployment mode) and that the attacker controls (as an org owner/admin) the webhook secret for at least one of those organizations—no privileged Shipit account, `ApiClient` token, or access to the victim org is needed. `/webhooks` is a public, unauthenticated endpoint by design, gated solely by the mis-scoped signature check described above.

### Recommendation
After verifying the HMAC, require that the organization/app used to compute the signature matches the organization segment of `repository.full_name` (or `organization.login`) actually referenced by the payload, and reject the webhook if they diverge. Alternatively, resolve the target `Stack`/`Repository` strictly by the same `repository_owner` value that was used to select/verify the signing secret, rather than trusting a second, independent field from the same untrusted body.

### Proof of Concept
1. Deploy Shipit with two organizations configured, `OrgOne` and `OrgTwo`, each with its own GitHub App/`webhook_secret`, as in `test/dummy/config/secrets_double_github_app.yml` / `docs/setup.md` §"Using Multiple Github Applications".
2. As an attacker who administers `OrgOne` (and thus knows `OrgOne`'s `webhook_secret`), build a `push` payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker chosen sha already on OrgTwo/victim-repo>",
  "repository": { "owner": { "login": "OrgOne" }, "full_name": "OrgTwo/victim-repo" }
}
```
3. Sign the raw body with `HMAC-SHA1(OrgOne_webhook_secret, body)` and send it to `POST /webhooks` with `X-Github-Event: push` and `X-Hub-Signature: sha1=<computed>`.
4. `verify_signature` calls `Shipit.github(organization: "OrgOne")` and successfully verifies the signature [1](#0-0) .
5. `PushHandler#process` resolves stacks via `repository.full_name = "OrgTwo/victim-repo"` and calls `stack.sync_github(expected_head_sha:)` [8](#0-7) , enqueuing a sync/deploy cycle for a stack the attacker has no legitimate access to, using `OrgTwo`'s own GitHub App credentials.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
