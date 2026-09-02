### Title
Webhook signature verification is keyed on `repository.owner.login` while event handlers act on the unrelated `repository.full_name` field, letting an attacker forge events for any tracked stack - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to verify the `X-Hub-Signature` against using `repository_owner`, computed as `params.dig('repository', 'owner', 'login')` (with a fallback to `params.dig('organization', 'login')`) [1](#0-0) . Once that check passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` hands the *entire raw, attacker-controlled JSON body* to the handler, which independently derives the target repository from a **different** field, `payload.dig('repository', 'full_name')`, via `Handler#repository_name` [2](#0-1) . These two fields are never cross-checked against each other.

### Finding Description
This is the same class of bug as the Knox oracle finding: two values that should be bound together (the identity used to authorize an action vs. the identity the action is actually performed on) are read from independent, unauthenticated inputs and never reconciled.

The equality that should hold but doesn't:
`organization used to select webhook_secret for signature verification == organization owning the repository that the handler mutates`

In multi-org Shipit deployments (`Shipit.github_organizations`, config keyed by org, see `lib/shipit.rb#github_app_config`) an operator can legitimately configure one organization with a blank `webhook_secret` (the docs' own example config ships `webhook_secret: # nil` for `someothergithuborg`) [3](#0-2) . `GitHubApp#verify_webhook_signature` explicitly no-ops when the secret is blank:

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [4](#0-3) 

Because `verify_signature` selects the `GitHubApp` instance via `Shipit.github(organization: repository_owner)`, and `repository_owner` is taken from `repository.owner.login`/`organization.login` in the *unverified* body, an attacker can pick any configured org that has a blank secret to make `verify_webhook_signature` return `true` unconditionally, i.e. with no valid HMAC at all [5](#0-4) , [6](#0-5) .

The request then proceeds to `create`, which re-parses the *same raw body* and dispatches it to handlers keyed only by `X-Github-Event` [7](#0-6) . Handlers such as `PushHandler` and `StatusHandler` locate the target `Stack`/`Commit` purely from `payload.dig('repository', 'full_name')` via `Handler#stacks`/`repository_name` [2](#0-1)  — a field that was never checked during signature verification and can be set to reference a completely different, real, already-tracked repository/stack belonging to another organization.

Concretely, an attacker (no credentials, no GitHub webhook secret, no session) can send:
```json
{
  "organization": { "login": "someothergithuborg" },  // configured org with blank webhook_secret
  "repository": {
    "owner": { "login": "someothergithuborg" },        // used only for signature-org lookup
    "full_name": "victim-org/victim-repo"               // used by the handler to find the real Stack/Commit
  },
  "sha": "<victim commit sha>",
  "state": "success"
}
```
with header `X-Github-Event: status` and *no valid `X-Hub-Signature`* (or an arbitrary one) - the request passes `verify_signature` (secret is blank for `someothergithuborg`) and `StatusHandler#process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, inserting a forged `success` status onto the victim commit [8](#0-7) .

### Impact Explanation
`Commit#deployable?` gates deploys on the commit's aggregated `status` being `success?` (derived from `statuses`) unless the stack ignores CI (`stack.ignore_ci?`) [9](#0-8) . `create_status_from_github!` writes directly into `statuses` and its `add_status` path re-evaluates deployability and can even trigger `stack.schedule_merges` and continuous-delivery scheduling once the new status is `success` [10](#0-9) . This lets an unprivileged attacker forge a passing CI status for a commit on a stack they have no relationship to, bypassing the real CI/status gate that blocks deploys/merges — an unauthorized-deploy/merge primitive, matching the "Critical: unauthorized deploy, rollback or merge" bucket. The same organization/repository binding gap also lets the attacker inject arbitrary `push` events (`GithubSyncJob`) or `check_suite`/`pull_request` events against the victim stack.

### Likelihood Explanation
This requires: (1) the deployment to use the multi-org `github:` config schema, and (2) at least one configured organization to have a blank/absent `webhook_secret` (explicitly documented and shipped as an example in this repo's own config templates). Given that the docs describe `webhook_secret` as *optional* and ship examples with it blank [11](#0-10) , this is a realistic misconfiguration, not a contrived edge case — directly analogous to the "oracle may legitimately report degenerate values" premise of the source finding. No credentials, sessions, or tokens are needed by the attacker; the request is a single unauthenticated HTTP POST.

### Recommendation
Bind the two identities together instead of trusting them independently: derive the organization used for signature verification from the *same* field the handlers use to resolve the target repository (e.g. parse the owner out of `repository.full_name`, or verify that `repository.owner.login` equals the owner segment of `repository.full_name`) before selecting the `GitHubApp`/secret. Additionally, treat a blank/missing `webhook_secret` for an organization as "reject all webhooks for this org" rather than "accept unsigned," or require every configured organization to have a non-blank secret at boot time.

### Proof of Concept
1. Configure Shipit with two organizations: `victim-org` (real secret, tracks `victim-org/victim-repo` as a `Stack`) and `empty-secret-org` (`webhook_secret: nil`, as shown in the shipped example config) [3](#0-2) .
2. POST to `/webhooks` with header `X-Github-Event: status`, no valid `X-Hub-Signature`, and body:
   ```json
   {"organization":{"login":"empty-secret-org"},
    "repository":{"owner":{"login":"empty-secret-org"},"full_name":"victim-org/victim-repo"},
    "sha":"<real commit sha on victim-org/victim-repo>","state":"success"}
   ```
3. `verify_signature` resolves `Shipit.github(organization: "empty-secret-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (missing/invalid) signature [4](#0-3) .
4. `StatusHandler` resolves the commit via `Commit.where(sha: params.sha)` on `victim-org/victim-repo` and records a forged `success` status [8](#0-7) , potentially satisfying `Commit#deployable?` and enabling deploy/merge on a stack the attacker never had signing access to.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```
