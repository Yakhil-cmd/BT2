### Title
Webhook signature is verified against the GitHub App selected by `repository.owner.login`, while stack matching (and therefore the write action) is performed against a different, unauthenticated field, `repository.full_name` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
Shipit supports multi-tenant GitHub App configuration, where each organization has its own webhook secret. `WebhooksController#verify_signature` selects *which* organization's secret to verify the HMAC against by reading `repository.owner.login` out of the (still-unverified) JSON body, then validates the signature over the entire raw body using that organization's secret. Once verification passes, the same raw body is dispatched to event handlers, which resolve the repository/stack to act on using a *different* field of the same payload: `repository.full_name` (`app/models/shipit/webhooks/handlers/handler.rb#repository_name`, `Repository.from_github_repo_name`). Because the field used to pick the verifying key (`owner.login`) is never required to match the field used to select the target repository (`full_name`), an attacker who legitimately owns/administers *any* one organization configured on the same Shipit instance can forge a webhook body that authenticates as their own organization but drives stack lookup toward another organization's repository/stack.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` computes: [1](#0-0) 

`repository_owner` is derived purely from JSON in the (unauthenticated at that point) POST body: [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up a per-organization webhook secret from `secrets.github`, via `github_app_config`: [3](#0-2) 

and `verify_webhook_signature` checks the `X-Hub-Signature` HMAC against the *whole raw body* using that organization's secret: [4](#0-3) 

If the HMAC matches, `create` dispatches the parsed body to the relevant handler: [5](#0-4) 

Handlers (e.g. `PushHandler`) resolve the affected stacks not by `owner.login`, but by a completely separate field, `repository.full_name`: [6](#0-5) [7](#0-6) 

`Repository.from_github_repo_name` splits `full_name` on `/` and looks up any repository by `owner/name`, with no cross-check against the `owner.login`/secret used earlier for verification: [8](#0-7) 

This is directly analogous to the re-nft finding: SeaPort's `_executionInvariantChecks()` verified recipients only for entries present in `totalExecutions`, but storage updates (`STORE`) trusted unrelated fields of the same order regardless of whether those fields were actually checked. Here, the HMAC signature "covers" the byte string of the whole payload, but the *decision of which key to check it against* is taken from a payload field (`owner.login`) that is logically decoupled from the field the write path trusts (`full_name`). Signing with a legitimately-owned organization's secret authenticates "this request came from an app installation the attacker administers," but the code then treats the same signed body as authoritative for an entirely different repository namespace, breaking the intended binding: `organization whose secret authenticated the request == organization whose repository is written by the handler`.

### Impact Explanation
On a multi-org Shipit deployment (the schema explicitly supported by `github_organizations`/`github_app_config`), an attacker who is an admin of *any one* configured GitHub organization/App can craft and sign (with their own legitimate webhook secret) a payload whose `repository.full_name` names a *victim* organization's stack. Handlers such as `PushHandler` will then enqueue `GithubSyncJob` for that victim stack, `check_suite`/`status` handlers will create commit statuses, and `pull_request`/`membership` handlers will mutate `Team`/`Membership`/`PullRequest`/`MergeRequest` records tied to that victim stack, entirely bypassing the intended per-organization trust boundary. Depending on which stack is targeted and its auto-deploy configuration, this can result in an unauthorized deploy/rollback trigger (`sync_github` → CI/merge status changes influencing deploy eligibility) on a repository/organization the attacker does not own or have credentials for — an authorization-boundary break matching "escalation into `Shipit.github_teams` authorization" / "unauthorized deploy" territory of the disclosure program's High/Critical categories, without requiring any Shipit session, API token, or the victim's webhook secret.

### Likelihood Explanation
Requires the deployment to be configured with more than one GitHub organization (multi-tenant `secrets.github` schema), and requires the attacker to control (be an admin of) at least one of the configured organizations/apps — a comparatively low bar relative to compromising the victim organization's own webhook secret, `GITHUB_TOKEN`, or Shipit account. On single-organization deployments (the more common/legacy schema, `github_default_organization.nil?`) this specific cross-organization vector collapses back to same-secret verification, but the underlying design flaw (verification key selection and write-target resolution reading unrelated, independently-forgeable fields of the same unauthenticated JSON body) remains present in the code path.

### Recommendation
Bind the verified identity to the acted-upon resource: after `verify_webhook_signature` succeeds for `repository_owner`, require that `repository.full_name`'s owner segment equals `repository_owner` (or, more robustly, verify the signature using the config keyed by the resolved `Repository`'s actual `owner` looked up from `full_name`, rather than trusting `owner.login` supplied in the same unauthenticated body). Reject the webhook if the two disagree.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`, e.g. `attacker-org` and `victim-org`, each with its own `webhook_secret` (multi-tenant schema per `lib/shipit.rb#github_app_config`).
2. Attacker administers a GitHub App installed on `attacker-org` and knows `attacker-org`'s `webhook_secret` (legitimately, as the org admin who created the App).
3. Attacker crafts a JSON body:
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
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org webhook_secret, raw_body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` computes `repository_owner == "attacker-org"`, fetches `attacker-org`'s `GitHubApp`, and the HMAC check in `verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`) succeeds because the attacker signed with their own valid secret.
6. `create` dispatches to `Webhooks::Handlers::PushHandler`, whose `stacks` method (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueues `GithubSyncJob` for the victim's stack — despite the request never being authenticated with `victim-org`'s webhook secret.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
