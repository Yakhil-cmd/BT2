### Title
Webhook signature verification keys on `repository.owner.login`, but every event handler acts on the unrelated `repository.full_name` — cross-tenant stack impersonation via `WebhooksController` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the inbound HMAC signature against using `repository_owner`, derived from the JSON body itself. Every downstream `Webhooks::Handlers::Handler` subclass, however, resolves the actual `Stack`/`Repository` to mutate using a *different* field of the same untrusted body: `repository.full_name`. Nothing ties these two values together, so the organization whose key "authenticates" the request is not bound to the repository that is actually written to.

### Finding Description
`Shipit::WebhooksController` verifies inbound GitHub webhooks like this: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` looks up a per-organization config block (`secrets.github[org]`), each with its own `webhook_secret`, in a multi-tenant Shipit deployment: [3](#0-2) 

Once the signature check passes, `create` dispatches the *entire raw payload* to the relevant handler: [4](#0-3) 

Every handler (e.g. `PushHandler`, `StatusHandler`, the `PullRequest::*` handlers) resolves which `Repository`/`Stack` to act on from `repository.full_name`, a field that is completely independent of the `repository.owner.login` field used for signature routing: [5](#0-4) [6](#0-5) 

The trust binding that should hold is:
`organization used to select/validate the signing key == owner of the repository whose Stack is mutated`

Because `repository_owner` (bits used for authentication) and `repository.full_name` (bits used for execution) are read independently from the same attacker-supplied JSON body, an attacker can set them to different values. This is structurally identical to the `VaultRouter.dispatch` bug: one field of the payload is checked/authenticated (`actionToExecute` / `repository_owner`), while a different, uncoupled field actually drives the state-changing action (`action` tuple used in the `else if` / `repository.full_name` used to load the target `Stack`).

Additionally, `GitHubApp#verify_webhook_signature` no-ops (`return true`) whenever `webhook_secret` is blank for the organization resolved by `repository_owner`: [7](#0-6) 
`webhook_secret` is documented as optional per-organization configuration: [8](#0-7) 
so any tenant organization onboarded without a `webhook_secret` (a supported, non-error configuration) turns `repository_owner` into a universal bypass key: pick that org's login for `repository.owner.login` (satisfies `verify_signature` unconditionally), then set `repository.full_name` to any other tenant's repository to drive real state changes (queue `GithubSyncJob`, flip commit `Status`, archive/unarchive review stacks, etc.) for a stack you have no relationship to.

Even where every tenant configures a `webhook_secret`, the binding is still broken for any party that legitimately possesses one organization's own secret (a normal, non-privileged artifact issued to that tenant to authenticate its own traffic): that party can compute a valid signature keyed to their own organization, then target `repository.full_name` at a stack belonging to a different repository/organization served by the same Shipit instance.

### Impact Explanation
This breaks tenant isolation in a multi-organization Shipit deployment (`Shipit.github(organization:)` per-org config, `Shipit.github_organizations`). An attacker who is unassociated with a target repository can:
- Force `GithubSyncJob`/`RefreshCheckRunsJob` runs against arbitrary stacks (`PushHandler`, `check_suite_handler`).
- Inject forged commit statuses on arbitrary commits (`StatusHandler#process` → `commit.create_status_from_github!`), which downstream deploy gating (`require_ci`) relies on to decide whether a commit is deployable.
- Archive/unarchive/provision review stacks belonging to unrelated repositories (`PullRequest::*Handler`).

Forging commit status directly undermines the CI-gate that `Api::DeploysController#create` enforces (`param_error!(:require_ci, ...) unless commit.deployable?`), enabling an unauthorized deploy of a commit that never actually passed CI on the real repository — matching the "unauthorized deploy" Critical impact bucket, and more generally constitutes cross-repository writes into stacks the caller has no authorization over.

### Likelihood Explanation
Requires only the ability to send an HTTP POST to the public `/webhooks` endpoint (unauthenticated, no Shipit session, no `ApiClient` token) plus a valid HMAC for *some* organization served by the instance. In multi-tenant Shipit deployments this can be trivial when (a) any onboarded organization has no `webhook_secret` configured (documented as optional), or (b) the attacker legitimately controls one tenant organization's own GitHub App/webhook secret and abuses it to target a sibling tenant's repositories — no compromise of the victim's secret is required at all.

### Recommendation
In `WebhooksController#verify_signature` / the `Webhooks::Handlers::Handler` base class, enforce that the organization resolved for signature verification matches the owner of the `repository.full_name` actually processed — e.g., derive both from the same normalized `repository` sub-hash and reject the request (422) if `repository.full_name.split('/').first` does not case-insensitively equal `repository_owner`, before any handler is invoked.

### Proof of Concept
1. Configure Shipit in multi-org mode with two organizations, `tenant-a` (its own GitHub App/`webhook_secret` known to its own admins) and `tenant-b` (contains the victim repository/stack).
2. As an actor who only knows `tenant-a`'s webhook secret (or targets any org configured without a `webhook_secret`), POST to `/webhooks` with:
   - `X-Github-Event: push`
   - `X-Hub-Signature` computed with `tenant-a`'s secret over the raw body (or omitted/arbitrary if the target org has no secret configured)
   - Body:
     ```json
     {
       "ref": "refs/heads/main",
       "after": "<attacker-chosen sha already known to exist on victim repo>",
       "repository": {
         "owner": { "login": "tenant-a" },
         "full_name": "tenant-b/victim-repo"
       }
     }
     ```
3. `verify_signature` resolves `Shipit.github(organization: "tenant-a")` and validates against `tenant-a`'s secret — passes.
4. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("tenant-b/victim-repo")` and triggers `sync_github` on the victim's stack, despite the request never having been authenticated by `tenant-b`'s own credentials.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L117-119)
```markdown
**`github.bot_login`** The login of the App [bot] user. Every GitHub App have an associated `[bot]` user which acts as the author of the App actions through the API, for example when an App merges a Pull Request. It should be the App "slug" with the suffix `[bot]`. For example if your app settings URL is `https://github.com/organizations/ACME/settings/apps/acme-shipit/installations`, the bot user should be `acme-shipit[bot]`. If you are unsure, you can leave it empty.

**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
```
