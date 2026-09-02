This confirms the multi-tenant configuration model: `Shipit.github(organization:)` looks up per-organization config (with its own `webhook_secret`) from `secrets.github` keyed by org name, as shown in `config/secrets.development.shopify.yml` where multiple orgs each have independent `webhook_secret` values [1](#0-0) [2](#0-1) . This is a genuine multi-tenant setup where different organizations onboarded to the same Shipit instance each control/know their own GitHub App's `webhook_secret`.

### Title
Webhook signature verified against attacker-controlled `repository.owner.login` while event handlers act on a different, unverified `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to use for HMAC verification based on a field taken directly from the unauthenticated, attacker-supplied JSON body (`repository.owner.login`, falling back to `organization.login`), rather than from any value tied to the actual target repository that the event handlers subsequently act on.

### Finding Description
The controller resolves the GitHub App used for signature verification like this: [3](#0-2) [4](#0-3) 

`repository_owner` is read straight out of the request body (`params.dig('repository', 'owner', 'login')`), and `Shipit.github(organization: repository_owner)` picks that organization's independently-configured `webhook_secret` to verify `X-Hub-Signature` [5](#0-4) .

Once the signature check passes, the actual event handler (e.g. `PushHandler`, and all others inheriting from `Handler`) resolves the target repository/stacks using a *different* field of the same payload — `repository.full_name` — via `Repository.from_github_repo_name`: [6](#0-5) [7](#0-6) [8](#0-7) 

Nothing cross-checks that `repository.owner.login` (used to select the verifying secret) matches the owner segment of `repository.full_name` (used to locate the `Stack`). Because the endpoint is a public, unauthenticated HTTP POST target (no session, no API token required — `skip_before_action :verify_authenticity_token`), any party who legitimately administers **any one** organization configured in this multi-tenant Shipit instance (and therefore knows that org's own `webhook_secret`, since they configure their own GitHub App's webhook secret) can craft an arbitrary raw body: set `repository.owner.login` to their own organization (to pass HMAC verification with a secret they know) while setting `repository.full_name` to `victim-org/victim-repo`. The signature check passes using the attacker's own org's secret, yet the handler dispatches state changes (new commits via `GithubSyncJob`, deploy statuses, check-run refreshes, pull-request label/merge processing, membership/team changes) against the victim organization's stacks.

This is a binding break: `organization authenticated (repository.owner.login)` ≠ `repository actually written to (repository.full_name)`.

### Impact Explanation
Depending on the event type dispatched, this allows cross-organization/cross-repository writes without possessing the victim org's `webhook_secret`:
- `push`/`status`/`check_suite` handlers can inject fabricated commit/CI state into a victim stack, causing `GithubSyncJob` to sync from GitHub using the victim stack's real GitHub credentials, or spoof commit statuses that gate `deployable?` — potentially unlocking unauthorized deploys on the victim's stack.
- `pull_request` handlers can affect merge-queue behavior (`labeled`/`unlabeled`/`closed`/`opened` handlers) on a victim repository's merge requests.
- `membership` handlers can create/remove `Membership`/`Team` records tied to whichever org name is embedded in the (unverified) payload fields those handlers read.

This matches the "cross-repository writes" / "unauthorized deploy" bar since the attacker forges events against a repository they were never authorized to send events for, using only credentials for a different, unrelated organization.

### Likelihood Explanation
Requires the attacker to be a legitimate administrator of at least one organization already onboarded to this specific multi-tenant Shipit deployment (so they know that org's `webhook_secret`), which is exactly the population of "unprivileged" (i.e., non-Shipit-admin) users this instance is designed to serve. No GitHub-side webhook delivery is required — the attacker can POST directly to the public `/webhooks` endpoint with a crafted body and their own valid HMAC signature.

### Recommendation
After verifying the signature, ensure the organization used to select the `webhook_secret` matches the owner of the repository the handler will act on — e.g., derive the verifying organization from `repository.full_name`'s owner segment (or explicitly compare `repository.owner.login` against the owner segment of `repository.full_name`) before dispatching to any handler, and reject the event if they diverge.

### Proof of Concept
1. Configure/observe that this Shipit instance serves at least two organizations, `attacker-org` and `victim-org`, each with independent `webhook_secret` values (as in `config/secrets.development.shopify.yml`).
2. As an admin of `attacker-org`, obtain `attacker-org`'s `webhook_secret` (known to them since they configured their own GitHub App).
3. Build a `push` event JSON body with:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen sha>",
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
   }
   ```
4. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org's webhook_secret, body)>`.
5. POST this to `/webhooks` with header `X-Github-Event: push`. `verify_signature` calls `Shipit.github(organization: 'attacker-org')` and validates the signature successfully [3](#0-2) .
6. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which looks up stacks via `Repository.from_github_repo_name('victim-org/victim-repo')` [6](#0-5)  and triggers `stack.sync_github(expected_head_sha: ...)` on the victim's stack [7](#0-6)  — a write against `victim-org/victim-repo` authorized only by `attacker-org`'s secret.

### Citations

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
