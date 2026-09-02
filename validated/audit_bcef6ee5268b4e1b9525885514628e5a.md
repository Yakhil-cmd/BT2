### Title
Webhook signature verified against the payload's declared organization, not the repository actually written — cross-organization Status/Push injection - ([File: app/controllers/shipit/webhooks_controller.rb])

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to use for HMAC verification based on `repository_owner`, computed as: [1](#0-0) 

```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

This value is passed to `Shipit.github(organization: repository_owner)` to fetch the org-specific `webhook_secret` used to validate `X-Hub-Signature`: [2](#0-1) 

Once the signature check passes, the entire raw JSON body is handed to the event handlers, which independently determine *which repository/stack to act on* using a different payload field — `repository.full_name` — via `Repository.from_github_repo_name`: [3](#0-2) 

Nothing binds `repository.owner.login` (the field that selects the authenticating organization's secret) to the owner segment of `repository.full_name` (the field that selects which repository/stack is written to). Since Shipit explicitly supports multiple GitHub Apps for different organizations, each configured with its own independently-chosen `webhook_secret` (see `config/secrets.development.example.yml`), an operator/attacker who legitimately controls one configured organization's GitHub App knows that organization's `webhook_secret` and can compute a valid HMAC over an arbitrary raw body. They can set `repository.owner.login` to their own organization (so `verify_signature` picks their own known secret and passes) while setting `repository.full_name` to a victim organization/repository that also has a Shipit stack configured, causing handlers such as `StatusHandler` (which writes a `Status` directly from unverified payload fields such as `state`, `target_url`, `description`, `context` — as exercised in `test/controllers/webhooks_controller_test.rb:42-59`) or `PushHandler` (which triggers `stack.sync_github`) to act on the victim's stack.

This is the same class of vulnerability described in the analog report: a verified credential (the HMAC, tied to "the organization that authenticated") is not bound to the object actually mutated (the repository resolved by handlers, "the repository that is written"), exactly matching the explicitly allowed analog "an organization that authenticated versus the repository that is written."

### Impact Explanation
An attacker holding a valid `webhook_secret` for any one organization configured in a multi-org Shipit deployment can forge signed webhook deliveries that are processed against any *other* organization's repositories/stacks known to Shipit. This allows unauthorized cross-repository writes — e.g., injecting fabricated commit `Status` records that influence deployability/merge-queue decisions, or forcing unwanted `GithubSyncJob`s — on stacks the attacker's organization has no legitimate relationship to. This matches the "cross-repository writes" / unauthorized action criteria for a valid finding.

### Likelihood Explanation
Requires the attacker to control (or have configured) at least one organization's GitHub App registered with the target Shipit instance and know that org's `webhook_secret` — a realistic scenario in shared/multi-tenant Shipit deployments where multiple orgs' GitHub Apps point at the same Shipit install, as explicitly documented as a supported configuration. No Shipit session, API token, or GitHub App private key for the *victim* organization is needed — only the attacker's own legitimately-configured organization's secret.

### Recommendation
Bind the field used to select the verifying `webhook_secret` to the field used to resolve the target repository: require that `repository.full_name`'s owner segment equals `repository_owner` before dispatching to handlers, or exclusively derive both values from the same single field. Additionally, when multiple organizations are configured, verify the signature against the GitHub App organization that the resolved `repository.full_name` actually belongs to, not the organization named in the payload.

### Proof of Concept
1. Configure Shipit with two GitHub Apps: `attacker-org` (attacker knows its `webhook_secret`) and `victim-org` (has a Shipit stack for `victim-org/victim-repo`), per the multi-org config format in `config/secrets.development.example.yml`.
2. Attacker crafts a `status` (or `push`) webhook JSON body with `repository.owner.login = "attacker-org"` and `repository.full_name = "victim-org/victim-repo"`, `sha`/`state`/`target_url` of their choosing.
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s known `webhook_secret` over the raw body and POSTs to `/webhooks`.
4. `WebhooksController#verify_signature` resolves `repository_owner = "attacker-org"`, fetches `attacker-org`'s secret, and the signature validates.
5. `StatusHandler`/`PushHandler` resolves the target stack via `repository.full_name = "victim-org/victim-repo"` and creates a forged `Status` (or triggers `sync_github`) against the victim's stack, despite the request never having been signed by `victim-org`'s GitHub App.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
