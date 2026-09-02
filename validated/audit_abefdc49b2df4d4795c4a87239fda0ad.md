### Title
Cross-tenant webhook forgery via organization without `webhook_secret` reaches `UnlabeledHandler` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App config to verify against using `params.dig('repository','owner','login')`, but `verify_webhook_signature` unconditionally returns `true` when that organization has no `webhook_secret` configured [1](#0-0) . Since the handler that actually processes the event (`UnlabeledHandler`) resolves the target repository from `params.repository.full_name` in the same attacker-controlled JSON body [2](#0-1) , an attacker can set `repository.owner.login` to a no-secret organization (to pass verification) while setting `repository.full_name` to a victim repository belonging to a different, secret-protected organization, causing the forged payload to mutate the victim's review stack.

### Finding Description
The broken binding is: *the organization whose config was used to verify the signature* (`repository_owner = params.dig('repository','owner','login')`, used in `Shipit.github(organization: repository_owner)` at [3](#0-2) ) *must equal the organization that owns the repository the handler actually mutates* (`params.repository.full_name`, used in `Repository.from_github_repo_name` at [2](#0-1) ). Nothing in the code enforces this equality: both values are read independently from the same attacker-supplied JSON body, and the `ExplicitParameters` schema for `UnlabeledHandler` only requires `repository.full_name` to be present as a `String`, with no cross-check against `owner.login` [4](#0-3) .

`GitHubApp#verify_webhook_signature` short-circuits to `true` whenever `webhook_secret` is blank for the resolved organization, before any signature/algorithm check is performed [1](#0-0) . `webhook_secret` is documented as optional in `docs/setup.md`, so an operator with a secret-less organization configured is realistic.

Exploit flow (**only applicable when Shipit is configured with the multi-organization `github` config schema**, i.e. `github_default_organization` is non-nil): the attacker sends
```
POST /webhooks
X-Github-Event: pull_request
X-Hub-Signature: sha1=anything
{
  "action": "unlabeled",
  "repository": { "owner": {"login": "attacker-org-with-no-secret"}, "full_name": "victim-org/victim-repo" },
  "pull_request": { ...state: "open", labels: [...] },
  "sender": {"login": "attacker"}
}
```
`verify_signature` resolves `Shipit.github(organization: "attacker-org-with-no-secret")`, finds no `webhook_secret`, and returns `true` regardless of the (bogus) `X-Hub-Signature` value [3](#0-2) . The request then flows into `Shipit::Webhooks.for_event('pull_request')`, which dispatches to `UnlabeledHandler`, which resolves `victim-org/victim-repo` and, based on `provisioning_behavior` and the label state in the forged payload, calls `stack.archive!` or `stack.unarchive!` on the victim's review stack via `ReviewStackAdapter` [5](#0-4) .

Note: I was **not able to fully confirm** whether Shipit's `Shipit.github` method actually honors a per-organization lookup in the deployment context assumed by the question. Reading `lib/shipit.rb`, when `github_default_organization` is `nil` (the single-tenant/legacy config schema shown as the primary example in `docs/setup.md`), the `organization` argument passed to `Shipit.github(organization: ...)` is **ignored** and the single top-level `secrets.github` config (with its single `webhook_secret`) is used regardless of what `repository_owner` says [6](#0-5) . In that common configuration, this cross-tenant attack does **not** work, because there is only one `webhook_secret` and it protects all repositories uniformly. The attack is only viable when Shipit is deployed with the multi-organization config schema (keyed by org name under `github:`) **and** at least one configured organization has no `webhook_secret` set.

### Impact Explanation
If exploitable (multi-org config with a no-secret org present), a completely unauthenticated attacker can forge `pull_request` webhooks that are accepted as valid for *any* repository already known to Shipit, causing archival/unarchival of that repository's review stacks, deprovisioning of infrastructure, and re-enqueuing of provisioning jobs — a cross-tenant state-mutation impact matching the "Critical: payload for one repository mutating another's stack" category, since the attacker only needs to control a no-secret org's name, not the victim org's secret.

### Likelihood Explanation
This requires a specific, non-default Shipit deployment configuration: the multi-organization `github:` secrets schema, and at least one configured organization lacking a `webhook_secret`. The documented example configuration in `docs/setup.md` uses the single-org legacy schema where this bypass does not apply. Whether any real deployment uses the multi-org schema with a no-secret org is deployment-specific and cannot be verified from the engine code alone. Given this precondition, likelihood is moderate-to-low absent confirmation of such deployments.

### Recommendation
- In `WebhooksController#verify_signature`, cross-validate that the resolved `repository_owner` used for signature verification matches the organization implied by `params.repository.full_name` before dispatching to handlers.
- In `GitHubApp#verify_webhook_signature`, do not silently accept unsigned/unverifiable requests when `webhook_secret` is blank for a multi-org config; instead reject or require an explicit "no verification" opt-in per organization, and log/alert on such configurations.
- Add signature/body binding for `X-Hub-Signature-256` support (SHA-256 HMAC) in addition to legacy `sha1`, since GitHub now recommends SHA-256.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (extension)
test "forged pull_request unlabeled webhook from no-secret org mutates a different org's stack" do
  # Requires multi-org secrets schema with orgs: 'attacker-org' (no webhook_secret) and the victim's real org.
  victim_repo = shipit_repositories(:shipit) # owned by e.g. 'shopify'
  stack = create_stack_for(victim_repo)
  configure_provisioning_behavior(repository: victim_repo, behavior: :allow_with_label, label: "pull-requests-label")

  request.headers['X-Github-Event'] = 'pull_request'
  request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # bogus, never actually checked

  payload = JSON.parse(payload(:pull_request_unlabeled))
  payload["repository"]["owner"]["login"] = "attacker-org" # org with no webhook_secret
  payload["repository"]["full_name"] = victim_repo.full_name # victim org/repo
  payload["pull_request"]["labels"] = [] # triggers archive per allow_with_label

  assert_changes -> { stack.reload.archived? }, from: false, to: true do
    post :create, body: payload.to_json, as: :json
  end
  assert_response :ok
end
```
Assert on both sides of the equality: `repository_owner` (`"attacker-org"`, used to select verification config) vs. the organization actually owning the mutated `stack` (derived from `victim_repo.full_name`, `"shopify"` in fixtures) — showing they diverge and the attacker's org's lack of a secret was sufficient to authorize a write against the victim's stack.

### Citations

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L49-57)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L59-63)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
