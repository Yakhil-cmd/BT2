### Title
Cross-organization commit-status forgery via unbound webhook signature verification - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook against the GitHub App configured for **one** organization (derived from the payload's `repository.owner.login`), but the event handler that consumes the very same payload (`StatusHandler`) never re-checks that the organization which the signature vouches for actually owns the resource the handler mutates. The equality the code implicitly assumes — "organization whose secret verified this request" == "organization that owns the repository/commit being written" — is never enforced, so a party who legitimately controls one Shipit-registered GitHub organization can forge commit statuses for commits belonging to a completely different, unrelated organization/repository also hosted on the same Shipit instance.

### Finding Description
`WebhooksController#verify_signature` picks the app config to validate against solely from the payload's own `repository.owner.login` (falling back to `organization.login`): [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves the `webhook_secret` used purely from that attacker-suppliable `repository_owner` string, and only that organization's secret is used for the HMAC check: [3](#0-2) [4](#0-3) 

Once the signature passes, `WebhooksController#create` hands the entire raw, attacker-influenced JSON to every registered handler for the event with no additional binding of "verified organization" to "target repository": [5](#0-4) 

`StatusHandler#process` — the handler for the `status` event — resolves the target purely by commit SHA, globally, with **no repository/organization scoping whatsoever**: [6](#0-5) 

Consequently, the "authenticating organization" (used only to pick which `webhook_secret` validates the HMAC) and the "repository/commit actually written" (any `Commit` anywhere in the Shipit instance whose `sha` matches the attacker-chosen value) are two independent values that are never required to match. This is the exact same class of bug as the report: the code authenticates against one identifier (`repository_owner` for secret selection) but then acts on a different, unchecked identifier (arbitrary `sha` reachable across all tenants) taken from the same untrusted payload.

Shipit explicitly supports multiple independent GitHub organizations sharing a single Shipit deployment, each with its own `webhook_secret`, as documented: [7](#0-6) [8](#0-7) 

An entity that legitimately administers its own GitHub App installation for `Org-A` (and therefore knows `Org-A`'s `webhook_secret`, which they configured themselves) can:
1. Compute a valid `X-Hub-Signature` over an arbitrary JSON body using `Org-A`'s own secret.
2. Set `repository.owner.login` (or `organization.login`) to `Org-A` so `verify_signature` selects and successfully validates against `Org-A`'s secret.
3. Set the `sha`/`state` fields to reference a commit that actually belongs to `Org-B` (a completely different, unrelated tenant on the same Shipit instance).
4. POST directly to the `/github_webhooks` (or configured webhooks) endpoint — no GitHub relay is required, since Shipit only checks the HMAC of the raw body, not its provenance.

The `status` webhook flows into `Commit#create_status_from_github!`, which is the mechanism Shipit uses to track CI/required-status state that gates deploy eligibility for a commit. Forging a "success" status for a victim organization's commit can make that commit appear deployable when it should not be, directly undermining Shipit's deploy-safety gating for a tenant the attacker has no legitimate access to.

### Impact Explanation
This breaks the trust boundary between tenants of a multi-organization Shipit deployment: possession of a secret for one organization's GitHub App is sufficient to write commit-status state for any other organization's repositories tracked by the same instance. Since commit statuses are used by Shipit to determine whether a commit satisfies required checks before it can be deployed, an attacker can forge a passing status on a victim commit, potentially enabling that commit to be deployed/promoted when it should have been blocked — matching the "unauthorized deploy" Critical-impact category.

### Likelihood Explanation
Requires the attacker to control (as a legitimate, unprivileged-relative-to-the-victim party) any one of the multiple GitHub organizations configured on a shared Shipit instance — a realistic operating model, since Shipit explicitly documents and supports hosting several independent orgs behind one instance. No access to the victim organization, no GitHub App private key, no Shipit session, and no privileged Shipit account are needed; only knowledge of the attacker's own org's webhook secret, which they set themselves.

### Recommendation
Bind the verified organization to the resource actually mutated:
- Have `WebhooksController#verify_signature` store/pass along the verified `repository_owner` (or the resolved `GitHubApp` organization) to handlers, and have every handler that mutates a `Commit`/`Repository`/`Stack` (in particular `StatusHandler`) filter its lookup by that verified organization instead of trusting `sha` (or `full_name`) alone.
- At minimum, `StatusHandler#process` should scope `Commit.where(sha: params.sha)` to commits whose `stack.repository` matches the organization that the request was verified against.

### Proof of Concept
1. Configure Shipit with two organizations, `victim-org` and `attacker-org`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md` multi-org format).
2. As the administrator of `attacker-org`'s GitHub App (attacker's own, legitimately-owned secret), craft:
```json
{
  "sha": "<sha-of-a-commit-that-belongs-to-victim-org/some-repo>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/attacker-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org's webhook_secret, body)>`.
4. `POST` the body with headers `X-Github-Event: status` and the computed signature to Shipit's webhooks endpoint.
5. `verify_signature` resolves `repository_owner` = `attacker-org`, fetches `attacker-org`'s (correct) secret, and the signature validates.
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, matches the victim's commit purely by SHA (no org check), and calls `create_status_from_github!`, writing a forged "success" status onto a commit the attacker has no legitimate access to.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** test/unit/shipit_test.rb (L11-22)
```ruby
    test ".github uses indifferent access to search through the Github applications" do
      secrets = ActiveSupport::OrderedOptions.new
      secrets.merge!(YAML.load_file('test/dummy/config/secrets_double_github_app.yml'))
      secrets.deep_symbolize_keys!
      Shipit.stubs(:secrets).returns(secrets)
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: 'OrgOne'))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :OrgOne))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: 'orgone'))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :orgone))
      assert_instance_of(Shipit::GitHubApp, Shipit.github(organization: :OrgTwo))
      Shipit.unstub(:secrets)
    end
```
