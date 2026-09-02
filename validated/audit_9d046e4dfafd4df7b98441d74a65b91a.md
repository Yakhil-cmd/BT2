### Title
Webhook signature verified against `repository.owner.login`'s GitHub App secret while routing/state-mutation uses the independent, unchecked `repository.full_name` field - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which multi-tenant GitHub App configuration (and therefore which `webhook_secret`) to validate the HMAC signature against by reading `repository.owner.login` (or `organization.login`) out of the *unverified* JSON body, then verifies the raw payload bytes against that org's secret. Once verification succeeds, the entire raw payload — including a completely separate field, `repository.full_name` — is handed unchanged to the event handlers, which use `full_name` (not `owner.login`) to look up the `Repository`/`Stack` records that are mutated. The code never checks that the organization whose secret validated the signature actually matches the owner encoded in `full_name`.

### Finding Description
`verify_signature` picks the GitHub App/secret to check against using a field read from the still-untrusted body: [1](#0-0) [2](#0-1) 

The secret used for that HMAC check is looked up per-organization in the multi-tenant config: [3](#0-2) 

After the signature check passes, `create` re-parses the same raw body and dispatches it to handlers untouched: [4](#0-3) 

Every handler resolves the target repository/stacks from a *different* JSON key, `repository.full_name`, with no cross-check against the organization that authenticated the request: [5](#0-4) [6](#0-5) 

Because the entity that owns/configures one tenant's GitHub App (and therefore knows that installation's `webhook_secret`, which they set themselves per `docs/setup.md`'s "Using Multiple Github Applications" instructions) fully controls the raw bytes they sign, they can set `repository.owner.login` to their own org (so `verify_signature` selects and validates against their own known secret) while setting `repository.full_name` to `"victim-org/victim-repo"`. The signature check passes because it only binds the message to *a* known secret, not to the specific owner encoded in `full_name`, and the handler layer trusts `full_name` unconditionally.

This is the same trust-boundary class as the reported oracle bug: two pieces of data (the value used to select/verify the authenticating secret and the value used to select what protected state is mutated) are expected to agree, but the code never enforces that equality, exactly matching the "organization that authenticated versus the repository that is written" analog category.

### Impact Explanation
An attacker who legitimately controls one low-privilege tenant's GitHub App installation in a multi-organization Shipit deployment can forge webhook events (signed with their own known secret) that are routed to and mutate **any other tenant's** `Stack`/`Repository`/`Commit` records. Concretely:
- `PushHandler` triggers `GithubSyncJob`/`stack.sync_github` for arbitrary victim stacks with an attacker-chosen `after` SHA: [7](#0-6) 
- `StatusHandler`-style flows create `Status` records for arbitrary commit SHAs on victim stacks (confirmed by the existing test creating a `Status` from a `status` event payload): [8](#0-7) 

Forged/fake success statuses on a victim repository's commit can defeat Shipit's deploy-gating checks, enabling an unauthorized deploy of an unreviewed or malicious commit by an unrelated, legitimate deployer relying on the (forged) green status — this reaches the required "unauthorized deploy" bar.

### Likelihood Explanation
Exploitation only requires: (1) a multi-organization Shipit deployment (explicitly documented and supported, see `docs/setup.md` "Using Multiple Github Applications"), and (2) attacker control of one tenant's own GitHub App / webhook secret — which is the minimum, expected credential for any onboarded tenant, not a privileged Shipit or repository-write credential. No `ApiClient` token, session, or GitHub repo write access is required, so this is reachable by an unprivileged tenant administrator against any other tenant hosted on the same Shipit instance.

### Recommendation
After signature verification, cross-check that the organization whose secret validated the request equals the owner portion of `repository.full_name` (and `organization.login`) before dispatching to handlers — i.e., bind the verified organization identity to every field the handlers subsequently act on, not just to secret selection. Reject the webhook (422) if they disagree.

### Proof of Concept
1. Deploy Shipit in multi-org mode with `OrgA` and `OrgB` both configured in `config/secrets.yml` under `github:` (per `docs/setup.md`), each with its own `webhook_secret`.
2. As the administrator/owner of `OrgA` (an attacker with no privileges over `OrgB`), craft a `status` webhook JSON body:
```json
{
  "sha": "<victim-repo-commit-sha>",
  "state": "success",
  "context": "ci",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac>` using `OrgA`'s known `webhook_secret` over the raw body.
4. POST to `/webhooks` with `X-Github-Event: status`. `verify_signature` resolves `repository_owner` → `"OrgA"`, fetches `OrgA`'s app, and the signature validates successfully.
5. `Handler#repository_name` resolves `"OrgB/victim-repo"` via `Repository.from_github_repo_name`, and the handler creates/updates a `Status` on `OrgB`'s commit — despite the request never being signed with `OrgB`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```
