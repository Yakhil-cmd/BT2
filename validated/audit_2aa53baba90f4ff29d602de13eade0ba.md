### Title
Cross-organization webhook forgery via mismatched signing-organization vs. acted-upon-repository fields - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In a multi-GitHub-App Shipit deployment (`config/secrets.yml` keyed by organization, as documented in `docs/setup.md` "Using Multiple Github Applications"), the webhook signature is verified using the GitHub App selected by `repository.owner.login`, while every event handler subsequently acts on the repository named by `repository.full_name` from the same, attacker-supplied JSON body. These two fields are never checked for consistency, and `webhook_secret` is explicitly optional per app/org. This breaks the intended binding "organization that authenticated == repository that is written": if any onboarded organization has no `webhook_secret` configured, an unauthenticated caller can pass verification as that org while pointing `repository.full_name` at a stack that belongs to a different, securely-configured organization.

### Finding Description
`WebhooksController#verify_signature` picks the `GitHubApp` used to validate `X-Hub-Signature` purely from the payload itself: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization app config in a multi-app setup: [3](#0-2) 

and `GitHubApp#verify_webhook_signature` explicitly treats an absent `webhook_secret` as automatically verified: [4](#0-3) 

`docs/setup.md` documents `webhook_secret` as **optional** for each organization app, and shows the multi-org config schema keyed by organization name: [5](#0-4) 

Meanwhile every webhook handler resolves the target `Stack`(s) from a *different* field of the same attacker-controlled JSON body — `repository.full_name` — with no cross-check against the organization used for signing: [6](#0-5) 

This is used, for instance, by the push handler to trigger a stack sync: [7](#0-6) 

and, per the controller test suite, the `status` event handler creates `Commit` `Status` rows for whatever commit/repo is named in the body: [8](#0-7) 

**Equality that should hold but doesn't:** `organization_that_authenticated_signature == organization_owning(repository.full_name)`. Nothing in `verify_signature` or `Handler#stacks` enforces that `repository.owner.login` (used to select the verifying app/secret) matches the owner prefix of `repository.full_name` (used to select the affected `Stack`). Both are attacker-supplied fields inside the same unsigned-until-verified JSON body, and verification only binds the raw body to *a* secret — it does not bind the *chosen* secret to the specific repository being mutated.

### Impact Explanation
Where an operator has configured multiple GitHub Apps (multi-tenant Shipit) and at least one of them has no `webhook_secret` set (an explicitly supported/optional configuration per the setup docs), an attacker can craft a JSON body with `repository.owner.login` = the org with no secret, and `repository.full_name` = `<securely-configured-org>/<repo>`. Since `verify_webhook_signature` returns `true` unconditionally for the no-secret org, the request passes verification and the handler acts on the named stack belonging to a different, victim organization — e.g. forging a `status` event to mark a malicious commit's CI as `success`, which can allow that commit to satisfy Shipit's deploy safety/CI checks and be auto-deployed via continuous deployment, i.e., an unauthorized deploy of unreviewed code on the victim's stack. This lands in the Critical bucket ("... or an unauthorized deploy, rollback or merge").

### Likelihood Explanation
Requires no privileged credential, session, or `ApiClient` token — the endpoint is `app/controllers/shipit/webhooks_controller.rb`'s public `/webhooks` route which is unauthenticated by design (`skip_before_action :verify_authenticity_token`). It only requires: (1) the deployment uses the documented multi-org GitHub App configuration, and (2) at least one onboarded organization has no `webhook_secret` set — a state the docs call "optional," making it a realistic misconfiguration rather than a contrived one. This is a plausible but conditional deployment scenario, not always exploitable (a single-app deployment with a secret set is not affected).

### Recommendation
In `Handler#stacks`/`Handler#repository_name`, or centrally in `WebhooksController`, verify that the organization used to select and validate the signature (`repository.owner.login`) matches the owner segment of `repository.full_name` before dispatching to any handler; reject the request otherwise. Additionally, consider making `webhook_secret` mandatory (fail closed) whenever more than one GitHub organization/app is configured, since an absent secret in a multi-tenant setup effectively disables authentication for that tenant while other tenants remain protected.

### Proof of Concept
Preconditions: Shipit configured with two orgs, e.g. `OrgNoSecret` (no `webhook_secret`) and `OrgVictim` (has stacks and a `webhook_secret`), per `test/dummy/config/secrets_double_github_app.yml`-style multi-org config.

```
POST /webhooks HTTP/1.1
X-Github-Event: status
X-Hub-Signature: sha1=0000000000000000000000000000000000000000  (any value; unchecked because OrgNoSecret has no secret)
Content-Type: application/json

{
  "sha": "<victim commit sha>",
  "state": "success",
  "target_url": "https://ci.example.com/fake",
  "context": "ci/attacker-forged",
  "repository": {
    "owner": { "login": "OrgNoSecret" },
    "full_name": "OrgVictim/victim-repo"
  }
}
```

1. `verify_signature` computes `repository_owner` = `"OrgNoSecret"` (from `repository.owner.login`), calls `Shipit.github(organization: "OrgNoSecret")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` regardless of the header.
2. Request passes to `Shipit::Webhooks.for_event('status')`, whose handler resolves the target repository from `payload.dig('repository', 'full_name')` = `"OrgVictim/victim-repo"`.
3. A CI status of `success` is recorded against the victim commit under `OrgVictim`, without ever presenting `OrgVictim`'s webhook secret.

I was unable to load and confirm the exact contents of the `status`/`commit_status` handler implementation (only inferred its behavior from `test/controllers/webhooks_controller_test.rb`); a Devin session with full file access should verify the precise handler class (`app/models/shipit/webhooks/handlers/status_handler.rb` or similarly named) to confirm the exact write path and any additional downstream safety-check gating before treating the deploy-triggering consequence as fully proven end-to-end.

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
