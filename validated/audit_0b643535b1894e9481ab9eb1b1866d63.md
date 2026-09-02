## Title
Webhook organization authenticated for signature verification is never bound to the repository the handler acts on, allowing cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` picks the GitHub App/secret used to validate `X-Hub-Signature` from `repository.owner.login` (or `organization.login`), while every webhook `Handler` subsequently resolves the target `Stack`s/`Repository` from an entirely separate, independently-controlled JSON field, `repository.full_name`. Because these two fields are never cross-checked, a party that can produce a validly-signed webhook for organization "A" (a legitimate org configured in this Shipit instance) can set `repository.full_name` to `"B/some-repo"` and have the handler act on organization "B"'s stack, even though "B"'s webhook secret was never used or known to the attacker.

### Finding Description
The signature check selects the app/secret keyed on the owner login extracted from the payload: [1](#0-0) [2](#0-1) 

This is only meaningful in the documented multi-organization configuration, where each GitHub org has its own `webhook_secret`: [3](#0-2) [4](#0-3) 

Once the signature is accepted, every handler resolves the affected `Repository`/`Stack`s from a *different* field of the same JSON body, `repository.full_name`, with no comparison back to the `repository.owner.login` value used for signature selection: [5](#0-4) [6](#0-5) 

`repository.owner.login` and `repository.full_name`'s owner segment are, in a genuine GitHub payload, always consistent — but nothing in this engine enforces that. An attacker who legitimately controls org "A" (already onboarded, so a valid `webhook_secret` for "A" exists and the attacker can produce/replay a signature for it — e.g. by triggering any real GitHub event in one of their own "A" repos, or by having admin access to org A's app settings) can hand-craft a webhook body: `repository.owner.login = "A"` (so `verify_signature` validates against A's secret) but `repository.full_name = "B/victim-repo"` (so `Handler#stacks` resolves org B's stacks). `PushHandler` will then call `stack.sync_github` for org B's stack, and the `status` handler will create a `Status` on org B's commit exactly as demonstrated by the existing test which posts a `status` payload merged with `repository_params` and asserts a `Status` row is created from attacker-controlled `state`/`target_url`/`description`/`context`: [7](#0-6) 

This breaks the trust binding: **organization authenticated by the signature check ≠ repository whose stacks are written by the handler.**

### Impact Explanation
By forging a `status` webhook for a foreign organization's repository, an attacker can inject arbitrary commit statuses (`state: success`, arbitrary `context`) into a stack they do not control. If that stack's `shipit.yml` uses `ci.require` on that context (a documented Shipit feature), this fabricated status satisfies the CI gate, letting a commit that never actually passed CI (or was never even reviewed) become deployable/mergeable by a legitimate, authorized user of the victim stack — effectively enabling deployment of unvetted/malicious code by circumventing the CI-required control. This crosses an authorization boundary between organizations sharing one Shipit instance and qualifies as enabling an unauthorized deploy of a commit that should never have satisfied deploy readiness checks.

### Likelihood Explanation
Requires the attacker to be an authenticated GitHub organization already integrated with this multi-org Shipit deployment (able to produce a webhook whose signature is valid for their own org's secret — no access to the victim org's secret, private key, or Shipit session/API token is needed). This is realistic for any Shipit deployment serving multiple GitHub organizations (the exact scenario `docs/setup.md`/`secrets_double_github_app.yml` document as supported), since none of these orgs are expected to trust each other.

### Recommendation
After verifying the signature with the app keyed by `repository.owner.login`, require that the resolved `Repository.owner` used by handlers (`repository.full_name`'s owner segment) matches the `repository.owner.login`/`organization.login` value that selected the signing key, and reject the webhook otherwise.

### Proof of Concept
1. Configure Shipit with two orgs, `A` and `B`, each with distinct `webhook_secret`s (per `docs/setup.md`), and create a Shipit stack for `B/victim-repo`.
2. As the operator/owner of GitHub org `A` (or anyone who can produce a validly HMAC-signed delivery for `A`), send:
```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=<hmac(webhook_secret_A, body)>

{
  "sha": "<victim-stack-commit-sha>",
  "state": "success",
  "context": "required-ci-context",
  "target_url": "http://attacker.example",
  "repository": {
    "owner": {"login": "A"},
    "full_name": "B/victim-repo"
  }
}
```
3. `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) validates against org `A`'s secret and passes.
4. `StatusHandler`/`Handler#stacks` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`, `app/models/shipit/repository.rb:53-56`) resolves `B/victim-repo` from `full_name` and creates a `Status` for the victim commit, marking it as passing the required CI context, without any credential belonging to org `B`.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
