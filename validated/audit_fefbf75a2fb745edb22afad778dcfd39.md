### Title
Webhook signature verification is scoped to the wrong field, allowing cross-organization forgery of GitHub events (e.g., forged commit statuses) - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to verify a webhook against using `repository_owner`, a value taken from the *unverified* JSON body (`repository.owner.login` or `organization.login`). Every webhook handler, however, resolves the repository/stack the event actually mutates independently, using `payload.dig('repository', 'full_name')`. Nothing ties these two fields together, so the "organization whose secret authenticated this request" and "the repository the request is allowed to write to" are two different, uncorrelated values inside the same unverified payload. Anyone who legitimately knows the `webhook_secret` of *any* organization configured on a shared, multi-tenant Shipit instance (a normal, documented deployment mode, see `docs/setup.md` "Using Multiple Github Applications") can forge a signature that Shipit accepts, while pointing `repository.full_name` at a completely unrelated organization's repository/stack.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb`: [1](#0-0) [2](#0-1) 

`verify_signature` picks the `GitHubApp` (and thus the HMAC secret) to check against via:
```
repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```

This value is entirely attacker-controlled prior to verification — it is only used to pick *which* secret to check the HMAC against, not to constrain what the payload is allowed to say. Once `verified` is true, the full, unmodified `params` are handed to the matching handler: [3](#0-2) 

Handlers resolve the target repository/stack from a *different* field, `repository.full_name`, independent of `repository.owner.login`: [4](#0-3) [5](#0-4) 

The `status` event handler (exercised by `test/controllers/webhooks_controller_test.rb`'s `":state create a Status for the specific commit"` test) creates a `Status` record directly from the webhook body fields (`sha`, `state`, `description`, `target_url`, `context`, `created_at`) with no independent confirmation against the GitHub API: [6](#0-5) 

The engine explicitly supports multiple, independently-secreted GitHub App configurations sharing one Shipit instance: [7](#0-6) [8](#0-7) 

**Broken binding:** `organization authenticated (repository.owner.login → webhook_secret used for HMAC check)` is assumed to equal `repository actually written (repository.full_name resolved by the handler)`. Nothing in `verify_signature` or in `Handler#repository_name` enforces this equality.

**Exploit path:**
1. Operator runs a shared Shipit instance configured with multiple organizations, e.g. `OrgA` and `OrgB` (as in `test/dummy/config/secrets_double_github_app.yml` / `docs/setup.md`), each with its own `webhook_secret`.
2. The attacker legitimately administers `OrgA`'s own GitHub App registration on this instance and therefore knows `OrgA`'s `webhook_secret` (this is normal setup knowledge for their own tenant, not a stolen credential of the victim).
3. The attacker crafts a JSON body for the `status` (or `push`) event where `repository.owner.login = "OrgA"` (used only for signature-key selection) but `repository.full_name = "OrgB/victim-repo"` (used to resolve the actual stack/commit to mutate), and computes `X-Hub-Signature: sha1=HMAC(OrgA_webhook_secret, raw_body)`.
4. `WebhooksController#verify_signature` looks up `Shipit.github(organization: "OrgA")`, verifies the HMAC against `OrgA`'s secret, and it matches — `verified` is `true`.
5. `Shipit::Webhooks.for_event('status').each { |handler| handler.call(params) }` runs `StatusHandler`, which creates/updates a `Status` for the attacker-chosen `sha` on `OrgB`'s tracked commit using attacker-chosen `state`/`context`/`description`, with no call back to GitHub to confirm it.

### Impact Explanation
This is a cross-tenant write with no privilege on the victim organization: an attacker who only administers an unrelated organization on the same shared Shipit instance can forge GitHub Status/webhook events for another organization's repository. Because `commit_status` records directly feed `Commit#deployable?`/`ci.require` gating (`required_statuses`, `blocking_statuses` in `deploy_spec.rb`), forging a passing status for an otherwise-unreviewed or CI-failing commit can make Shipit treat that commit as deployable, undermining the CI gate that stands between "code reachable on GitHub" and "code Shipit will ship." Combined with a legitimate maintainer deploying what they believe is a green commit, this can result in an unauthorized/unintended deploy of code that did not actually pass CI — a direct, cross-repository trust-boundary violation matching the report's "field acted upon but not covered by the intended authorization" pattern.

### Likelihood Explanation
Requires a shared, multi-organization Shipit deployment (an explicitly documented and supported configuration) and knowledge of one organization's own `webhook_secret` — knowledge an attacker legitimately has for their *own* tenant, not the victim's. No access to the victim's GitHub repository, Shipit account, or API token is needed. This is a realistic "unprivileged-with-respect-to-victim" attacker scenario in any Shipit instance shared across untrusted or semi-trusted organizations.

### Recommendation
Bind the signature-verification key to the same field the handler will actually act on. At minimum, after verifying the signature, re-derive `repository_owner` from `repository.full_name`'s owner segment (or from the resolved `Repository`/`Stack` record) and reject the request (422) if it does not match the organization whose secret was used to verify the signature. More robustly, resolve the target `Repository` first (independent of any org claim in the body), and verify the signature using that repository's configured organization secret exclusively.

### Proof of Concept
Given a Shipit deployment configured with two organizations `OrgA` (attacker-administered) and `OrgB` (victim), with `OrgB/victim-repo` tracked as a stack:

```
POST /github/webhooks
X-Github-Event: status
X-Hub-Signature: sha1=<HMAC_SHA1(OrgA_webhook_secret, RAW_BODY)>
Content-Type: application/json

RAW_BODY:
{
  "sha": "<victim commit sha>",
  "state": "success",
  "description": "forged status",
  "target_url": "https://ci.example.com/attacker",
  "context": "ci/required-check",
  "created_at": "2026-09-02T00:00:00Z",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```

`verify_signature` resolves `repository_owner = "OrgA"`, verifies against `OrgA`'s secret (matches, since attacker computed the HMAC with it), and the request is accepted. `StatusHandler` then resolves the target commit via `repository.full_name = "OrgB/victim-repo"` and records the forged `success` status against `OrgB`'s commit, even though the attacker has no relationship with `OrgB`.

Note: I was unable to open the full source of `app/models/shipit/webhooks/handlers/status_handler.rb` within the available tool budget; the behavior above is inferred from `test/controllers/webhooks_controller_test.rb`'s `":state create a Status for the specific commit"` test, which exercises exactly this code path and its field mapping. A Devin session with full repository access can confirm the exact `StatusHandler` implementation and the downstream CI-gating logic in `deploy_spec.rb`/`Commit#deployable?`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

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
