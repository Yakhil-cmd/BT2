### Title
Cross-organization webhook forgery via decoupled signature-org and dispatch-repository fields - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate a request against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` (or `params.dig('organization', 'login')`) [1](#0-0) [2](#0-1) . Once the signature passes, every event handler resolves the actual `Stack`/`Repository` to act on from a *different* field of the same untrusted JSON body: `payload.dig('repository', 'full_name')` [3](#0-2) . Nothing in the code enforces that `repository.owner.login` (the field that selected the signing secret) is the owner encoded in `repository.full_name` (the field that selects the write target). This breaks the binding: "organization whose secret authenticated the request" = "organization whose repository/stack is written."

### Finding Description
Shipit explicitly supports hosting multiple GitHub organizations on one instance, each with its own `webhook_secret` [4](#0-3) . `Shipit.github(organization: repository_owner)` picks the `GithubApp` (and thus the HMAC secret) to verify `X-Hub-Signature` against, based purely on the attacker-supplied `repository.owner.login`/`organization.login` field [1](#0-0) .

The HMAC signature only proves "this raw body was signed with OrgA's secret" — it says nothing about which other fields inside that same body are trustworthy relative to OrgA. Every handler, however, derives the actual write target from a sibling field, `repository.full_name` [3](#0-2) , used identically across `PushHandler`, pull-request handlers, etc. [5](#0-4) [6](#0-5) . There is no check that `repository.full_name`'s owner segment matches `repository.owner.login`.

Consequently, anyone who legitimately possesses (or is later handed/rotated) OrgA's `webhook_secret` — a routine credential for any org onboarded onto the shared Shipit instance, not an OrgB privilege — can sign a POST to `/webhooks` where `repository.owner.login = "OrgA"` (so verification passes against OrgA's secret) but `repository.full_name = "OrgB/victim-repo"` (so the handler resolves and mutates OrgB's `Stack`/`Repository`). Handlers such as the `status`/`check_run` handlers persist payload-provided fields (state, description, target_url, created_at) directly onto the resolved commit without re-querying GitHub, as shown by the equivalent test assertions [7](#0-6) , so an OrgA-secret holder can inject a fabricated green CI status onto an OrgB commit it has no access to, or trigger `GithubSyncJob`/`ReviewStack` provisioning against OrgB's stack via the push/pull_request paths [8](#0-7) .

### Impact Explanation
This is a cross-repository/cross-organization write: an entity trusted only for OrgA's webhook channel can forge CI status/check state and trigger sync/provisioning actions against a completely unrelated OrgB's `Stack`, without any GitHub write access to OrgB's repository. Forged "success" statuses can unblock Shipit's CI-gating and merge-queue logic, leading to an unauthorized deploy of code that never actually passed CI — matching the report's underlying bug class of "a permission/authentication boundary asserted for one entity being silently reused to act on a different entity's resource."

### Likelihood Explanation
Exploitability requires only possession of a valid `webhook_secret` for *any one* organization configured on the shared Shipit instance — not privileged access to the victim organization, and not a Shipit session/API token. Any customer/tenant onboarded with their own GitHub App on a multi-org Shipit deployment (a documented, supported configuration) can craft and POST this payload directly to the public `/webhooks` endpoint.

### Recommendation
When resolving the target repository/stack in `Shipit::Webhooks::Handlers::Handler#repository_name` (and anywhere `repository.full_name` is used), verify that its owner segment equals the `repository_owner`/`organization` value that was used to select and validate the signature, e.g.:
```ruby
def repository_name
  full_name = payload.dig('repository', 'full_name')
  owner = full_name&.split('/', 2)&.first
  raise Shipit::GithubOrganizationUnknown, owner unless owner&.casecmp?(verified_organization)
  full_name
end
```
and thread the organization verified during `verify_signature` through to the handler dispatch so the two are cryptographically and logically tied together, rejecting any payload where they diverge.

### Proof of Concept
1. Attacker controls/knows the `webhook_secret` configured for `OrgA` on a shared Shipit instance that also hosts `OrgB` (multi-org config per `docs/setup.md`).
2. Attacker crafts a `status` (or `push`) webhook body:
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" },
  "sha": "<OrgB commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "branches": [{ "name": "main" }]
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(OrgA_webhook_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: "OrgA")`, whose secret matches → request accepted [1](#0-0) .
5. The status handler resolves the stack via `Repository.from_github_repo_name("OrgB/victim-repo")` [3](#0-2)  and writes a forged "success" `Status` for OrgB's commit, which OrgB's Shipit instance may treat as satisfying CI requirements for deploy/merge.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
  end
end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
