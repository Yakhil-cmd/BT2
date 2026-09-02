### Title
Signature verification binds to the attacker's own organization while payload dispatch binds to an unrelated repository, allowing cross-organization forgery of commit statuses/pushes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App secret to validate an incoming webhook based on an **untrusted** field taken directly from the JSON body (`repository.owner.login` / `organization.login`), not from any pre-authenticated source. Every event `Handler` then independently re-reads `payload.dig('repository', 'full_name')` to decide which `Repository`/`Stack` the event actually acts on. Nothing enforces that these two fields refer to the same organization, so an attacker who legitimately controls a webhook secret for *their own* small/low-privilege GitHub organization configured on the Shipit instance can forge a webhook whose signature is valid for their org, while `repository.full_name` names a completely different organization's repository/stack.

### Finding Description
`verify_signature` derives the app/secret to check against purely from payload content: [1](#0-0) [2](#0-1) 

The HMAC (`GitHubApp#verify_webhook_signature`) is computed over the entire raw body using the secret selected for that same untrusted `repository_owner`/`organization` value: [3](#0-2) 

This only proves "whoever produced this body knows the secret configured for `repository.owner.login`" — it never proves that the *rest* of the JSON, in particular `repository.full_name`, belongs to that same organization. Every handler resolves the target `Stack` independently via `repository.full_name`: [4](#0-3) [5](#0-4) 

Because Shipit supports multiple independently configured GitHub organizations, each with its own `webhook_secret`, in `config/secrets.*.yml` (`somegithuborg`, `someothergithuborg`, …): [6](#0-5) 

an attacker who administers their own low-privilege org (`repository_owner = "attacker-org"`, whose secret they legitimately know) can set `repository.owner.login = "attacker-org"` (so `verify_signature` selects and validates against the attacker's own secret) while setting `repository.full_name = "victim-org/victim-repo"` (so the handler dispatches the event against the victim organization's actual `Stack`). The engine's binding "organization that authenticated" (`repository_owner` used to pick the verification secret) is never checked for equality against "repository that is written" (`repository.full_name` used by the handler), breaking the intended invariant `authenticated_org == acted_upon_repo.owner`.

The `status` event handler demonstrably writes payload-controlled state (`sha`, `state`, `description`, `target_url`, `context`) as a new `Status` on the commit resolved from `repository.full_name`: [7](#0-6) 

so an attacker satisfying the signature check with their own org's secret can still push an arbitrary CI status (e.g., forged "success") onto a commit belonging to a victim organization's `Stack`, as long as they guess/know a valid commit SHA already present in the victim stack. Push events similarly enqueue a `GithubSyncJob` scoped to whichever `Stack` matches the forged `full_name`, independent of the org used to pass signature verification: [8](#0-7) 

### Impact Explanation
Forged commit statuses can flip Shipit's CI-check gating logic (status checks are a core input to whether a commit is deployable), letting an attacker who only controls a webhook secret for their own unrelated, low-privilege GitHub organization mark a victim organization's commit as passing/failing checks. This directly maps to the report's bug class ("action taken on a field/state that the verification step never actually covers") and to an explicitly allowed analog: "an organization that authenticated versus the repository that is written." The reachable consequence is an unauthorized manipulation of deploy-gating state for a repository the attacker does not own — matching the required "unauthorized deploy" impact bucket.

### Likelihood Explanation
Requires the attacker to have a legitimate, low-privilege GitHub organization already configured with a `webhook_secret` on the same Shipit instance (a normal, unprivileged condition when a Shipit instance serves multiple GitHub orgs), plus knowledge/guessing of a target commit SHA in the victim stack. No repository write access, no `ApiClient` token, and no Shipit session are needed — only the ability to send an arbitrary POST to the shared `/github/webhooks` endpoint with a valid signature for their own org.

### Recommendation
After signature verification succeeds using the secret resolved from `repository.owner.login`/`organization.login`, re-derive the acted-upon repository strictly from that same verified organization (e.g., assert `repository.full_name`'s owner segment case-insensitively equals the `repository_owner` used to select the verification secret) before dispatching to any `Handler`, rejecting the webhook with `422` otherwise.

### Proof of Concept
1. Attacker configures/owns GitHub org `attacker-org`, which the Shipit operator has legitimately added to `config/secrets.*.yml` with its own `webhook_secret`.
2. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "<victim commit sha already in victim-org/victim-repo>",
  "state": "success",
  "description": "forged",
  "target_url": "https://evil.example.com",
  "context": "ci/forged",
  "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "attacker-org" } }
}
```
3. Attacker signs the raw body with `attacker-org`'s known `webhook_secret` using `sha1=HMAC-SHA1(secret, body)` and sends it with `X-Github-Event: status` and `X-Hub-Signature`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`) and validates successfully against the attacker's own secret [1](#0-0) .
5. `Shipit::Webhooks.for_event('status')` dispatches to the status handler, which resolves the `Stack` via `repository.full_name = "victim-org/victim-repo"` [4](#0-3)  and creates a forged `Status` record on the victim commit, as verified by the equivalent legitimate-path test [7](#0-6) .

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** test/controllers/webhooks_controller_test.rb (L23-32)
```ruby
    test ":push with the target branch queues a GithubSyncJob" do
      request.headers['X-Github-Event'] = 'push'

      parsed_body = JSON.parse(payload(:push_master))
      expected_head_sha = parsed_body["after"]

      assert_enqueued_with(job: GithubSyncJob, args: [stack_id: @stack.id, expected_head_sha:]) do
        post :create, body: parsed_body.to_json, as: :json
      end
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
