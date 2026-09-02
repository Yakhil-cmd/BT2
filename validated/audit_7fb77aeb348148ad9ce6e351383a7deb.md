### Title
Webhook signature is verified against `repository.owner.login`, but handlers act on independent, unvalidated fields (`repository.full_name`, `sha`) — allowing cross-organization forgery - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to verify the HMAC signature against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` (or `organization.login`) [1](#0-0) [2](#0-1) . Once the signature is accepted, the actual event handlers determine *what data gets written* using entirely different, independently attacker-controlled fields from the same JSON body — `repository.full_name` for stack resolution [3](#0-2) , or, in the case of `StatusHandler`, only a bare `sha` with no repository scoping at all [4](#0-3) . Nothing enforces that the organization whose secret validated the signature actually matches the organization/repository that gets mutated.

### Finding Description
This mirrors the report's bug class: a verification step (`sweep()`/fee snapshot) is decoupled from the action that trusts its result (`collect()`), so the action ends up using data that was never actually validated. Here, the binding that should hold is:

`organization that authenticated (repository.owner.login, checked in verify_signature) == organization whose data is written (repository.full_name / sha, used inside the handler)`

Before the request: an attacker who legitimately administers their own GitHub organization ("attacker-org") can install the Shipit GitHub App there and thus legitimately knows/derives a valid HMAC signature for any raw payload body, because `verify_webhook_signature` only checks the HMAC against that organization's `webhook_secret` [5](#0-4) .

After the request: the attacker crafts a webhook body where `repository.owner.login` (or `organization.login`) is set to `"attacker-org"` (so `verify_signature` picks and passes against the attacker's own legitimate secret), while other fields inside the same payload point at a victim's data:
- For `push`/pull-request events, `repository.full_name` can be set to `"victim-org/victim-repo"`, which `Handler#stacks` uses via `Repository.from_github_repo_name(repository_name)` to select the *actual* Stack acted upon — completely independent of the org that authenticated the request [3](#0-2) [6](#0-5) .
- For `status` events, there is no repository scoping whatsoever: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` matches by commit SHA across the *entire* database, so any known SHA belonging to any other organization's stack can have a forged commit status written to it [4](#0-3) .

Because the `repository_owner` used for the trust check and the `repository.full_name`/`sha` used for the write are two independently attacker-supplied JSON fields from the same forged payload, the check "did the correct org sign this" never implies "is this org allowed to touch this repo/commit."

### Impact Explanation
High/Critical: an attacker who controls a GitHub organization with the Shipit App installed (an unprivileged attacker with respect to any *other* tenant's repository) can forge `commit_status` webhooks that write CI/deployable statuses onto commits belonging to a different organization's Stack. Since blocking/deployable statuses gate the merge queue and deploy eligibility (`test ":state create a Status for the specific commit"` confirms statuses are created straight from webhook fields with no repo check [7](#0-6) ), this is a cross-repository write that can unblock or spoof CI state for a stack the attacker does not own, enabling an unauthorized merge/deploy decision on another tenant's stack — squarely in the Critical bucket ("cross-repository writes ... an unauthorized deploy, rollback or merge").

### Likelihood Explanation
Medium: it requires the attacker to operate their own GitHub organization with the Shipit App installed (a realistic multi-tenant scenario for this engine, which is explicitly designed to support "Using Multiple GitHub Applications" per multiple organizations sharing one Shipit instance) [8](#0-7) , and to know/guess a target commit SHA in another tenant's stack (SHAs are often public/leaked via PRs, CI logs, etc.).

### Recommendation
Enforce that the organization used for signature verification actually matches the organization implied by the data the handler is about to mutate:
- In `Handler#stacks`/`#repository_name`, verify that the resolved `Repository`'s `owner` equals the `repository_owner` (or `organization.login`) that was used to select the webhook secret in `WebhooksController#verify_signature`, and reject the payload otherwise.
- In `StatusHandler#process`, scope the `Commit` lookup to commits belonging to stacks whose repository owner matches the verified organization, instead of matching by bare `sha` across all repositories.

### Proof of Concept
1. Attacker registers/administers GitHub org `attacker-org` and installs the Shipit GitHub App there, giving them the legitimate `webhook_secret` for `attacker-org` per `config/secrets.yml`'s multi-org layout [8](#0-7) .
2. Attacker learns (via a public PR, CI log, etc.) a commit `sha` belonging to `victim-org/victim-repo`, tracked by that org's Stack.
3. Attacker crafts a `status` webhook body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/some-repo" }
}
```
4. Attacker computes `X-Hub-Signature` using `attacker-org`'s own `webhook_secret` and POSTs to `/webhooks`.
5. `verify_signature` computes `repository_owner` as `"attacker-org"` [2](#0-1) , loads `Shipit.github(organization: "attacker-org")`, and the HMAC check passes because it was signed with the attacker's own valid secret [1](#0-0) .
6. `StatusHandler#process` runs unconditionally against `Commit.where(sha: ...)`, creating a forged status on the victim's commit regardless of which org's secret signed the request [4](#0-3) .

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
