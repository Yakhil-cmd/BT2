### Title
Webhook signature is verified against `repository.owner.login`/`organization.login`, but handlers act on the unrelated `repository.full_name` — allowing a signature valid for one GitHub organization to write commit statuses / trigger syncs for a completely different, unrelated repository - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and therefore which `webhook_secret`) to verify the HMAC signature with, based on `repository.owner.login` (falling back to `organization.login`). Every downstream `Webhooks::Handlers::Handler` subclass, however, resolves *which stacks to mutate* using an entirely different, unauthenticated field of the same payload: `repository.full_name`. Nothing ties these two fields together, so a payload whose `repository.owner.login`/`organization.login` names one organization while `repository.full_name` names a repository under a different organization will be "verified" using the first organization's secret, then acted upon as if it belonged to the second.

### Finding Description
`verify_signature` computes the signing organization solely from: [1](#0-0) 
```
def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
and uses it to fetch the app config and verify the raw body against that org's `webhook_secret`: [2](#0-1) 

Crucially, `GitHubApp#verify_webhook_signature` treats an **unset** `webhook_secret` as automatically valid: [3](#0-2) 
```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```
`config/secrets.*.yml` examples ship with `webhook_secret:` left blank/optional per organization in multi-org setups: [4](#0-3) 

Meanwhile, every webhook handler resolves the target repository from a *different* JSON field that is never compared against `repository_owner`: [5](#0-4) 
```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```
`PushHandler` uses `stacks` to enqueue a real `GithubSyncJob` against whatever stack matches `repository.full_name`: [6](#0-5) 

And `Repository.from_github_repo_name` performs a straight DB lookup with no ownership cross-check: [7](#0-6) 

**Binding broken:** `authenticating_organization (repository.owner.login / organization.login)` should equal `owning_organization(repository.full_name)` for every handler action, but this equality is never enforced anywhere in `WebhooksController` or `Handler`.

### Impact Explanation
In a multi-organization Shipit deployment (the documented "Using Multiple Github Applications" configuration), if *any* onboarded organization has a blank/unset `webhook_secret` (shown as the default/optional value in the shipped example secrets files), an unprivileged actor who can send a request to `/webhooks` claiming `repository.owner.login` = that blank-secret org will pass `verify_signature` unconditionally (`return true unless webhook_secret`), regardless of the actual `X-Hub-Signature` value. They can then set `repository.full_name` to any **other** organization's real repository tracked by the Shipit instance, causing:
- `status`/`commit_status` events to write forged `Status` rows (state, context, target_url) onto a real commit of a repository the attacker has no access to — this can be used to falsify a required CI check used to gate deploys or the merge queue, i.e. an unauthorized deploy/merge path via `Ticks... ` — concretely `merge_request_required_statuses`/`deployable?` checks rely on `Status`/`Statuses` records.
- `push` events forcing `GithubSyncJob` to run against a victim stack (`PushHandler#process`).

This is a cross-repository write performed with a signature that was never actually validated against the payload's claimed target repository — matching the report's "authentication crosses a trust boundary it shouldn't" bug class.

### Likelihood Explanation
Requires: (1) a multi-org Shipit deployment, and (2) at least one onboarded organization configured without a `webhook_secret` (the documented default/example value). Given the setup docs explicitly present `webhook_secret:` as optional per-org, this is a plausible, easy-to-hit misconfiguration rather than a contrived edge case, and no privileged credential (session, ApiClient token, GitHub App private key) is required by the attacker — only knowledge that Shipit is multi-tenant and that one tenant has no webhook secret.

### Recommendation
- Require `webhook_secret` to be present for every configured organization in multi-org mode (fail closed instead of `return true unless webhook_secret`).
- Enforce that the organization used to verify the signature is the same organization that owns `repository.full_name` (and `organization.login` when present), rejecting the webhook with 422 otherwise.
- Extract the "owner" segment from `repository.full_name` in `WebhooksController#repository_owner` and cross-check it against `params.dig('repository','owner','login')`/`params.dig('organization','login')` before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two organizations: `victim-org` (proper `webhook_secret`) and `blank-org` (no `webhook_secret` set, per the documented optional field).
2. Send `POST /webhooks` with header `X-Github-Event: status` (or `push`) and no valid `X-Hub-Signature` for `victim-org`, but body:
```json
{
  "repository": { "owner": { "login": "blank-org" }, "full_name": "victim-org/victim-repo" },
  "sha": "<real commit sha in victim-org/victim-repo>",
  "state": "success",
  "context": "<required-ci-context>",
  "target_url": "https://attacker.example/fake",
  "branches": [{"name": "master"}]
}
```
3. `verify_signature` calls `Shipit.github(organization: "blank-org")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` without checking the signature at all.
4. `StatusHandler` (via `Handler#stacks`/`#repository_name`) resolves the target using `repository.full_name = "victim-org/victim-repo"`, and creates a `Status` on the real commit as if it came from `victim-org`'s verified webhook — demonstrated by the existing test flow at [8](#0-7) .

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

**File:** config/secrets.development.shopify.yml (L5-23)
```yaml
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
