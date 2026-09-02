### Title
Cross-repository webhook forgery via organization/repository binding mismatch - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to verify a webhook against using an **unverified** field of the same payload (`repository.owner.login`), while the downstream event handlers act on a **different** field (`repository.full_name`) to decide which `Stack`/`Repository` to mutate. Because these two fields are never cross-checked, an attacker who can produce (or who is handed, via a permissively configured multi-org install) a valid signature for *any one* configured GitHub organization can forge webhook events that write state (commits, commit statuses) for a completely unrelated repository/organization.

### Finding Description
`WebhooksController#verify_signature` picks the signing secret to check against based on `repository_owner`, which is read straight out of the untrusted JSON body before the signature has been validated: [1](#0-0) [2](#0-1) 

The signature is then checked against that organization's app config only: [3](#0-2) 

Note that if the selected organization has no `webhook_secret` configured — a state explicitly documented and supported for multi-org installs — `verify_webhook_signature` returns `true` unconditionally, i.e. **any** payload passes for that organization regardless of the `X-Hub-Signature` header: [4](#0-3) 

Once `verify_signature` passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the raw parsed body to handlers. Handlers resolve the target `Stack`/`Repository` from an entirely different payload field, `repository.full_name`, with no cross-check against the `repository.owner.login` value that was used to select the verification secret: [5](#0-4) [6](#0-5) 

This breaks the intended trust binding: **organization authenticated (`repository.owner.login`, used to pick the verification secret) ≠ repository actually written (`repository.full_name`, used to pick the target `Stack`)**.

### Impact Explanation
An attacker who knows (or who benefits from) a webhook secret for any one organization configured in this Shipit instance — including an organization deliberately left with `webhook_secret: nil` per the documented multi-org config schema — can set `repository.owner.login` to that organization (to pass/bypass `verify_signature`) while setting `repository.full_name` to point at a completely different, unrelated stack's repository. Handlers such as the `status` handler then act on that unrelated stack, e.g. creating a `Status` record for an arbitrary commit sha as observed in existing test coverage: [7](#0-6) 

and the `push` handler enqueues a `GithubSyncJob` for the resolved stack based on the forged `repository.full_name`: [8](#0-7) 

Since commit statuses gate Shipit's safety/CI checks and continuous-delivery decisions, an attacker able to forge a passing status for a commit on a victim stack can influence whether that commit is treated as deployable, i.e. this crosses into unauthorized manipulation of a repository/stack the attacker does not control — a cross-repository write consistent with the required impact bar.

### Likelihood Explanation
This requires the deployment to have more than one GitHub organization configured (a documented, supported configuration) and for the attacker to know or exploit one organization's webhook secret (or for one org to have no secret set, which the shipped example config explicitly shows as a valid value). This is not a purely theoretical corner case — it is a direct consequence of code that separates the field used for authentication from the field used for authorization of the write target, exactly analogous to the reported MetaSwap issue where a component that received trust (approval) was different from the component that acted on funds.

### Recommendation
After `verify_signature` succeeds, the controller/handlers should re-derive the organization from the same authenticated field (`repository_owner`) and enforce that `repository.full_name`'s owner segment matches `repository_owner` before any handler is allowed to look up or mutate a `Stack`/`Repository`. Alternatively, resolve the target `Repository` from the verified organization context rather than trusting `repository.full_name` independently.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `orgA` (secret unset/`nil`) and `orgB` (victim, with a real stack).
2. POST to `/github/webhooks` (webhook endpoint) with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  "branches": [{"name": "master"}]
}
```
3. `verify_signature` resolves `repository_owner` = `orgA`, whose `webhook_secret` is unset, so `verify_webhook_signature` returns `true` regardless of the (even absent) `X-Hub-Signature` header.
4. The `status` handler resolves the target stack via `repository.full_name` = `orgB/victim-repo` and creates a `Status` record for the victim's commit, even though the request was never authenticated for `orgB`.

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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
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
