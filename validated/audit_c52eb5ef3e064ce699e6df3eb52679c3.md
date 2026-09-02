### Title
Webhook signature authenticates the organization, but every handler acts on an independently-controlled `repository.full_name` field — cross-organization status/deploy forgery - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate the HMAC against using `repository.owner.login` (or `organization.login`) taken from the unverified JSON body. [1](#0-0) [2](#0-1)  Every event handler, however, resolves the target `Stack`/`Repository` from a *different* field of the same body, `repository.full_name`, with no check that its organization prefix matches the organization whose secret produced a valid signature. [3](#0-2) 

### Finding Description
`Shipit.github(organization: repository_owner)` is used purely to pick which configured GitHub App/secret to verify the HMAC against; `repository_owner` comes straight from the payload. [1](#0-0)  Once the signature passes, `WebhooksController#create` dispatches the *entire* payload to `Shipit::Webhooks.for_event(event)` handlers. [4](#0-3) 

All handlers inherit `Handler#stacks`/`#repository_name`, which look up the acted-upon `Repository` solely from `payload.dig('repository', 'full_name')` — a field never cross-checked against `repository_owner`/the org whose secret validated the request. [3](#0-2)  For example, `PushHandler#process` triggers `stack.sync_github` for every non-archived stack matching the branch on that looked-up repository, and the status webhook path creates a `Status`/commit status row for whatever commit `sha` the payload names, keyed only by that repository lookup, as exercised in `test/controllers/webhooks_controller_test.rb`. [5](#0-4) [6](#0-5) 

This reproduces the report's bug class: a value used to authorize/authenticate an action (`repository_owner`, which selects the webhook secret) is never bound, by equality check, to the value that determines what is actually written (`repository.full_name`, which selects the `Repository`/`Stack`). The equality that should hold — `organization(repository_owner) == organization(repository.full_name)` — is never enforced. An attacker who administers their own GitHub organization/App installation on the same Shipit instance (and thus legitimately possesses a valid `webhook_secret` for *their own* org) can craft a payload where `repository.owner.login` is their own org (so the correct secret is selected and the HMAC verifies) while `repository.full_name` names a *different* organization's repository/stack tracked by the same Shipit deployment.

### Impact Explanation
Because the HMAC only proves "this body was signed with Org A's secret," not "this body pertains to Org A's repositories," an Org-A-privileged webhook sender can push a validly-signed payload whose `repository.full_name` points at Org B. Depending on event type this allows: forging commit statuses (`status` event) for Org B commits — which feed `deployable_status`/`merge_status` gating used to permit deploys — or forcing `sync_github` resyncs on Org B's stacks (`push` event). Forged passing statuses on a target repository's commits can result in an unauthorized deploy being permitted for a stack the attacker does not otherwise control, matching the "unauthorized deploy" Critical-impact criterion.

### Likelihood Explanation
Exploitation requires the attacker to control a legitimate GitHub App installation/webhook secret for at least one organization configured on the shared Shipit instance — a real but plausible scenario in multi-tenant Shipit deployments (`config/secrets.yml` supports multiple orgs, each with its own `webhook_secret`, as documented in `docs/setup.md`). [7](#0-6)  No GitHub write access, Shipit session, or API token is needed — only the ability to send an HTTP POST with a valid signature computed from a secret the attacker legitimately owns.

### Recommendation
In `Handler#repository_name`/`#stacks`, or centrally in `WebhooksController#verify_signature`, assert that the organization used to select the webhook secret (`repository_owner`) equals the organization prefix of `repository.full_name` (and of `organization.login` when present) before dispatching to any handler; reject the request (422) on mismatch.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` and `OrgB`, each with a distinct `webhook_secret` (supported per `test/dummy/config/secrets_double_github_app.yml`). [8](#0-7) 
2. As an actor who legitimately controls `OrgA`'s GitHub App/webhook secret, build a `status` (or `push`) event payload with:
   - `repository.owner.login` = `"OrgA"` (so `verify_signature` selects `OrgA`'s secret) [9](#0-8) 
   - `repository.full_name` = `"OrgB/target-repo"`, `sha` = a commit on an `OrgB`-tracked stack, `state` = `"success"`
3. Sign the raw body with `OrgA`'s `webhook_secret` and POST to `/webhooks` with `X-Hub-Signature`; `verify_webhook_signature` succeeds because it only checks the HMAC against the secret selected in step 2. [10](#0-9) 
4. `Handler#stacks` resolves `OrgB/target-repo` and the handler creates a forged commit status / triggers a sync on `OrgB`'s stack, despite the request only being authenticated for `OrgA`. [3](#0-2)

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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-20)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S
        73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG
        M0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv
        ibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu
        pQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s
        Gu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1
        u0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM
        TZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b
        qicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og
        qRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI
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
