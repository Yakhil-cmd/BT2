### Title
Webhook signature verified against attacker's own organization's secret while the repository actually mutated is taken from an unverified `full_name` field, allowing cross-tenant status/event forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to check the HMAC signature against using `repository_owner`, which is read straight from the untrusted JSON body (`repository.owner.login` or `organization.login`). Every event handler, however, resolves which `Stack`/`Repository` record to act on using a *different* payload field, `repository.full_name`, which is never cross-checked against `repository_owner`. An organization that is itself a legitimately configured Shipit tenant (and therefore knows its own valid `webhook_secret`) can therefore sign a payload with its own secret while setting `repository.full_name` to point at a repository belonging to a different, unrelated tenant/organization on the same Shipit instance, and have that event processed as if GitHub itself had sent it for the victim repository.

### Finding Description
Signature verification happens before any per-event dispatch: [1](#0-0) 

The org used to pick the verification secret comes from the payload body itself: [2](#0-1) 

Once the signature check passes, the raw, attacker-controlled `params` are handed unchanged to every registered handler: [3](#0-2) 

Every handler resolves the target `Stack`(s) using an independent field of the same payload, `repository.full_name`, with no re-validation against the organization that was actually authenticated: [4](#0-3) 

This breaks the equality the deployment-trust model relies on: `organization whose secret verified the signature == organization/repository whose Stack records are mutated`. `Shipit.github(organization: repository_owner)` only proves that *some* org configured in Shipit (which could be the attacker's own onboarded org/tenant, complete with its own valid `webhook_secret`) produced a validly-signed payload; it proves nothing about which repository `full_name` in that same payload refers to. `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, `CommitDeploymentHandler`, etc. all trust `full_name` unconditionally to select the `Stack` to operate on: [5](#0-4) 

The `status` webhook path illustrates concrete state corruption: it copies GitHub-status fields directly out of the payload onto the matched commit without any independent verification against GitHub's API, as shown by the corresponding test asserting the payload's `state`, `description`, `target_url`, and `context` are persisted verbatim: [6](#0-5) 

### Impact Explanation
Any organization already onboarded as a Shipit "tenant" (i.e. any org for which the operator has configured a `github_app`/`webhook_secret`, per `lib/shipit/github_app.rb`) can forge events for *any other* tenant's repository tracked by the same Shipit instance, because the signing secret is selected from the same untrusted JSON that also carries the target-repository field. Most severely, forging a `status` event lets the attacker inject an arbitrary passing CI status (`state: "success"`) on a victim's commit. Since Shipit's deploy gating (`required_statuses`/`blocking_statuses` in `DeploySpec`) and continuous-delivery scheduling rely on stored `Status` records reflecting real CI state, this can cause an untested/failing commit to appear deployable and be shipped automatically or by an unwitting operator — i.e., an unauthorized deploy of a cross-tenant repository, which falls squarely in the Critical impact bucket ("an unauthorized deploy"). It can also be used to spuriously trigger `sync_github` / check-run refresh cycles against a victim stack.

### Likelihood Explanation
Exploitation requires only that the attacker control one legitimately configured Shipit organization/tenant (with its own valid `webhook_secret`) — no repository write access, no Shipit session, and no privileged Shipit account are needed, satisfying the "unprivileged attacker" bar. The only prerequisite is that the Shipit deployment tracks repositories/organizations for more than one independent party (the intended multi-tenant use case the per-organization `webhook_secret`/`oauth` configuration in `lib/shipit/github_app.rb` is built for). Given that, forging the payload is trivial: sign it with the attacker's own secret and set `repository.full_name` to the victim's repo.

### Recommendation
After signature verification, re-derive `repository_owner` from `repository.full_name` (the same field used by `Handler#repository_name`) and require it to match the organization whose secret validated the signature, rejecting the request otherwise. Equivalently, `Handler#stacks`/`#repository_name` should verify that the resolved `Repository#owner` equals the organization that authenticated the webhook before dispatching to any handler.

### Proof of Concept
1. Attacker controls organization `evil-org`, which is a legitimately configured Shipit tenant with its own `webhook_secret` (`S_evil`).
2. Attacker crafts a `status` webhook payload:
   ```json
   {
     "repository": { "full_name": "victim-org/victim-repo", "owner": { "login": "evil-org" } },
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "ci/required-check",
     "target_url": "https://ci.example.com/fake"
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(S_evil, raw_body)>` and POSTs to `/webhooks`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "evil-org")` and successfully verifies the signature using `S_evil` (app/controllers/shipit/webhooks_controller.rb:24-30, 59-62).
5. `Shipit::Webhooks.for_event('status').each { |handler| handler.call(params) }` runs `StatusHandler`, which resolves the target stack via `payload.dig('repository','full_name') == "victim-org/victim-repo"` (app/models/shipit/webhooks/handlers/handler.rb:32-38), and persists a forged passing status on `victim-org/victim-repo`'s commit, as demonstrated by the direct field copy in the existing test (test/controllers/webhooks_controller_test.rb:42-59).
6. If `victim-org/victim-repo`'s stack gates deploys/continuous-delivery on that status context, the forged "success" status can cause an unauthorized deploy of an unreviewed or failing commit.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-18)
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
