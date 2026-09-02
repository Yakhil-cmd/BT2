### Title
Webhook signature is verified against the organization derived from the payload, but every event handler acts on a different, unchecked `repository.full_name` field - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate the HMAC signature against using `repository_owner`, a value read straight out of the untrusted JSON body (`params.dig('repository','owner','login')` or the `organization.login` fallback). Once the signature check passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` hands the *entire* raw payload to handlers, and every handler (`Handler#repository_name`, used by `PushHandler`, `PullRequest::LabeledHandler`, etc.) resolves the target `Stack`/`Repository` from a completely different field: `payload.dig('repository', 'full_name')`. Nothing ties the organization whose secret validated the signature to the repository/stack the handler subsequently mutates.

### Finding Description
The verification and the mutation sides check different fields of the same attacker-influenced payload:

- Signature/organization selection: `repository_owner` in `app/controllers/shipit/webhooks_controller.rb:59-62`, used to fetch the app config with `Shipit.github(organization: repository_owner)` and verify the HMAC in `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`). [1](#0-0) [2](#0-1) 

- Handler target selection: `Handler#repository_name` reads `payload.dig('repository', 'full_name')`, independent of `repository.owner.login`, to look up the `Repository`/`Stack` that is acted upon. [3](#0-2) 

Because the raw HMAC covers the entire request body, whoever holds the `webhook_secret` for **any** organization configured in a multi-tenant Shipit instance (see `test/dummy/config/secrets_double_github_app.yml`, which configures independent `webhook_secret`s per organization) can sign an arbitrary JSON body themselves. They can set `repository.owner.login` to their own organization (so `verify_signature` picks their own valid secret) while setting `repository.full_name` to a target repository belonging to a *different* organization also tracked by the same Shipit instance. The signature check passes because it is computed over a body the attacker fully controls and signs with their own known secret; the field that the check "trusts" as the identity of the payload (`repository.owner.login`) is never cross-validated against the field the business logic actually consumes (`repository.full_name`).

This breaks the intended binding: `organization whose webhook_secret authenticated the request == repository/stack that the handler subsequently mutates`.

### Impact Explanation
Handlers gated only by `repository.full_name` perform state-changing operations on the resolved `Stack`/`Repository`:
- `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` for every non-archived stack on the resolved branch [4](#0-3) , forcing a sync/refresh cycle on a stack that belongs to an organization the attacker does not control.
- `PullRequest::LabeledHandler#handle` can archive/unarchive review stacks for a repository resolved purely from the forged `repository.full_name` [5](#0-4) .
- `StatusHandler#process` writes GitHub commit statuses for any `Commit` matching the attacker-supplied `sha`, without any organization/repository ownership check on the commit itself [6](#0-5) , and commit statuses gate CI-based deploy eligibility elsewhere in the engine.

An attacker who legitimately administers one org's GitHub App integration (and thus knows/owns that org's `webhook_secret`) can therefore cross into a second, unrelated org's repositories/stacks that are configured on the same Shipit instance - forcing syncs, injecting fabricated commit statuses that unblock deploy gating, or archiving/unarchiving review stacks - none of which their credentials should authorize. This crosses the "cross-repository writes" / unauthorized state-change bar for a multi-tenant Shipit deployment.

### Likelihood Explanation
Exploitation requires only a webhook secret for *some* organization configured on the target Shipit instance - not access to the victim organization at all. Any GitHub App owner integrated with a shared, multi-org Shipit deployment (the documented and tested topology, per `test/dummy/config/secrets_double_github_app.yml`) already meets this bar. No repository write access, Shipit session, or `ApiClient` token is needed; the request is a plain unauthenticated POST to `/webhooks` with a self-signed body.

### Recommendation
After signature verification succeeds, re-derive `repository_owner`/organization strictly from the same field used to select the verifying secret, and reject the payload if `repository.full_name`'s owner segment does not match the organization that authenticated the request (i.e., cross-check `repository.full_name.split('/').first == repository_owner` before dispatching to handlers). Alternatively, look up the target `Repository`/`Stack` and confirm its configured GitHub organization equals the organization whose `webhook_secret` validated the signature before invoking any handler.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`). Attacker administers `OrgA`'s GitHub App and knows `OrgA`'s `webhook_secret`.
2. Attacker crafts a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha>",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` calls `Shipit.github(organization: 'OrgA')` and validates successfully against `OrgA`'s secret [1](#0-0) .
5. `PushHandler` resolves the target stack via `Repository.from_github_repo_name('OrgB/victim-repo')` [3](#0-2)  and triggers `sync_github` on `OrgB`'s stack, even though the request was never signed by anything belonging to `OrgB`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-68)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
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
