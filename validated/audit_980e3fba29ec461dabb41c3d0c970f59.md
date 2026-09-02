### Title
Webhook signature verification is scoped to attacker-supplied `repository.owner.login`, decoupled from the repository whose stack is mutated - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which org's `webhook_secret` to check against using `repository_owner`, a value read straight out of the unauthenticated JSON body. The handlers that actually mutate a `ReviewStack` (e.g. `LabeledHandler`) resolve the target repository independently, from `params.repository.full_name`, with no comparison back to the org that was used to verify the signature. Because `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the resolved org's `webhook_secret` is blank, an attacker can pick any org name that has no configured secret to satisfy `verify_signature`, then point `repository.full_name` at a completely different, secret-protected org's repo to make Shipit act on that org's stack.

### Finding Description
Broken binding, stated as an equality that the code fails to enforce:

`org_used_for_signature = repository_owner (params.dig('repository','owner','login'))`
must equal
`org_owning_mutated_stack = Repository.from_github_repo_name(params.repository.full_name).owner`

but the code never checks this equality.

Path:
1. `before_action :check_if_ping, :drop_unhandled_event, :verify_signature` runs before `create`. [1](#0-0) 
2. `verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` and calls `github_app.verify_webhook_signature(...)`, using only `repository_owner` (attacker-controlled JSON field) to pick the org/secret. [2](#0-1) 
3. `repository_owner` is read directly from the unauthenticated request body: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. [3](#0-2) 
4. `GitHubApp#verify_webhook_signature` short-circuits to `true` when that org's `webhook_secret` is blank/unconfigured: `return true unless webhook_secret`. [4](#0-3) 
5. Once `verify_signature` passes, `create` parses the raw body and dispatches to handlers for the event, passing the full attacker-controlled payload. [5](#0-4) 
6. `LabeledHandler#repository` resolves the actual target repository from `params.repository.full_name` alone - a completely separate JSON field from the one used in step 2/3, with no cross-check against `repository_owner`. [6](#0-5) 
7. `#handle` calls `stack.unarchive!` on a `ReviewStackAdapter` scoped to `repository.review_stacks` (the victim repo's actual review stacks). [7](#0-6) 
8. `ReviewStackAdapter#unarchive!` enqueues real provisioning work and unarchives the real stack: `Shipit::ReviewStackProvisioningQueue.add(stack)` then `stack.unarchive!(*args, &block)`. [8](#0-7) 

Attacker request: a crafted `POST /webhooks` body (no valid signature required) with `X-Github-Event: pull_request`, `action: "labeled"`, `repository.owner.login` set to any org configured in Shipit with a blank `webhook_secret`, and `repository.full_name` set to `"victim-org/victim-repo"` where `victim-org` has `review_stacks_enabled` and `provisioning_behavior_allow_with_label` with the matching label present on the PR. Existing guards do not prevent this: `drop_unhandled_event` only checks the event type is handled; `ExplicitParameters` schemas only validate shape/types of fields, not cross-consistency between `repository.owner.login` and `repository.full_name`'s owner segment; there is no `force_github_authentication`/session check on this unauthenticated webhook endpoint by design; and `Repository` model validations only constrain owner/name character sets, not which org can reference which repository via webhook.

### Impact Explanation
An unauthenticated internet attacker can trigger real, credentialed side effects (`Shipit::ReviewStackProvisioningQueue.add`, `stack.unarchive!`, and downstream provisioning that runs `shipit.yml` steps under Shipit's `GITHUB_TOKEN` for the victim org) against any repository configured in Shipit, as long as at least one configured org anywhere in the installation has a blank `webhook_secret`. This is a payload for one repository (attacker-named org) mutating another repository's stack (victim org) — matching "Critical: a payload for one repository mutating another's stack ... or an unauthorized deploy". It is repeatable against any repository/org combination and is not limited to a single tenant; blast radius spans every org configured in the same Shipit instance.

### Likelihood Explanation
Requires only that one org in the multi-org Shipit configuration has a blank/missing `webhook_secret` (an explicitly stated precondition, and a realistic misconfiguration since `webhook_secret` is optional per-org). No GitHub secrets, session, API token, or team membership is needed — cost is a single crafted HTTP POST with no valid HMAC signature. Fully repeatable and scriptable against arbitrary target repos.

### Recommendation
Bind webhook signature verification to the same repository that will be mutated, not to an attacker-supplied owner field: resolve `repository_owner` from `params.repository.full_name`'s owner segment consistently, and additionally cross-validate that any handler's target repository owner matches the org that authenticated the request. Also, `GitHubApp#verify_webhook_signature` should not silently accept unsigned/blank-secret webhooks as valid — treat a missing configured `webhook_secret` as a hard failure (reject the webhook) rather than `return true`.

### Proof of Concept
Minitest plan (no live GitHub, following the pattern already used in `test/controllers/webhooks_controller_test.rb` and `test/models/shipit/webhooks/handlers/pull_request/labeled_handler_test.rb`):

1. Configure two orgs in test `Shipit.github_apps`/secrets: `attacker-org` with `webhook_secret: nil`, and `victim-org` with a real `webhook_secret`.
2. Create `victim_repo = Repository.create!(owner: "victim-org", name: "victim-repo", review_stacks_enabled: true, provisioning_behavior: "allow_with_label", provisioning_label_name: "deploy-me")` and an archived `ReviewStack` under it matching the PR's `environment`.
3. POST to `/webhooks` with headers `X-Github-Event: pull_request`, and NO valid `X-Hub-Signature` (or an arbitrary bogus one), body: `action: "labeled"`, `repository: { owner: { login: "attacker-org" }, full_name: "victim-org/victim-repo" }`, PR labeled `"deploy-me"`, PR state `"open"`.
4. Assert response is `200 OK` (not `422`), proving `verify_signature` passed using `attacker-org`'s (blank) secret — i.e. `repository_owner == "attacker-org"`.
5. Assert `Shipit::ReviewStackProvisioningQueue.add` was invoked with the `victim-org/victim-repo` stack (`assert_enqueued_with` / mocha `.expects(:add).with(victim_stack)`), and/or `victim_stack.reload.archived?` is now `false` — proving `org_owning_mutated_stack == "victim-org"` while `org_used_for_signature == "attacker-org"`, demonstrating the two sides of the binding diverge.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L6-6)
```ruby
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature
```

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-63)
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
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L37-50)
```ruby
          def unarchive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no ReviewStack exists. Creating."
              )
              return create!
            end
            return unless stack.archived?

            stack.transaction do
              Shipit::ReviewStackProvisioningQueue.add(stack)
              stack.unarchive!(*args, &block)
            end
          end
```
