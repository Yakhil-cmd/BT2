### Title
Webhook signature verification org (`repository_owner`) is never checked against the mutated repository (`repository.full_name`), allowing cross-repository stack forgery via `UnlabeledHandler` - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` picks which organization's webhook secret to use for HMAC verification from `params.dig('repository','owner','login') || params.dig('organization','login')`, while `UnlabeledHandler` resolves the actually-mutated repository/stack from the independent `params.repository.full_name` field. No code checks that these two attacker-controlled fields refer to the same organization/repository, so a payload that verifies against one organization's secret can still target and mutate a completely different repository's review stack.

### Finding Description
The broken binding, stated explicitly: the code implicitly assumes
`org_of(repository_owner) == org_of(params.repository.full_name)`
but this equality is never enforced anywhere in the request path.

- `repository_owner` is computed purely from the JSON body: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) , and used only to pick which `GitHubApp` (and thus which `webhook_secret`) validates the HMAC signature [2](#0-1) .
- `verify_webhook_signature` explicitly returns `true` (skips verification) if that organization's `webhook_secret` is blank/unconfigured: `return true unless webhook_secret` [3](#0-2) .
- `UnlabeledHandler` never looks at `repository_owner`/`organization.login` at all. It resolves the target repository strictly from `params.repository.full_name`: `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [4](#0-3) , then resolves the stack via a `ReviewStackAdapter` scoped to that repository's review stacks [5](#0-4) , and finally calls `stack.archive!` or `stack.unarchive!` based on the PR's labels [6](#0-5) .

Exploit flow: an attacker crafts one `pull_request`/`action=unlabeled` JSON body containing `organization.login` (or `repository.owner.login`) set to some organization X that Shipit has onboarded with no `webhook_secret` configured (or one the attacker otherwise knows), and `repository.full_name` set to `"victim-org/victim-repo"` — an entirely unrelated repository whose review stack has `merge_queue_enabled: true`. `verify_signature` authenticates the request against organization X's (missing) secret and passes, but `UnlabeledHandler` then archives or unarchives the victim's review stack based on the (attacker-controlled) `pull_request.labels` in the same forged payload. Existing guards (`drop_unhandled_event`, `ExplicitParameters` schema requiring `repository.full_name`, `check_if_ping`) do not perform any cross-field consistency check between `repository_owner` and `repository.full_name`, so none of them block this.

Note: I was not able to trace, within this investigation, the exact downstream code that ties stack `archive!`/`unarchive!` to merge-queue processing/`merge!` invocation (that logic lives outside the files inspected here), so the specific "green head advances the queue and `merge!` fires" amplification step described in the question is plausible given `merge_queue_enabled` stacks resume/pause activity on archive state, but is not independently confirmed in this trace. The core forgery — a payload authenticated for one organization mutating an unrelated repository's stack — is confirmed directly in the code above and already satisfies the "payload for one repository mutating another's stack" Critical criterion on its own.

### Impact Explanation
An attacker who controls (or can name) any Shipit-onboarded organization with a blank/unset `webhook_secret` can forge a single HTTP POST to `/webhooks` that archives or unarchives any other organization's review stack, identified solely by `repository.full_name`, which they fully control in the JSON body. This is a cross-tenant integrity violation ("a payload for one repository mutating another's stack") — repeatable against any repository/stack reachable via `Repository.from_github_repo_name`, and not limited to `UnlabeledHandler`: any handler that resolves its target purely from `repository.full_name` (independent of `repository_owner`) is equally exposed to this same organization/repository confusion at the controller layer.

### Likelihood Explanation
Preconditions: (1) at least one organization/installation is configured in Shipit without a `webhook_secret` (or the attacker otherwise knows/leaks one org's secret), and (2) the victim repository has review-stacks enabled with a matching review stack for the targeted PR/branch. Given those, the attack is a single unauthenticated HTTP request with no GitHub credentials, session, or API token required — cost is trivial and fully repeatable/scriptable against any repository name.

### Recommendation
Bind signature verification to the actual mutated resource: require that `repository.owner.login`/`organization.login` used to select the verifying `GitHubApp`/secret matches the organization portion of `repository.full_name` used by handlers, and reject the request (422) on mismatch. Additionally, do not allow `verify_webhook_signature` to silently pass (`return true unless webhook_secret`) for organizations lacking a configured secret — treat a missing secret as a hard configuration error/rejection rather than an implicit bypass.

### Proof of Concept
minitest plan (`test/controllers/shipit/webhooks_controller_test.rb`-style, no live GitHub):
1. Configure two organizations in `Shipit.github`: `"attacker-org"` with `webhook_secret: nil`, and `"victim-org"` with a real secret.
2. Create `victim_repo = Shipit::Repository.create!(name: "victim-repo", owner: "victim-org", review_stacks_enabled: true, provisioning_behavior: "prevent_with_label")` and an associated `review_stack` with `merge_queue_enabled: true` and status `active`.
3. Build a `pull_request`/`action=unlabeled` payload with `organization: { login: "attacker-org" }`, no `repository.owner`, `repository: { full_name: "victim-org/victim-repo" }`, `pull_request.labels: []` (no provisioning label), `pull_request.state: "open"`.
4. POST to `/webhooks` with `X-Github-Event: pull_request` and any/garbage `X-Hub-Signature` (or omitted).
5. Assert response is `200 OK` (verification bypassed because `attacker-org` has no `webhook_secret`).
6. Assert, as the explicit equality check: before the request, `victim_stack.archived? == false`; after the request, `victim_stack.reload.archived? == true` — i.e. the stack owned by `victim-org` (never named in `repository_owner`) was mutated by a payload that authenticated as `attacker-org`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L49-57)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L59-63)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L65-69)
```ruby
          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```
