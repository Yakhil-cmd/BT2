### Title
Webhook signature is verified against `repository.owner.login` while the handler acts on `repository.full_name`, letting a payload authenticated as a no-secret org provision a `ReviewStack` for an unrelated victim repository - (File: app/controllers/shipit/webhooks_controller.rb, lib/shipit/github_app.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App config (and thus the HMAC secret) using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')`, an attacker-controlled JSON field. `OpenedHandler`, however, resolves the target repository/stack from a different attacker-controlled field, `params.repository.full_name`. Nothing binds these two fields together, so a payload can claim to originate from one (unsecured) org for signature purposes while actually targeting another (secured) org's repository/stack.

### Finding Description
The broken binding: the code implicitly assumes `repository_owner == owner_segment(repository.full_name)`, but no equality check enforces it.

- `verify_signature` in [1](#0-0)  computes `repository_owner` from `params.dig('repository', 'owner', 'login')` [2](#0-1)  and passes it to `Shipit.github(organization: repository_owner)` to pick the app config used for `verify_webhook_signature`.
- `GitHubApp#verify_webhook_signature` in [3](#0-2)  explicitly returns `true` and skips HMAC verification entirely `unless webhook_secret` is configured for that resolved org, and otherwise only accepts the legacy `sha1=` algorithm prefix.
- `Shipit.github` in multi-org mode resolves the config strictly by the `organization` key supplied [4](#0-3) , so any org name that maps to a config entry lacking `webhook_secret` yields an always-verified (bypassed) signature check.
- `OpenedHandler#process` never consults `repository_owner`; it resolves the affected repository purely from `params.repository.full_name` via `Shipit::Repository.from_github_repo_name` [5](#0-4) , then calls `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` [6](#0-5) .
- `ReviewStackAdapter#find_or_create!` / `#create!` builds a `Stack`/`ReviewStack` using `params.pull_request.head.ref` as the branch and `pr#{params.number}` as the environment [7](#0-6) , with no re-check that this repository matches whatever org authenticated the request.

Exploit flow: an attacker crafts a JSON body where `repository.owner.login` names an org that is configured in `secrets.github` without a `webhook_secret` (or where multi-org routing otherwise resolves to an unsecured/unknown config path), while `repository.full_name` names the real victim org/repo (which has `blocking_statuses` configured and review-stack provisioning enabled). The attacker sends `POST /webhooks` with `X-Github-Event: pull_request`, `action: "opened"`, and any `X-Hub-Signature: sha1=...` value (or omits it, if that path is reachable) — `verify_webhook_signature` short-circuits to `true` because the resolved org has no secret. `WebhooksController#create` then dispatches the full attacker-controlled `params` (including the true `repository.full_name`) to `OpenedHandler`, which provisions/mutates a `ReviewStack` for the victim repository despite the request never being authenticated by that victim org's secret.

Existing guards that fail to prevent this: `drop_unhandled_event` only checks the event type exists, not authenticity; `verify_signature` authenticates by the wrong field relative to what the handler acts on; there is no `ExplicitParameters` or model-level check binding `repository.owner.login` to `repository.full_name`'s owner segment.

### Impact Explanation
An unauthenticated request, verified (or exempted from verification) under one organization's identity, can write to another organization/repository's `ReviewStack`/`Stack` records — this is a payload for one repository mutating another's stack, matching the Critical "cross-repository/tenant state manipulation" category. Combined with `blocking_statuses` configured on the victim stack, subsequent forged `status` events (subject to the same signature-resolution flaw) can flip `blocked?` to gate or unblock deploys on the victim stack, amplifying the impact toward unauthorized deploy gating. The attack is repeatable against any repository whose full name the attacker can guess/know, as long as at least one org in the multi-org config lacks a `webhook_secret`.

### Likelihood Explanation
This requires: (1) a multi-org GitHub App configuration (`secrets.github` keyed by multiple orgs) where at least one configured org entry has no `webhook_secret` set, and (2) the victim repository has review-stack provisioning enabled (`review_stacks_enabled` plus an allowing `provisioning_behavior`). Precondition (1) is a plausible but non-default operational misconfiguration (e.g., a newly onboarded org or a legacy/test org left without a secret) rather than the engine's own default; in single-org mode, `Shipit.github(organization: repository_owner)` ignores the attacker-supplied organization entirely and always uses the single configured secret, so this path is not exploitable there. Given the no-secret-org precondition, attacker cost is a single unauthenticated HTTP POST, fully repeatable and scriptable.

### Recommendation
Enforce that `repository.owner.login` used to select the signing secret is consistent with the owner segment of `repository.full_name` (or, better, always derive both from the same sub-object and reject mismatches). Additionally, treat a missing `webhook_secret` as a hard misconfiguration (reject the request, or require an explicit "unauthenticated org" allow-list) rather than silently returning `true` in `GitHubApp#verify_webhook_signature`, and support/require `X-Hub-Signature-256` verification.

### Proof of Concept
Minitest plan (to be added under `test/controllers/webhooks_controller_test.rb`, out of scope for this audit deliverable but describing the required assertions):
1. Configure `Shipit.stubs(:github).with(organization: 'attacker-org')` returning a `GitHubApp` built with a config that has no `webhook_secret` (or nil), and separately ensure `victim-org` has an active `Stack`/repository with `review_stacks_enabled` and `blocking_statuses` configured.
2. POST `/webhooks` with header `X-Github-Event: pull_request`, `X-Hub-Signature: sha1=deadbeef` (garbage), and body:
   ```json
   { "action": "opened", "number": 1,
     "pull_request": { "id":1, "number":1, "url":"...", "title":"t", "state":"open",
       "additions":1, "deletions":1,
       "head": {"sha":"abc","ref":"attacker-ref"},
       "user": {"login":"attacker"}, "assignees": [], "labels": [] },
     "repository": { "full_name": "victim-org/victim-repo", "owner": {"login": "attacker-org"} },
     "sender": {"login":"attacker"} }
   ```
3. Assert equality-before: `Shipit::ReviewStack.where(stack_id: victim_stack_group).count == 0`.
4. Assert response is `200 OK` (not `422`), proving `verify_signature` accepted the forged/garbage signature because it resolved `attacker-org`'s (secret-less) config.
5. Assert equality-after divergence: a new `Shipit::ReviewStack`/`Stack` row now exists under `victim-org/victim-repo` with `branch == "attacker-ref"`, even though no valid HMAC for `victim-org`'s secret was ever presented — demonstrating the cross-tenant write.

Note: I was unable to inspect `Shipit::Repository.from_github_repo_name`, `Shipit::Stack#blocked?`, or the `status` webhook handler in this session (no further tool calls available), so the precise mechanics of the `blocking_statuses`/`blocked?` amplification step are asserted based on the question's description and the `Stack`/`Commit` grep hits, not directly verified against their implementations.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
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

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L19-94)
```ruby
          def find_or_create!
            stack || create!
          end

          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end

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

          def user
            @user ||= Shipit::User.find_or_create_by_login!(params.sender["login"])
          end

          private

          attr_reader :params, :scope

          def action
            params.action
          end

          def repo_name
            params.repository["full_name"]
          end

          def pr_number
            params.number
          end

          def create!
            ReviewStack.transaction do
              stack = scope.create!(stack_attributes)
              stack
                .build_pull_request
                .update!(
                  github_pull_request: params.pull_request
                )
            end

            Shipit::ReviewStackProvisioningQueue.add(stack)

            @stack = stack
          end

          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```
