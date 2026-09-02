### Title
Missing webhook authentication for organizations without a configured `webhook_secret` allows forged `pull_request` `reopened` events to unarchive/deploy Review Stacks - (File: `lib/shipit/github_app.rb`, `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`GitHubApp#verify_webhook_signature` returns `true` unconditionally when the organization's config has no `webhook_secret`, so `WebhooksController#verify_signature` accepts any unsigned, attacker-crafted `pull_request` payload as long as `repository.owner.login` (or `organization.login`) resolves to such an org. This lets an unauthenticated attacker drive `ReopenedHandler` to unarchive a `ReviewStack` for any PR number on a repository under that org, and if the target stack has `continuous_deployment` enabled, the resulting green build can be auto-shipped by `ContinuousDeliveryJob`.

### Finding Description
The broken binding: `verified == HMAC_valid(webhook_secret, raw_body)` is expected to hold before any handler runs; instead, when `webhook_secret` is blank, `verified` is hardcoded to `true` regardless of the body or signature header: [1](#0-0) 

`WebhooksController#verify_signature` looks up the `GitHubApp` purely from attacker-controlled `repository.owner.login`/`organization.login` in the JSON body, and gates only on the boolean it returns: [2](#0-1) 

If that org exists in Shipit's config but was set up without a `webhook_secret`, `verify_webhook_signature` short-circuits to `true` and the raw forged body is dispatched to handlers unmodified: [3](#0-2) 

For `action=reopened`, `ReopenedHandler` resolves the target `Repository` purely from the attacker-supplied `repository.full_name` in the same forged body and, if provisioning rules allow it, unarchives the PR's `ReviewStack`: [4](#0-3) [5](#0-4) 

Exploit flow: attacker POSTs `X-Github-Event: pull_request` with a JSON body where `repository.owner.login` is a real Shipit-configured org lacking `webhook_secret`, `repository.full_name` matches a real repo/stack under that org with `continuous_deployment` enabled and review stacks permitted, `action: "reopened"`, and a `pull_request.number` of the attacker's choosing. No `X-Hub-Signature` is required because `verify_webhook_signature` never reaches the HMAC comparison. The handler unarchives (or, via `ReviewStackAdapter`, effectively (re)provisions) the corresponding `ReviewStack`, after which the existing continuous-deployment machinery can auto-ship the latest green commit on that PR's head ref.

Existing guards do not prevent this: `drop_unhandled_event` only filters unknown event types, not authentication; the `ExplicitParameters` schema in `ReopenedHandler` validates shape, not provenance; there is no `require_permission!`/session check on this unauthenticated endpoint by design (webhooks are meant to be authenticated solely via HMAC). The only real guard, HMAC verification, is bypassed by design whenever `webhook_secret` is absent.

### Impact Explanation
Any org configured in Shipit without a `webhook_secret` becomes fully unauthenticated for webhook purposes: an attacker can forge arbitrary `pull_request` (and other) events for any repository/stack under that org's namespace. For `reopened`, this allows unarchiving/reviving review stacks and PR numbers of the attacker's choosing; combined with `continuous_deployment` enabled on the target stack, this can lead to unauthorized deployment of attacker-influenced code — matching the Critical category "authentication bypass (forged webhook accepted)" / "unauthorized deploy". The blast radius is scoped to repositories under the specific misconfigured (secret-less) organization, but repeatable against every repository/PR in that org's namespace with a single crafted HTTP request each time.

### Likelihood Explanation
Requires a real precondition: a Shipit-configured GitHub organization whose `github_app` config omits `webhook_secret`, and a stack under it with `continuous_deployment` enabled and review-stack provisioning allowed. Given that precondition, attacker cost is a single unauthenticated `POST /webhooks` request with a crafted JSON body — no credentials, tokens, or GitHub write access required. This is a design flaw (`return true unless webhook_secret`) rather than a hypothetical timing issue, so it is fully reproducible and deterministic once the org config gap exists.

### Recommendation
Do not default to "verified" when `webhook_secret` is blank. Either require every configured organization to have a non-blank `webhook_secret` (fail closed / reject at load time), or make `verify_webhook_signature` return `false` (reject the webhook) when no secret is configured, forcing operators to explicitly opt an org into an "unsigned" trust mode rather than silently granting it by omission.

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb` style, no live GitHub):
1. Configure `Shipit.github_apps` (or equivalent) with an org `"no-secret-org"` whose config hash has no `webhook_secret` key/blank value.
2. Create `repository = Repository.create!(owner: "no-secret-org", name: "victim-repo")`, `stack = Stack.create!(repository: repository, continuous_deployment: true, ...)`, with review stacks enabled/`provisioning_behavior_allow_all?` true.
3. POST to `/webhooks` with header `X-Github-Event: pull_request`, no `X-Hub-Signature` (or a garbage one), and JSON body: `{"action":"reopened","number":<n>,"pull_request":{...archived PR of head sha of a passing build...},"repository":{"full_name":"no-secret-org/victim-repo","owner":{"login":"no-secret-org"}},"sender":{"login":"attacker"}}`.
4. Assert response is `200 OK` (not `422`), and assert (equality check both sides): `ReviewStack.find_by(pull_request_number: n)&.archived? == false` (i.e., stack got unarchived) even though no valid HMAC was ever supplied — proving `verified` (should equal HMAC-based authenticity) was `true` while `HMAC_valid(secret, raw_body)` is undefined/false.
5. Contrast: repeat with an org that *does* have `webhook_secret` configured and assert the same forged request yields `422` and no state mutation — demonstrating the divergence is caused solely by the blank-secret branch in `GitHubApp#verify_webhook_signature`.

### Citations

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-59)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L65-75)
```ruby
          def respond_to_pull_request_reopened?
            params.action == "reopened" &&
              unarchive?
          end

          def unarchive?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```
