### Title
`pull_request` webhook `owner/full_name` split lets an attacker authenticate with one org's secret while mutating another org's `ReviewStack` via `LabelCapturingHandler` - (File: app/controllers/shipit/webhooks_controller.rb, lib/shipit/github_app.rb, app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App/HMAC secret to validate a webhook using `repository.owner.login` [1](#0-0) , while `LabelCapturingHandler` resolves the target `Repository`/`ReviewStack` from the completely independent `repository.full_name` field [2](#0-1) . Because nothing binds these two values together, an attacker can pick a "no-secret" org for signature verification and point `full_name` at an arbitrary victim repository/stack, causing labels the attacker fully controls to be written onto that victim stack's `PullRequest` and merged as uppercased environment variables in `ReviewStack#env` [3](#0-2) .

### Finding Description
The broken binding, stated as an equality that the code fails to enforce:
`org_that_authenticated_signature (params.repository.owner.login)` MUST equal `org_that_owns_the_mutated_repository (params.repository.full_name.split('/').first)`.

Trace:
1. `WebhooksController#verify_signature` computes `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` and fetches `Shipit.github(organization: repository_owner)` to obtain that org's `webhook_secret` [1](#0-0) [4](#0-3) .
2. `GitHubApp#verify_webhook_signature` returns `true` unconditionally `unless webhook_secret` is present for that org's config [5](#0-4) . If the attacker names any Shipit-known org that has no `webhook_secret` configured (or otherwise controls a repo under such an org), the signature check trivially passes with `verified = true`.
3. Once verification passes, `WebhooksController#create` dispatches `params` (the whole raw JSON, unrelated to which org "verified" it) to every handler for the event, including `LabelCapturingHandler` for `pull_request` `unlabeled` [6](#0-5) .
4. `LabelCapturingHandler#repository` looks up the target `Shipit::Repository` purely from `params.repository.full_name` via `Repository.from_github_repo_name`, with no cross-check against `repository.owner.login` used in step 1 [2](#0-1) .
5. `capture_labels?` -> `unlabeled_active_stack?` is satisfied for any non-archived stack with a matching `PullRequest`, and `capture_labels` persists attacker-supplied `params.pull_request.labels.map(&:name)` directly onto `stack.pull_request` [7](#0-6) .
6. `ReviewStack#env` merges those label names, uppercased, into the environment with value `"true"` whenever the stack builds/deploys/tests, e.g. `pull_request.labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` [3](#0-2) .

No existing guard closes this gap: `drop_unhandled_event` only checks the event type is handled [8](#0-7) ; the `ExplicitParameters` schema in the handler only requires `repository.full_name` be a `String`, it does not require it to match the owner used for signature verification [9](#0-8) ; `Repository` model validations only constrain character format of `owner`/`name`, not cross-consistency with the webhook's authenticating org [10](#0-9) . There is no session/API-client/permission check on this unauthenticated endpoint that could catch the mismatch.

### Impact Explanation
An attacker who can get any Shipit-configured GitHub organization (one without a `webhook_secret`, or one they otherwise control) accepted by `verify_signature`, and who knows the `owner/name` of any victim repository/stack tracked by Shipit, can forge a `pull_request` `unlabeled` webhook to overwrite `labels` on that victim stack's `PullRequest`. This is a payload from one repository/org mutating another repository's stack state — explicitly listed as a Critical impact in the rules ("a payload for one repository mutating another's stack, commit, task or team"). When the targeted `ReviewStack` corresponds to a production environment, the injected uppercase env vars (e.g., `SKIP_TESTS=true`, or any deploy-script-consumed flag) flow into the build/deploy environment used at deploy time, enabling unauthorized alteration of production deploy behavior. The attack is repeatable against any stack whose `owner/name` the attacker can guess or discover, is not limited to the attacker's own repository, and crosses tenant/org boundaries.

### Likelihood Explanation
Preconditions: Shipit must have at least one configured GitHub organization/App entry without a `webhook_secret` (or the attacker must otherwise be able to have their org's secret accepted), and the victim repository/stack must exist with review stacks enabled and an active `PullRequest` record. The attacker needs no Shipit credentials, session, or API token — only the ability to send an HTTP POST to `/webhooks` with a crafted JSON body and matching `X-Github-Event: pull_request` header. This is inexpensive and fully repeatable/scriptable against arbitrary target `full_name` values.

### Recommendation
In `WebhooksController#verify_signature` (or in each handler's `process`), enforce that the organization/owner used to select the webhook secret is the same organization that owns `params.repository.full_name` before dispatching to handlers — e.g., verify `params.dig('repository','full_name').split('/').first.casecmp?(repository_owner)` and reject (422) on mismatch. Additionally, require that `webhook_secret` be mandatory (non-blank) for every configured organization, removing the `return true unless webhook_secret` bypass in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
Minitest plan (under `test/controllers/webhooks_controller_test.rb`, no live GitHub):
1. Configure two orgs in `Shipit.github_apps`/`Shipit.app.env` fixtures/stubs: `attacker-org` (no `webhook_secret`) and `victim-org` (with `webhook_secret`, or none — either demonstrates the gap).
2. Create `Shipit::Repository` owned by `victim-org` and a `Shipit::ReviewStack` under it, `environment: "production"`, with an associated `Shipit::PullRequest` (`labels: []`).
3. Build the equality under test explicitly: `expected_binding = (owner_used_for_signature == full_name.split('/').first)` — assert this is `false` for the crafted payload before sending it.
4. POST to `/webhooks` with header `X-Github-Event: pull_request`, `X-Hub-Signature` absent/anything, and JSON body: `{"action":"unlabeled","number":1,"pull_request":{...,"labels":[{"name":"skip_tests"}]},"repository":{"full_name":"victim-org/victim-repo","owner":{"login":"attacker-org"}},"sender":{"login":"attacker"}}`.
5. Assert response is `200 OK` (signature accepted via `attacker-org`'s absent secret).
6. Reload the victim `PullRequest` and assert `pull_request.labels == ["skip_tests"]`, and assert `review_stack.env["SKIP_TESTS"] == "true"`, proving the attacker mutated a stack belonging to an org whose secret never authenticated the request, on a production-environment stack.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L66-102)
```ruby
          def unlabeled_active_stack?
            unlabeled? && stack.present? && !stack.archived?
          end

          def reopened_active_stack?
            reopened? && stack.present? && !stack.archived?
          end

          def opened?
            action == "opened"
          end

          def labeled?
            action == "labeled"
          end

          def unlabeled?
            action == "unlabeled"
          end

          def reopened?
            action == "reopened"
          end

          def action
            params.action
          end

          def pull_request
            params.pull_request
          end

          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-114)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end
```

**File:** app/models/shipit/review_stack.rb (L84-93)
```ruby
    def env
      return super unless pull_request.present?

      super
        .merge(
          pull_request
            .labels
            .each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }
        )
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

**File:** app/models/shipit/repository.rb (L41-45)
```ruby
    validates :name, uniqueness: { scope: %i[owner], case_sensitive: false,
                                   message: 'cannot be used more than once' }
    validates :owner, :name, presence: true, ascii_only: true
    validates :owner, format: { with: /\A[a-z0-9_\-.]+\z/ }, length: { maximum: OWNER_MAX_SIZE }
    validates :name, format: { with: /\A[a-z0-9_\-.]+\z/ }, length: { maximum: NAME_MAX_SIZE }
```
