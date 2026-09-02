This vulnerability is confirmed. Verifying both sides of the claimed binding:

- Signature verification binding: `Shipit.github(organization: repository_owner)` where `repository_owner = params.dig('repository','owner','login')` [1](#0-0)  — this org's `webhook_secret` HMAC-verifies the raw request body [2](#0-1) .
- Write-target binding: handlers resolve the mutated `Repository`/`Stack` from `payload.dig('repository', 'full_name')` [3](#0-2) , or explicitly `params.repository.full_name` in `OpenedHandler#repository` [4](#0-3) , which is then split into `owner`/`name` and looked up independent of `repository_owner` [5](#0-4) .

Nothing in `create` re-derives `repository_owner` or cross-checks it against `repository.full_name`; `verify_signature` and `create` both operate on the same attacker-controlled JSON body but read two different, independently attacker-settable JSON fields (`repository.owner.login` vs `repository.full_name`) [6](#0-5) . Since the attacker crafts the raw JSON body themselves and signs it with their own org's `webhook_secret`, they can set `repository.owner.login` to their own org (to pass `verify_webhook_signature`) while setting `repository.full_name` (and `pull_request.head.ref`, etc.) to reference a victim org's repo — the `ReviewStackAdapter#create!` then creates/mutates a `ReviewStack`/`Stack`/`PullRequest` under the victim repo, attributing the action to `params.sender.login` (also attacker-controlled) [7](#0-6) . `GithubOrganizationUnknown` rescue only blocks unregistered orgs, not mismatched ones [8](#0-7) .

### Title
Webhook signature verified against `repository.owner.login` but write target resolved from `repository.full_name` — cross-tenant stack mutation - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController` verifies the HMAC signature of a webhook using the GitHub App config for `params.dig('repository','owner','login')`, but the handlers that actually create/mutate `Stack`/`ReviewStack`/`PullRequest` records resolve the target repository from `params.dig('repository','full_name')`. An attacker who owns any onboarded organization (org-A) can craft and sign an arbitrary JSON body whose `repository.owner.login` is `org-A` but whose `repository.full_name` points at a victim organization's repo (`org-B/victim-repo`), passing signature verification with their own legitimate `webhook_secret` while causing writes against org-B's records.

### Finding Description
The broken binding is: `organization-whose-webhook_secret-verified-body == organization-owning-repository-mutated-by-handler`. Concretely, `verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` from `params.dig('repository','owner','login')` and calls `github_app.verify_webhook_signature(signature, request.raw_post)`, which is a pure HMAC-SHA1 check of the raw body against that org's secret — it does not constrain any other field of the JSON body. `create` then dispatches the same raw `params` to handlers such as `PullRequest::OpenedHandler`, whose `repository` method and the base `Handler#repository_name`/`#stacks` methods look up the target `Shipit::Repository` via `Repository.from_github_repo_name(params.repository.full_name)`, splitting `full_name` into `owner/name` independent of `repository_owner`. Since org-A and org-B have distinct `webhook_secret` values per `Shipit.github(organization:)`, and the attacker fully controls the raw JSON body they submit (this is a direct `POST /webhooks` from the attacker, not a GitHub-relayed event, so GitHub's own owner/full_name consistency is never enforced), the attacker sets `repository.owner.login = "org-A"` and `repository.full_name = "org-B/victim-repo"` (plus `pull_request.head.ref` and `sender.login` as desired), signs it with `org-A`'s secret they legitimately possess, and the request passes `verify_signature`. `ReviewStackAdapter#create!` then creates a `ReviewStack` (and a `PullRequest` record) scoped to `org-B/victim-repo`, and `labeled_handler`/`closed_handler`/etc. can similarly archive/unarchive/mutate existing stacks under org-B using the same forged binding. No code path cross-checks `repository_owner` against `repository.full_name`'s owner segment.

### Impact Explanation
An attacker with a legitimate, self-owned GitHub organization onboarded to Shipit can create, provision, archive, or unarchive `ReviewStack`/`Stack`/`PullRequest` records under any other tenant organization configured in the same Shipit instance, without ever possessing that victim org's `webhook_secret`. This is a payload for one repository mutating another's stack/PR records — a cross-tenant write authorized by the wrong organization's signature — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." It is repeatable against any onboarded victim repository/org and any PR-related event handler (`opened`, `closed`, `labeled`, `unlabeled`, `assigned`, `reopened`, `edited`), since all of them resolve the target via `repository.full_name`/`pull_request` fields independent of the field used for signature verification.

### Likelihood Explanation
Preconditions are modest and match realistic multi-tenant Shipit deployments: multiple organizations configured via `Shipit.github(organization:)` with distinct `webhook_secret`s, and the attacker owning/controlling at least one of them (trivial — they can register their own GitHub org and configure Shipit's webhook endpoint against it, or simply know their own org's secret from Shipit configuration they administer for their org). The attack cost is a single crafted HTTP POST with a valid HMAC computed from a secret the attacker legitimately owns; no bypass of cryptography is needed and it is fully repeatable.

### Recommendation
In `verify_signature`/`create`, after verifying the signature, assert that the organization used to select the `webhook_secret` matches the owner segment of every repository reference the handlers will act on (e.g., `params.dig('repository','full_name')`'s owner, and `pull_request.base.repo.full_name`'s owner if present), rejecting the request (422) on mismatch. Alternatively, have handlers receive and enforce the already-verified `repository_owner` as the authoritative organization and refuse to operate on any repository whose owner differs from it.

### Proof of Concept
Minitest `ActionDispatch::IntegrationTest` in `test/controllers/webhooks_controller_test.rb`-style (not modifying out-of-scope files, but describing the plan):
1. Configure two orgs in test `Shipit.github`-style config: `org-a` with `webhook_secret: "secret-a"`, `org-b` with `webhook_secret: "secret-b"`. Create a `Shipit::Repository` for `org-b/victim-repo` with `review_stacks_enabled` and `provisioning_behavior_allow_all`.
2. Build a JSON body for a `pull_request` `opened` event where `repository.owner.login == "org-a"` and `repository.full_name == "org-b/victim-repo"`, with a valid `pull_request` payload (`head.ref`, `sender.login`, etc.).
3. Compute `X-Hub-Signature` as `"sha1=" + OpenSSL::HMAC.hexdigest('sha1', "secret-a", raw_body)`.
4. `post shipit.webhooks_path, params: raw_body, headers: { 'X-Github-Event' => 'pull_request', 'X-Hub-Signature' => signature, 'Content-Type' => 'application/json' }`.
5. Assert response is `200 OK` (signature verified using org-A's secret) — this is the first side of the equality (`organization-whose-webhook_secret-verified-body == "org-a"`).
6. Assert `Shipit::ReviewStack.find_by(environment: "pr...")`'s repository has `owner == "org-b"` — the second side of the equality (`organization-owning-repository-mutated-by-handler == "org-b"`).
7. Since `"org-a" != "org-b"`, the binding is broken and the record was written for a repository whose owning organization never authenticated the request.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-49)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L36-38)
```ruby
        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L52-94)
```ruby
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
