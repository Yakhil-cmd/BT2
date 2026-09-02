### Title
Webhook signature verified against attacker-controlled `repository.owner.login`, decoupled from the `repository.full_name` used to mutate stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to verify against using `params.dig('repository', 'owner', 'login')`, a field taken directly from the attacker-supplied JSON body [1](#0-0) [2](#0-1) . `LabeledHandler#repository` and `#stack` instead resolve the affected repository from the independent `params.repository.full_name` field of the same attacker-supplied body [3](#0-2) . Because these two fields are never cross-checked, an attacker who owns/controls "attacker-org" and signs a request with attacker-org's own valid webhook secret can set `repository.full_name` to `victim-org/victim-repo` and cause `stack.archive!`/`stack.unarchive!` to execute against the victim's real `ReviewStack`.

### Finding Description
The broken binding, stated as an equality that the code fails to enforce: **the organization whose secret authenticates the request** (`Shipit.github(organization: params.dig('repository','owner','login'))`) **must equal the organization that owns the repository being mutated** (`Shipit::Repository.from_github_repo_name(params.repository.full_name).owner`). The code never enforces `params.dig('repository','owner','login') == params.repository.full_name.split('/').first`.

Trace:
1. `WebhooksController#create` parses the raw JSON body and dispatches to handlers only after `verify_signature` runs as a `before_action` [4](#0-3) .
2. `verify_signature` picks the GitHub App config via `Shipit.github(organization: repository_owner)` where `repository_owner` reads `params.dig('repository', 'owner', 'login')` from the raw request body — a value fully controlled by whoever sends the POST [2](#0-1) .
3. `GitHubApp#verify_webhook_signature` HMACs the raw body against `webhook_secret` for the org resolved in step 2 [5](#0-4) . An attacker who owns "attacker-org" in Shipit's GitHub App config can legitimately sign the payload with attacker-org's real webhook secret (it's their own org). Nothing checks that this org matches `repository.full_name`.
4. Once verified, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs with the entire raw params hash, including the attacker-chosen `repository.full_name` [6](#0-5) .
5. `LabeledHandler#repository` resolves the repository purely from `params.repository.full_name`, independent of `repository_owner` used for signing [3](#0-2) .
6. `#archive?`/`#unarchive?` evaluate against that resolved (victim) repository's real `provisioning_behavior_*` and `provisioning_label_name` settings [7](#0-6) , and `#handle` calls `stack.archive!`/`stack.unarchive!` on the victim's actual `ReviewStack` [8](#0-7) .

Existing guards do not close this gap: `drop_unhandled_event`/`check_if_ping` only look at the event type header, not repository identity; `ExplicitParameters` schema in the handler only validates types/presence of `repository.full_name`, not its consistency with the org that signed the request; and `verify_signature`'s only failure modes are "unknown organization" (`GithubOrganizationUnknown`) or bad HMAC — both bypassed when the attacker owns a legitimately configured org and signs correctly with its own secret while naming an unrelated repo in the body.

### Impact Explanation
An attacker who controls any org onboarded into Shipit's GitHub App config (even their own, e.g. a public/self-service org) can forge a `pull_request`/`labeled` webhook naming any other tenant's `owner/repo` in `repository.full_name`, as long as they can guess or observe that repo's `provisioning_label_name` (described in the prompt as guessable/public). This causes `Stack#archive!`/`#unarchive!` to execute on a repository/organization that never authenticated the request — a write for one tenant's stack triggered by another tenant's credentials. `unarchive!`/reprovisioning schedules deploy commands per the review-stack provisioning flow, so this can cause unauthorized deploy/rollback activity or unwanted deprovisioning of a victim's environment. This matches the "Critical: a payload for one repository mutating another's stack" category.

### Likelihood Explanation
Preconditions: victim repo must have `review_stacks_enabled` and a `provisioning_behavior_prevent_with_label`/`allow_with_label` config with a known `provisioning_label_name` (stated as guessable/public in the prompt). The attacker needs no privileges on the victim repo at all — only control of any org that is itself configured in Shipit (which could be their own public/self-service org, per the threat model where "any internet user who can send HTTP requests to the Shipit host" is the attacker and only needs to avoid needing secrets they don't have). The attack is a single crafted HTTP POST, fully repeatable against any repository whose full name and label they can guess, with no live GitHub interaction needed.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), enforce that the organization used to verify the signature matches the organization/owner of `repository.full_name` in the same payload before dispatching to handlers — reject the request (422) if they diverge. Alternatively, resolve the target `Shipit::Repository` first and verify the signature using that repository's actual owning organization's secret rather than trusting attacker-supplied `repository.owner.login` independently from `repository.full_name`.

### Proof of Concept
Minitest plan (webhooks_controller or labeled_handler test, no live GitHub):
1. Configure two orgs in `Shipit.github_configs`-equivalent test fixtures: `attacker-org` (with a known webhook secret) and `victim-org`.
2. Create `victim_repo = Shipit::Repository.create!(name: 'victim-repo', owner: 'victim-org', review_stacks_enabled: true, provisioning_behavior: 'prevent_with_label', provisioning_label_name: 'no-deploy')` and an active `ReviewStack`/`Stack` under it with `archived: false`.
3. Build a JSON body with `repository.full_name = 'victim-org/victim-repo'`, `repository.owner.login = 'attacker-org'`, `action = 'labeled'`, `pull_request.state = 'open'`, `pull_request.labels = [{name: 'no-deploy'}]`, matching pull request head/number tied to the victim stack.
4. Compute `X-Hub-Signature` using `attacker-org`'s webhook secret over the raw JSON body.
5. POST to `/webhooks` with `X-Github-Event: pull_request` and the computed signature.
6. Assert response is `200`/`:ok` (signature accepted) and assert `victim_stack.reload.archived?` is now `true` — i.e., `repository_owner` used for signing (`attacker-org`) != repository actually mutated (`victim-org/victim-repo`), yet the write succeeded.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L6-15)
```ruby
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-57)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L85-97)
```ruby
          def archive?
            (repository.provisioning_behavior_allow_with_label? && !pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && pull_request_has_provisioning_label?)
          end

          def unarchive?
            (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end

          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
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
