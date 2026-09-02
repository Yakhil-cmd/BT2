### Title
Cross-tenant webhook auth bypass allows attacker to mutate a victim stack's `PullRequest` via `AssignedHandler` - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/secret to verify a webhook against using `repository_owner`, which falls back to `params.dig('organization','login')` whenever `repository.owner.login` is absent from the payload. `AssignedHandler` (and the shared `Handler#repository_name`) instead resolve the target repository/stack purely from the independent `params['repository']['full_name']` field. Because these two fields are never cross-checked, an attacker who can produce a validly-signed webhook for *any* org configured on the Shipit instance (including one whose `webhook_secret` is unset, in which case `verify_webhook_signature` returns `true` unconditionally) can set `repository.full_name` to point at a victim's repository/stack and have `AssignedHandler` overwrite that victim's persisted `PullRequest` row.

### Finding Description
The broken binding, stated as an equality the code assumes but never enforces:

`repository_owner` (the value used to pick the verifying `GitHubApp`/secret in `verify_signature`, `app/controllers/shipit/webhooks_controller.rb:59-62`) is assumed to equal the owner of `params['repository']['full_name']` (the value the handler actually acts on, `app/models/shipit/webhooks/handlers/handler.rb:36-38` and `app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb:67-69`). These are two independently attacker-supplied JSON fields with no validation tying them together.

Code path:
1. `verify_signature` computes `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) , then calls `Shipit.github(organization: repository_owner)` and checks `verify_webhook_signature` [2](#0-1) .
2. `AssignedHandler`'s `ExplicitParameters` schema requires `repository.full_name` but never requires `repository.owner.login` [3](#0-2) . Omitting `repository.owner` (and including only `organization.login`) forces the fallback branch in step 1.
3. `verify_webhook_signature` returns `true` unconditionally if the resolved org's `webhook_secret` is blank [4](#0-3) ; this is a documented, supported configuration (`webhook_secret: # nil` appears in `config/secrets.development.example.yml` and the multi-org example `test/dummy/config/secrets_double_github_app.yml`). Even where a secret is set, an attacker who legitimately owns a repo/org onboarded to this Shipit instance knows/administers that org's own webhook secret and can sign arbitrary payload bodies with it.
4. `AssignedHandler#repository` resolves `Shipit::Repository.from_github_repo_name(params.repository.full_name)` — an entirely separate field from the one used for signature verification — and `AssignedHandler#pull_request` looks up an existing `PullRequest` scoped to that repository's stacks [5](#0-4) .
5. On `process`, for `action` in `%w[assigned unassigned]`, it calls `pull_request.update(github_pull_request: params.pull_request)` if found [6](#0-5) , which overwrites `title`, `state`, `additions`, `deletions`, `user`, `assignees`, `labels`, and `head` (commit) on the victim's PR record [7](#0-6) .

No guard rejects this: `verify_signature` never compares its resolved org against `repository.full_name`'s owner; `ExplicitParameters` only validates the shape of fields present, not their consistency with authentication; `drop_unhandled_event` only checks the event type is registered.

### Impact Explanation
The attacker forges a `pull_request` webhook, correctly signed for their own (or any weakly-configured, secret-less) org, but with `repository.full_name` set to an arbitrary victim repository/stack and `action` set to `assigned`/`unassigned`. This writes attacker-controlled `title`, `additions`, `deletions`, `assignees`, `labels`, and `head` commit sha/ref data into the victim's real `PullRequest` record — "a payload for one repository mutating another's stack['s]... commit" — without the victim's org ever authenticating the request. This is repeatable against any repository/stack whose `full_name` the attacker knows, across tenants, as long as a `PullRequest` with the matching `number` already exists for that stack. `AssignedHandler` itself does not invoke `Command`/`PTY.spawn` or provision review stacks (that behavior lives in `opened_handler.rb` / `review_stack_adapter.rb`, not in `AssignedHandler`), so the RCE narrative asserted in the question is not substantiated for this specific handler; the concretely demonstrated impact is unauthorized cross-tenant data mutation, matching the "payload for one repository mutating another's stack/commit" Critical category, not a direct command-execution path.

### Likelihood Explanation
Preconditions: (a) the Shipit instance uses the multi-org `github:` config form or any org configuration with a blank `webhook_secret` (both explicitly documented/supported), and (b) a target stack already has a `PullRequest` row for the spoofed `number`. Attacker cost is a single crafted HTTP POST to `/webhooks` with a known-good signature for their own tenant/org and a victim `repository.full_name` — no session, API token, or GitHub secret of the victim's org is needed. This is fully repeatable and requires no interaction from the victim.

### Recommendation
In `WebhooksController#verify_signature`, derive the authenticating organization/repository exclusively from a single trusted source and enforce that the same source is used by every handler. Concretely: require `repository.owner.login` in every handler's `ExplicitParameters` schema (reject payloads lacking it) and, in `verify_signature`, refuse to fall back to `organization.login` when a `repository` object is present; additionally, after signature verification, assert that `repository_owner` matches the owner segment of the `repository.full_name` used later in `Handler#repository_name`/`AssignedHandler#repository`, rejecting the request otherwise. Also flag/disallow blank `webhook_secret` in production-like environments to eliminate the unconditional bypass in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers/pull_request/assigned_handler_test.rb`), no live GitHub:

1. Seed a victim `Stack`/`Repository` (`full_name = "victim-org/victim-repo"`, `review_stacks_enabled: true`, provisioning behavior `allow_all`) and a `Shipit::PullRequest` with `number: 42` belonging to that stack, with known baseline `title`/`labels`/`head`.
2. Configure `Shipit.secrets.github` with two orgs, e.g. `attacker-org` (with a known `webhook_secret`, or blank to skip signing entirely) and the victim's org (different/unrelated secret the attacker does not know).
3. Build a `pull_request` webhook payload: `action: "unassigned"`, `number: 42`, `repository: { full_name: "victim-org/victim-repo" }` (no `owner` key), `organization: { login: "attacker-org" }`, and a `pull_request` object with attacker-chosen `title`, `additions`, `deletions`, `assignees`, `labels`, `head.sha`.
4. Sign the raw JSON body with `attacker-org`'s known webhook secret (or send unsigned if that org's secret is blank) and set `X-Hub-Signature`/`X-Github-Event: pull_request`.
5. Assert equality-before: `victim_pull_request.reload.title` equals the original seeded title, and `repository_owner` (as computed by the controller) equals `"attacker-org"` while `params['repository']['full_name']` equals `"victim-org/victim-repo"` — i.e., the two are unequal but both accepted.
6. POST to `/webhooks`; assert `response` is `:ok` (200), i.e., `verify_signature` passed using the attacker org's credentials.
7. Assert equality-after: `victim_pull_request.reload.title` now equals the attacker-supplied title (and `head`, `labels`, `assignees` also changed) — proving a record for a repository that did not authenticate the request (`victim-org/victim-repo`) was mutated using credentials belonging to a different org (`attacker-org`).

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

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_assignee_change?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L53-69)
```ruby
          def pull_request
            @pull_request ||= Shipit::PullRequest
                              .joins(:stack, stack: :repository)
                              .find_by(
                                number: params.number,
                                stacks: {
                                  repositories:
                                    {
                                      id: repository.id
                                    }
                                }
                              )
          end

          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
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

**File:** app/models/shipit/pull_request.rb (L36-50)
```ruby
    def github_pull_request=(github_pull_request)
      self.github_id = github_pull_request.id
      self.number = github_pull_request.number
      self.api_url = github_pull_request.url
      self.title = github_pull_request.title
      self.state = github_pull_request.state
      self.additions = github_pull_request.additions
      self.deletions = github_pull_request.deletions
      self.user = User.find_or_create_by_login!(github_pull_request.user.login)
      self.assignees = github_pull_request.assignees.map do |github_user|
        User.find_or_create_by_login!(github_user.login)
      end
      self.labels = github_pull_request.labels.map(&:name)
      self.head = find_or_create_commit_from_github_by_sha!(github_pull_request.head.sha)
    end
```
