### Title
Cross-organization webhook `repository.owner.login`/`repository.full_name` mismatch allows attacker to forge writes to a victim's `PullRequest` via `AssignedHandler` - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to verify a payload using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')`, while `AssignedHandler#repository` independently resolves the target `Repository` from `params.repository.full_name`. Because these are two independently attacker-controlled JSON fields inside the same payload, an attacker can set `repository.owner.login` to an organization whose configured `webhook_secret` is `nil` (bypassing signature verification per `GitHubApp#verify_webhook_signature`'s `return true unless webhook_secret`), while setting `repository.full_name` to `victim-org/victim-repo`, causing the handler to write attacker-controlled PR fields onto the victim's `PullRequest` record.

### Finding Description
The claimed broken binding is: `verifying_org (params.repository.owner.login used in WebhooksController#verify_signature) == owning_org (derived from params.repository.full_name used in AssignedHandler#repository)`.

Trace:
- `WebhooksController#verify_signature` builds the verifying GitHub App from `repository_owner`: `Shipit.github(organization: repository_owner)`, where `repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) .
- `GitHubApp#verify_webhook_signature` explicitly returns `true` unconditionally when that org's `webhook_secret` is blank/`nil`: `return true unless webhook_secret` [2](#0-1) .
- Separately, `AssignedHandler#repository` resolves the repository to filter the `PullRequest` lookup from `params.repository.full_name`, via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [3](#0-2) .
- `pull_request` is looked up scoped by that repository's id and the payload's PR `number`, then `pull_request.update(github_pull_request: params.pull_request)` writes attacker-supplied `title`, `assignees`, `labels`, `additions`, `deletions`, etc. onto the record [4](#0-3) [5](#0-4) .

Root cause: `repository.owner.login` and `repository.full_name` are both plain fields inside the single attacker-supplied JSON body — nothing enforces that the owner used for signature verification matches the owner embedded in `full_name`. If the Shipit deployment is configured with multiple GitHub orgs (`docs/setup.md` "Using Multiple Github Applications" / `test/dummy/config/secrets_double_github_app.yml`) and at least one configured org has no `webhook_secret` set, an attacker who knows (or guesses) that org's name can craft a payload with `repository.owner.login = <no-secret-org>` and `repository.full_name = 'victim-org/victim-repo'`. `verify_signature` calls `Shipit.github(organization: 'no-secret-org')`, which returns `true` from `verify_webhook_signature` without checking any HMAC against the actual bytes, entirely bypassing authentication for the payload content that names the victim repo.

Existing guards do not catch this: `drop_unhandled_event` only checks the event type exists; `check_if_ping` is unrelated; `ExplicitParameters` (`params do ... end`) only validates JSON *shape*, not cross-field consistency between `repository.owner.login` and `repository.full_name`; and `PullRequest`/`Repository` model validations only constrain owner/name character sets, not that the acting org matches. There is no code path that re-derives `repository_owner` from `full_name` or compares them.

### Impact Explanation
A successful forged request lets an unprivileged attacker who controls (or names) an organization with a no-secret GitHub App configuration overwrite arbitrary `PullRequest` metadata (`title`, `labels`, `assignees`, `additions`, `deletions`, `head` commit lookup) belonging to any other repository/stack tracked by the same Shipit instance, as long as they know or can guess a valid PR number for that victim stack. This is a cross-repository/cross-tenant write matching the "payload for one repository mutating another's stack/PR" Critical category, and it is repeatable against arbitrary victim repos/PR numbers from the same forged-org identity. Downstream logic that reads `PullRequest#labels`/`title`/`assignees` for merge/deploy gating could subsequently act on attacker-authored data.

### Likelihood Explanation
Exploitability strictly depends on the deployment's `config/secrets.yml` github section containing **multiple** organizations (the single-org default schema has no analogous "other, no-secret org" to abuse — see `Shipit.github` behavior) and at least one of those configured orgs having `webhook_secret` unset/nil. This is a real, documented, supported configuration (`docs/setup.md` "Using Multiple Github Applications", `test/dummy/config/secrets_double_github_app.yml` shows both `OrgOne`/`OrgTwo` with `webhook_secret: # nil`). Given that precondition, attacker cost is a single unauthenticated HTTP POST to `/webhooks` with a crafted JSON body; no secrets, sessions, or GitHub credentials are required, and it is fully repeatable.

### Recommendation
In `WebhooksController#verify_signature`/`AssignedHandler` (and the other PR handlers using `repository.full_name`), enforce that the `repository.owner.login` used to select the verifying GitHub App matches the owner segment of `repository.full_name` before trusting the payload; reject the request (422) on mismatch. Additionally, avoid — or explicitly opt into — the "no webhook secret configured" bypass per-organization, since it globally disables authentication for any payload claiming that org, regardless of the repository actually being mutated.

### Proof of Concept
Minitest plan (multi-org secrets fixture, e.g. `test/dummy/config/secrets_double_github_app.yml`):
1. Configure two orgs, `OrgOne` (has `webhook_secret` set — the victim org owning `victim-repo`) and `OrgTwo` (`webhook_secret: nil` — the attacker-usable org).
2. Create `victim_stack = create_stack(repository: create(:repository, owner: 'OrgOne', name: 'victim-repo'))` and `pull_request = create(:pull_request, stack: victim_stack, number: 42, title: 'Legit title', assignees: [])`.
3. Build payload from `pull_request_assigned` fixture, set `payload['number'] = 42`, `payload['pull_request']['number'] = 42`, `payload['pull_request']['title'] = 'PWNED'`, `payload['pull_request']['assignees'] = [{login: 'attacker'}]`, `payload['repository']['full_name'] = 'OrgOne/victim-repo'`, but `payload['repository']['owner']['login'] = 'OrgTwo'`.
4. POST to `/webhooks` with header `X-Github-Event: pull_request` and no/garbage `X-Hub-Signature`.
5. Assert `response).to have_http_status(:ok)` (not 422) because `Shipit.github(organization: 'OrgTwo').verify_webhook_signature` returns true unconditionally.
6. Assert `pull_request.reload.title == 'PWNED'` and `pull_request.reload.assignees.map(&:login) == ['attacker']`, proving the equality `verifying_org == owning_org` is broken and the victim's PR row was mutated by a payload verified only against an unrelated org's (missing) secret.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L41-65)
```ruby
          def process
            return unless respond_to_assignee_change?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end

          private

          def respond_to_assignee_change?
            %w[assigned unassigned].include?(params.action)
          end

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
```

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L67-69)
```ruby
          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
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
