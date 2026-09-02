### Title
`pull_request` webhook signature verified against `repository.owner.login`, but repo/stack resolved from independent `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which org's `webhook_secret` to check against using `repository_owner` = `params.dig('repository','owner','login')`, while `EditedHandler` (and the shared `Handler#repository_name`) resolves the actual `Shipit::Repository`/stack to mutate from the independent field `params.repository.full_name`. Because nothing in the code enforces `repository.owner.login == repository.full_name.split('/').first`, an attacker who owns a repo in an org with no configured `webhook_secret` can forge a `pull_request` `action=edited` payload whose `repository.owner.login` names their own no-secret org (making `verify_webhook_signature` auto-pass) while `repository.full_name` names a victim org/repo, causing `EditedHandler` to update the victim's persisted `PullRequest` record.

### Finding Description
The broken binding is the implicit equality the code assumes but never checks:
`params.dig('repository','owner','login') == params.dig('repository','full_name').split('/').first`

- `verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-30` computes `github_app = Shipit.github(organization: repository_owner)` and calls `github_app.verify_webhook_signature(...)`, where `repository_owner` comes only from `params.dig('repository', 'owner', 'login')` (`app/controllers/shipit/webhooks_controller.rb:59-62`).
- `GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`) returns `true` unconditionally `unless webhook_secret` is configured for that org. So if the attacker controls (or names) an org with **no** `webhook_secret` configured in `Shipit.github_configurations` for that org key, the signature check is bypassed entirely regardless of the actual HMAC.
- Once past `verify_signature`, `EditedHandler#repository` (`app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb:63-65`) resolves the target repo via `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, which is a completely separate JSON field from `repository.owner.login` — nothing forces them to agree.
- `EditedHandler#pull_request` (`edited_handler.rb:49-61`) finds the `PullRequest` scoped to that resolved repository and updates it: `pull_request.update(github_pull_request: params.pull_request)`.

Exploit flow: attacker sends `POST /webhooks` with header `X-Github-Event: pull_request`, body `action: "edited"`, `repository.owner.login: "attacker-org-no-secret"`, `repository.full_name: "victim-org/victim-repo"`, and a `pull_request` block referencing an existing victim PR `number`. The signature check passes trivially because `attacker-org-no-secret` has no configured secret; the handler then finds and overwrites the victim's `Shipit::PullRequest` (title, state, additions/deletions, assignees, labels, head commit) with attacker-supplied values.

Regarding the "shared commit SHA" amplification path: `PullRequest#github_pull_request=` calls `find_or_create_commit_from_github_by_sha!(sha)` (`app/models/shipit/pull_request.rb:52-61`), which does `stack.commits.by_sha(sha)` — this lookup **is scoped to `stack.commits`**, not a global/bare SHA lookup. Similarly `StatusHandler` and `CheckSuiteHandler` scope by stack/branch or global `Commit.where(sha:)` respectively, but those are different handlers/events, not reachable from this `pull_request edited` flow. So the specific "collides with victim's commit via bare SHA" amplification claimed in the question is not substantiated for `EditedHandler` — the commit association stays correctly scoped to the resolved (victim) stack. This doesn't invalidate the primary owner/full_name split bug, but the specific SHA-collision amplification mechanism described could not be confirmed in this code path.

Existing guards checked and found insufficient: `drop_unhandled_event` only checks the event type is handled, not the payload's internal consistency; `ExplicitParameters` schema in `EditedHandler` validates types/presence but not cross-field consistency between `repository.owner.login` and `repository.full_name` (in fact the schema for `EditedHandler` doesn't even require `repository.owner.login`); there is no `force_github_authentication`, `require_permission!`, or model validation anywhere in this webhook path that re-derives or re-checks the owner against the full_name used for record resolution.

### Impact Explanation
An unprivileged attacker (anyone who can open a PR against a repo they control and send an unauthenticated `POST /webhooks`) can overwrite the title, state, additions/deletions, assignees, and labels of another organization's tracked pull request in Shipit's database, as long as they can name an org with no configured `webhook_secret` in `repository.owner.login` and know/guess the victim's `repository.full_name` and PR `number`. This is a payload from one repository (attacker's, or a fictitious no-secret org) mutating another repository's/stack's persisted record — matching the "Critical: a payload for one repository mutating another's stack, commit, task or team" category. The blast radius depends on how many orgs in the Shipit deployment lack a configured `webhook_secret`; if at least one org is configured without a secret (or the attacker can register/claim such an org name in the multi-org config), every other org's PR/commit records tracked by Shipit become forgeable via this owner/full_name mismatch.

### Likelihood Explanation
Preconditions: the Shipit deployment must have at least one configured GitHub organization (in `Shipit.github_configurations` / `Shipit.github_teams`) with no `webhook_secret` set — a legitimate and plausible configuration choice for organizations that don't require verified webhooks (e.g. an org exists in config with only `oauth`/team info and no `webhook_secret` key). Given that, the attack requires no authentication, no valid GitHub signature, and no privileged Shipit role — only knowledge of the victim's `owner/repo` name and an existing PR number, both of which are typically public or easily discoverable. This is fully repeatable against arbitrary PRs in any repo tracked by Shipit, for every request.

### Recommendation
Enforce that `repository.owner.login` (used to select the signing org/secret) matches the owner segment of `repository.full_name` (used to resolve the actual `Repository`/`Stack`) before dispatching to handlers — e.g., derive `repository_owner` from `full_name.split('/').first` only, or explicitly reject requests where the two disagree, in `Shipit::WebhooksController#verify_signature`/`#repository_owner`. Additionally, consider requiring `webhook_secret` to be present for every configured org, or failing closed (rejecting, not auto-passing) when no secret is configured, in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
```ruby
# test/controllers/shipit/webhooks_controller_test.rb (illustrative minitest plan)
test "pull_request edited from a no-secret org can mutate another org's PullRequest via full_name mismatch" do
  # Setup: configure Shipit.github_configurations with:
  #   "attacker-org" => { app_id:, installation_id:, private_key: } # no webhook_secret
  #   "victim-org"   => { webhook_secret: "victim-secret", ... }
  victim_repo  = shipit_repositories(:shipit) # owner: "victim-org", name: "shipit"
  victim_stack = shipit_stacks(:shipit)
  victim_pr    = shipit_pull_requests(:one) # belongs_to victim_stack, number: 42, title: "Original title"

  payload = {
    action: "edited",
    number: victim_pr.number,
    pull_request: {
      id: victim_pr.github_id, number: victim_pr.number, url: "http://x",
      title: "PWNED BY ATTACKER", state: "open", additions: 1, deletions: 1,
      head: { sha: victim_stack.commits.last.sha, ref: "main" },
      user: { login: "attacker" }, assignees: [], labels: []
    },
    repository: { full_name: "#{victim_repo.owner}/#{victim_repo.name}", owner: { login: "attacker-org" } },
    sender: { login: "attacker" }
  }.to_json

  # BEFORE: victim_pr.title == "Original title"
  assert_equal "Original title", victim_pr.reload.title

  post :create, body: payload, params: {},
       headers: { "X-Github-Event" => "pull_request", "X-Hub-Signature" => "sha1=deadbeef" }

  assert_response :ok
  # AFTER: victim_pr.title mutated by attacker-controlled payload authenticated under "attacker-org"'s (absent) secret
  assert_equal "PWNED BY ATTACKER", victim_pr.reload.title
end
```

This demonstrates the equality `repository_owner` (used to select the verifying org secret) ≠ `owner segment of repository.full_name` (used to resolve the mutated repository/stack), and shows the persisted `PullRequest` for `victim-org` is written by a request authenticated (or auto-passed) under `attacker-org`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L41-65)
```ruby
          def process
            return unless respond_to_pull_request_edited?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end

          private

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

**File:** app/models/shipit/pull_request.rb (L36-61)
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

    def find_or_create_commit_from_github_by_sha!(sha)
      if commit = stack.commits.by_sha(sha)
        commit
      else
        github_commit = stack.github_api.commit(stack.github_repo_name, sha)
        stack.commits.create_from_github!(github_commit)
      end
    rescue ActiveRecord::RecordNotUnique
      retry
    end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
