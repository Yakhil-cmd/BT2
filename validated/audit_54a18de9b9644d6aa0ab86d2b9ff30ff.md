### Title
`status` webhook accepted for a repository that never authenticated the request creates commit statuses on unrelated stacks - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App config for HMAC verification purely from the attacker-supplied `repository.owner.login`/`organization.login` field, and `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that org's `webhook_secret` is blank. `StatusHandler#process` then runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with no repository/stack scoping whatsoever, unlike sibling handlers (`PushHandler`, `CheckSuiteHandler`) which scope through `Repository.from_github_repo_name(repository_name)`.

### Finding Description
The broken binding: the code must guarantee `authenticated_repository == affected_repository`, i.e. only the repository whose secret authenticated the webhook may have its commits/stacks mutated. In `StatusHandler` this equality does not hold.

- `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) resolves `github_app = Shipit.github(organization: repository_owner)` using the attacker-controlled `repository_owner` value from the JSON body, then calls `github_app.verify_webhook_signature(...)`.
- `GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`) does `return true unless webhook_secret` — if the named organization is configured in Shipit but has no `webhook_secret` set (a legitimate, documented configuration state, see `test/dummy/config/secrets_double_github_app.yml`), any payload naming that org is accepted with **no HMAC check at all**.
- Once accepted, `Shipit::Webhooks.for_event('status').each { |handler| handler.call(params) }` dispatches to `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`):
  ```ruby
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
  ```
  This query is **global** across the `commits` table — it is not filtered by `stack_id`, `repository`, or anything derived from the payload's `repository` field, unlike `PushHandler#process` (`stacks.not_archived.where(branch:)...`) or `CheckSuiteHandler#process` (`stacks.where(branch: ...)`), both of which use the `Handler#stacks` helper that resolves `Repository.from_github_repo_name(repository_name)` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`).
- `Commit#create_status_from_github!` → `Status.replicate_from_github!` creates a `Status` row scoped to `commit.stack_id` (the *victim's* actual stack, not the attacker's named org/repo), and `Status` has `after_create :enable_ci_on_stack` and `after_commit :schedule_continuous_delivery` (`app/models/shipit/status.rb:18-19`), which can enqueue merge/deploy processing (`ProcessMergeRequestsJob`, confirmed in `test/models/commits_test.rb:773`) on the victim stack.

**Attacker's request**: `POST /webhooks` with `X-Github-Event: status`, a body whose `repository.owner.login`/`organization.login` is set to any org configured in Shipit with a blank `webhook_secret` (attacker doesn't need to control that org, only needs to know it exists in Shipit's config and lacks a secret — a config choice, not an attacker action), and `sha` set to the SHA of a commit that exists in a completely different, victim stack (SHAs are public, discoverable via the victim's PRs/commits), plus a favorable `state`/`context` matching what the victim stack's CI or merge automation expects.

**Why existing guards fail**: `verify_signature` only checks the org named in the forged payload, not the org that actually owns the target commit/stack; `drop_unhandled_event` and `ExplicitParameters` schema checks pass (the `status` schema only requires `sha`, `state`, etc., not `repository`); `StatusHandler` never calls `Repository.from_github_repo_name` or filters by `stacks`, so there is no code path that ties the authenticated organization to the mutated stack.

### Impact Explanation
An attacker who can name any Shipit-configured, secret-less GitHub organization can forge `status` events that create `Status` records for commits belonging to **any other stack in the installation**, including a bot-login-configured victim stack, without possessing that stack's/org's webhook secret. This can trigger `schedule_continuous_delivery`/`ProcessMergeRequestsJob` and downstream auto-merge/auto-deploy machinery that executes as the Shipit bot identity — this is a cross-tenant payload mutating another repository's commit/stack state, matching the Critical category "a payload for one repository mutating another's stack, commit, task" and potentially leading to unauthorized deploy/merge.

### Likelihood Explanation
Preconditions: (1) Shipit must be configured with at least one organization entry that has a blank/nil `webhook_secret` — this is an explicitly supported and documented configuration (`docs/setup.md:30` notes the secret is "optional"; the repo's own multi-org fixture `test/dummy/config/secrets_double_github_app.yml` has both orgs with `webhook_secret: # nil`); (2) attacker needs the target commit SHA, which is typically public. Given these, the attack is trivial and repeatable against any number of victim stacks/commits with a single unauthenticated POST per forged status, requiring no session, token, or GitHub credentials.

### Recommendation
`StatusHandler` (and any handler using bare `Commit.where(sha:)`) must scope lookups through the repository named in the authenticated webhook payload, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or equivalently restrict to `Repository.from_github_repo_name(payload.dig('repository','full_name')).stacks.joins(:commits).where(commits: { sha: params.sha })`, mirroring `PushHandler`/`CheckSuiteHandler`. Additionally, `verify_webhook_signature` returning `true` for organizations with blank secrets should be revisited/require an explicit opt-in, since it defeats webhook authentication for any such org.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` or `test/models/shipit/webhooks/handlers_test.rb`):
```ruby
test ":status from a no-secret organization creates a status on an unrelated victim stack" do
  # Setup: two orgs in Shipit config, "no-secret-org" has webhook_secret: nil (as in secrets_double_github_app.yml)
  victim_commit = shipit_commits(:first)             # belongs to victim stack with bot_login configured
  refute_equal victim_commit.stack.repository.owner, "no-secret-org"

  request.headers['X-Github-Event'] = 'status'
  body = {
    "sha" => victim_commit.sha,
    "state" => "success",
    "context" => "ci/attacker",
    "repository" => { "full_name" => "no-secret-org/unrelated-repo",
                       "owner" => { "login" => "no-secret-org" } }
  }.to_json

  assert_difference -> { victim_commit.statuses.count }, 1 do
    post :create, body:, as: :json
  end
  assert_response :ok
  # Binding check: authenticated_repository ("no-secret-org/unrelated-repo")
  # != affected_repository (victim_commit.stack.repository.full_name) yet mutation occurred.
end
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L16-34)
```ruby
    validates :state, inclusion: { in: STATES, allow_blank: true }, presence: true

    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-46)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S
        73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG
        M0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv
        ibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu
        pQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s
        Gu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1
        u0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM
        TZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b
        qicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og
        qRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI
        Rsn3r6ajlpwzpwvsJFU2Txq7xBTzGQMFmy/Pnjk83kP2cogxB2+tRyjITGqTwD8b
        gg9PFCkCgYEA+7u8A0l0Cz6p0SI6c7ftVePVRiIhpawWN7og/wEmI6zUjm/3rA+R
        hrhaVKuOD8QF/HdDsqTck5gjGAjTmJz6r33/cl1Tz+pr62znsrB4r0yMKvQbKN81
        WGaWOsi2+ZXqLNv5h5wpUF0MTKlXHeKnwP5kuEvGwVn6WURFCh6PhLMCgYEA8i5e
        JjulJVGyd5HuoY3xyO7E6DjidsqRnVRq+hYpORjnHvTmSwe4+tH4ha2p9Kv2Y6k3
        C1NYY/fSMQoYCCRaYyJleI+la/9tsZqAmtms4ZB8KhFmPHf9fW75i6G0xKWyZ8K+
        E2Ft/UaEiM282593cguV6+Kt5uExnyPxLLK4FlUCgYEAwRJ/JGI8/7bjFkTTYheq
        j5q75BufhOrU6471acAe2XPgXxLfefdC3Xodxh0CS3NESBvNL4Ikr4sbN37lk4Kq
        /th7iOKtuqUIeru/hZy2I3VpeDRbdGCmEJQ2GwYA2LKztg5Nd0Y9paaIHXAwIfrK
        QUqcQ4HTAk8ZpUeoUBeaaeMCgYANLmbjb9WiPVsYVPIHCwHA7PX8qbPxwT7BsGmO
        KQyfVfKmZa/vH4F67Vi4deZNMdrcO8aKMEQcVM2065a5QrlEsgeR00eupB1lUEJ1
        qylUsZeAdqf43JMIc7TTW77KATa/nQLZbTEeWus1wvTngztuEqFbUGAks9cOkVc8
        FpIcbQKBgQDVIL8gPLmn0f+4oLF8MBC+oxtKpz14X5iJ1saGFkzW5I+nIEskpS0S
        qtirnTCnJFGdCrFwctnxiuiCmyGwpBYdjIfHyvYAHnqAtMnESzCUyeSFZiquVW5W
        MvbMmDPoV27XOHU9kIq6NXtfrkpufiyo6/VEYWozXalxKLNuqLYfPQ==
        -----END RSA PRIVATE KEY-----
      oauth:
        id: Iv1.bf2c2c45b449bfd9
        secret: ef694cd6e45223075d78d138ef014049052665f1
        teams:
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
