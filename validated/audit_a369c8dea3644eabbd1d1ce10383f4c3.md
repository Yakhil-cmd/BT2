### Title
`StatusHandler#process` updates commit status for every stack sharing a sha, with no repository-identity check - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits by `sha` alone (`Commit.where(sha: params.sha).each`) and never compares the webhook's signing repository to the target commit's repository. The base `Handler#initialize`/params contract for this handler does not even require a `repository` key, so there is no way to enforce (signing repository == target repository) before mutating `Commit`/`Status` rows.

### Finding Description
Binding that should hold: `signing_repository.full_name == commit.stack.repository.full_name` for every `Commit`/`Status` row written by a status webhook. What the code actually enforces: `commit.sha == payload['sha']`, full stop.

- `StatusHandler#params` only requires `:sha`, `:state`, and optional `:description`/`:target_url`/`:context`/`:created_at`/`:branches` — no `:repository` field is declared at all: [1](#0-0) .
- `#process` resolves target commits purely by `sha`, iterating over *every* matching `Commit` row across the entire database and writing a status to each: [2](#0-1) . The `.each` loop itself is evidence the code anticipates multiple `Commit` rows (i.e., multiple stacks/repositories) sharing the same sha, yet applies no repository filter.
- `Handler#initialize` only parses `payload` into `params` via the declared schema; it performs no identity check between the webhook's origin and the target of the mutation: [3](#0-2) . The base class does expose a `repository_name`/`stacks` helper that other handlers (`PullRequest::*Handler`) use to scope lookups to `Repository.from_github_repo_name(params.repository.full_name)`, but `StatusHandler` never calls it: [4](#0-3) .
- Upstream, `verify_signature` in `WebhooksController` only proves the payload was signed with the webhook secret configured for the *organization* named in `repository.owner.login`/`organization.login` — it never checks that the signed repository matches the repository whose commit is later mutated: [5](#0-4) . Because `GitHubApp#verify_webhook_signature` is keyed per configured organization (`@webhook_secret = @config[:webhook_secret]`), any repository under that same organization — including one an unprivileged member creates/owns — produces a validly-signed `status` webhook: [6](#0-5) .
- A successful match drives real mutation with side effects: `create_status_from_github!` → `add_status` emits `commit_status`/`deployable_status` hooks and calls `stack.schedule_merges` when the new status is pending/success, i.e., it can advance merge/deploy automation for a stack the attacker never authenticated against: [7](#0-6) .

Exploit flow: an attacker who owns or can create a repository within the same GitHub organization that Shipit's `GitHubApp` is configured for (unprivileged member, no Shipit secrets) forks/mirrors a repository whose commits are tracked by a different Shipit stack, preserving identical commit shas. The attacker then triggers (or fabricates via GitHub's API on their own repo) a `status` event for that shared sha on their own repository. GitHub signs and delivers the webhook with the organization's real `webhook_secret`, so `verify_signature` passes. `StatusHandler.call(payload)` is invoked with a payload that never needed a `repository` key to satisfy its own `ExplicitParameters` schema, and `#process` updates the `Commit`/`Status` rows for **every** stack that has a commit with that sha — including the victim's stack, which the attacker's webhook never authenticated for.

### Impact Explanation
A payload legitimately signed for the attacker's own repository mutates `Commit`/`Status` records belonging to an unrelated repository/stack, and can flip commit state to `success`, triggering `stack.schedule_merges` and downstream continuous-deployment/merge automation for a repository the attacker does not control. This matches the Critical category "a payload for one repository mutating another's stack, commit ... or an unauthorized deploy." It is repeatable against any stack whose tracked repository shares a sha with a repository the attacker controls under the same organization, not limited to a single victim.

### Likelihood Explanation
Preconditions: the attacker needs write/webhook-triggering access to some repository under the same GitHub organization/app-configuration as the victim stack (e.g., an org member creating a new repo, or forking within the org), and a commit sha that is shared between that repository and the victim's tracked commit (trivial via fork/mirror/cherry-pick-preserving-parents). No Shipit session, API token, or secret is required — the webhook signature is legitimately produced by GitHub for the attacker's own repository. This is moderate-cost but fully within the stated unprivileged threat model wherever an organization's GitHub App/webhook secret is shared across multiple repositories (the common configuration, per `Shipit.github(organization:)`/`GitHubApp` above).

### Recommendation
`StatusHandler#params` should require a `:repository` block (as every `PullRequest::*Handler` already does) and `#process` should scope the `Commit` lookup to commits belonging to stacks whose repository matches `params.repository.full_name` (e.g., `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { ... full_name match ...})`), mirroring the `repository_name`/`stacks` helper already defined on `Handler`.

### Proof of Concept
`test/models/shipit/webhooks/handlers/status_handler_test.rb` (new or extended, minitest, no live GitHub):
1. Create two stacks/repositories, `stack_a` (repo `"org/repo-a"`) and `stack_b` (repo `"org/repo-b"`), each with a `Commit` row sharing the same `sha` value (e.g., `"deadbeef"`).
2. Build a payload identical to `test/fixtures/payloads/status_master.json` shape but whose `"repository"`/`"name"` field (if included) names only `repo-b`, or omit `repository` entirely (valid per the handler's `ExplicitParameters` schema, since `:repository` is never declared).
3. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly.
4. Assert: `stack_a.commits.find_by(sha: "deadbeef").statuses.count` increased and its `state` reflects the payload — i.e., a payload that only ever named/authenticated `repo-b` mutated `stack_a`'s commit, proving `(sha match)` was substituted for `(signing repository == target repository)`.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L15-24)
```ruby
        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

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

**File:** lib/shipit/github_app.rb (L44-83)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
    end

    def login
      raise NotImplementedError, 'Handle App login / user'
    end

    def api
      client = (Thread.current[:github_client] ||= new_client(access_token: token))
      client.access_token = token if client.access_token != token
      client
    end

    def api_status
      conn = Faraday.new(url: 'https://www.githubstatus.com')
      response = conn.get('/api/v2/components.json')
      parsed = JSON.parse(response.body, symbolize_names: true)
      parsed[:components].find { |c| c[:id] == API_STATUS_ID }
    end

    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```
