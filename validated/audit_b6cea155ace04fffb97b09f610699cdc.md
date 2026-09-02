### Title
Webhook signature verified against the wrong organization's secret allows cross-organization/cross-repository writes - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/organization whose `webhook_secret` is used to validate `X-Hub-Signature` based on a value pulled from the *unverified* JSON body (`repository.owner.login` or `organization.login`). Every event handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) then independently re-reads `repository.full_name` from that same body to decide which `Repository`/`Stack` to act on. Because these two lookups are performed independently from the same attacker-controlled payload, nothing binds "the organization whose secret validated this HMAC" to "the repository the handler subsequently mutates."

### Finding Description
`verify_signature` computes `repository_owner` from the raw JSON body and fetches `Shipit.github(organization: repository_owner)` to validate the signature: [1](#0-0) [2](#0-1) 

Once the signature check passes, `WebhooksController#create` simply dispatches the raw parsed params to the handler for the event, without re-validating that the org used to verify the signature matches the repository targeted by the handler: [3](#0-2) 

Each handler independently derives the target `Repository`/`Stack` from `payload.dig('repository', 'full_name')`: [4](#0-3) 

For example, `PushHandler` calls `stack.sync_github(expected_head_sha: params.after)` for every non-archived stack on the branch of the resolved repository: [5](#0-4) 

Because Shipit supports multiple organizations, each with its own `github_app` config/`webhook_secret` (see `config/secrets.development.shopify.yml`), an attacker who legitimately controls one configured organization ("org A", i.e., they operate their own GitHub App installation registered in Shipit and know its `webhook_secret`) can craft a payload whose `repository.owner.login` is `"org-a"` (used only for signature verification) while `repository.full_name` is set to `"org-b/victim-repo"` (used by the handler to select the actual `Stack`/`Repository`). They sign the raw JSON with org A's real webhook secret, so `verify_webhook_signature` succeeds: [6](#0-5) 

The handler then resolves `Repository.from_github_repo_name("org-b/victim-repo")` and mutates stacks belonging to an organization the attacker never authenticated against: [7](#0-6) 

This breaks the intended binding: `organization that authenticated == repository that is written`. The signature only proves the payload was produced by someone holding org A's webhook secret; it proves nothing about org B, yet org B's stack data is written.

### Impact Explanation
Multiple handlers perform state-changing operations scoped only by the unverified `repository.full_name`/`organization.login` fields:
- `PushHandler` triggers `stack.sync_github(expected_head_sha:)` on victim stacks, which updates the stack's tracked head SHA from GitHub — this can be leveraged to advance/misalign a stack's known revision state, feeding into deploy eligibility (`Stack#trigger_continuous_delivery`, `undeployed_commits?`).
- `StatusHandler` creates commit statuses (`Commit#create_status_from_github!`) for arbitrary commits by `sha` regardless of the authenticating org, which can flip a commit's deployability/CI status (`deployable?`/`green?`) used to gate deploys.
- `CheckSuiteHandler` schedules check-run refresh for arbitrary stacks/commits.
- `MembershipHandler` creates/deletes `Team`/`Membership` records keyed off `organization.login` and `member.login` in the body, independent of the org that signed the request — since `authorized?` gates access based on `Shipit.github_teams` membership, an attacker signing with org A's secret could add an arbitrary GitHub login to a `Team` referenced by `organization.login` set to a victim org, potentially escalating that account into `Shipit.github_teams` authorization used across the app: [8](#0-7) [9](#0-8) 

This satisfies "cross-repository writes" (Critical) and "escalation into `Shipit.github_teams` authorization" (High), depending on the handler abused.

### Likelihood Explanation
Requires only that the attacker control one legitimately configured GitHub organization/App in the Shipit deployment (a normal, unprivileged tenant of a multi-org Shipit instance) and know that org's own `webhook_secret` — something they are entitled to as the owner of that org's GitHub App. No access to the victim org, no Shipit session, and no privileged Shipit account is needed. The only friction is that the attacker must know or guess a valid `owner/name` pair for a repository/stack tracked under the victim organization, which is typically public information (GitHub repo names are visible, and Shipit stack URLs like `/org/repo/env` are often discoverable).

### Recommendation
After `verify_signature` resolves the organization from the payload, re-verify that every subsequent lookup of `repository`/`organization` fields inside the handler uses the *same* organization that was authenticated, e.g., pass the verified `repository_owner` into `Handler.call`/`Handler#initialize` and assert `payload.dig('repository','owner','login') == verified_organization` (and, for `MembershipHandler`, that `params.organization.login == verified_organization`) before processing, rejecting mismatches with a 422.

### Proof of Concept
1. Configure Shipit with two GitHub orgs, `org-a` (attacker-controlled, webhook_secret known to attacker) and `org-b` (victim, has a tracked `Repository`/`Stack`).
2. Attacker crafts a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef...",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(org-a-webhook-secret, raw_body)` and POSTs to `/github/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `repository_owner = "org-a"`, fetches `Shipit.github(organization: "org-a")`, and the signature validates successfully (`verify_webhook_signature`, `app/controllers/shipit/webhooks_controller.rb:24-30`).
5. `PushHandler.call(params)` resolves `Repository.from_github_repo_name("org-b/victim-repo")` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`, `app/models/shipit/repository.rb:53-56`) and invokes `stack.sync_github(expected_head_sha: "deadbeef...")` on org B's stack — a write the attacker never authenticated for.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-43)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
