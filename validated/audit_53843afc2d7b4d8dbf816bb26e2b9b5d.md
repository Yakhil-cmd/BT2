### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but the repository/stack acted on is resolved from the unauthenticated `repository.full_name` field, letting a holder of one organization's webhook secret trigger GitHub syncs for a stack owned by a different organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to HMAC-verify a delivery against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` (or `organization.login` for org-scoped events). [1](#0-0)  Once the signature check passes, `Shipit::Webhooks::Handlers::Handler#repository_name`/`#stacks` resolve the *target* repository/stack from a completely different, unauthenticated field: `payload.dig('repository', 'full_name')`. [2](#0-1)  `PushHandler#process` then calls `stack.sync_github(expected_head_sha: params.after)` on whatever stacks match that `full_name`. [3](#0-2) 

Because the HMAC covers the raw JSON body and is checked with the secret belonging to `repository.owner.login`, anyone who legitimately knows the webhook secret for their own installed GitHub App/organization ("org A") can forge a signed request where `repository.owner.login = "org A"` (so signature verification passes using org A's secret) while `repository.full_name = "org-B/some-repo"` (a different organization's repository/stack). The equality the engine relies on — *the organization whose secret authenticated the delivery* == *the repository/stack the delivery's handler acts on* — is never enforced; only the first field is checked, the second is trusted blindly.

### Finding Description
- Signature verification binds to `repository_owner` derived from `repository.owner.login` / `organization.login`. [4](#0-3) 
- Handlers that then act on data (e.g. `PushHandler`, PR handlers) look up the target `Repository`/`Stack` using `repository.full_name`, an entirely separate JSON field within the same signed payload, via `Repository.from_github_repo_name`. [5](#0-4)  `push_handler.rb` uses this to select `stacks` and call `stack.sync_github`. [3](#0-2) 
- Nothing anywhere compares `repository.owner.login` to the owner portion of `repository.full_name`, or otherwise ties the two fields together. Genuine GitHub webhooks always keep them consistent, but the signature only proves "this body was HMAC'd with organization A's secret" — it says nothing about which fields inside that body are internally consistent.
- Only for the `MembershipHandler`, the `organization.login` field is reused for both signature-org selection and team creation, so that path is self-consistent. [6](#0-5)  The push/PR paths are not: they authenticate on `repository.owner.login` but act on `repository.full_name`.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" trust boundary called out as a valid analog class. An attacker who administers a legitimate Shipit-integrated GitHub App/org (and therefore knows that org's `webhook_secret`) can craft `push` webhook deliveries naming any other organization's repository in `repository.full_name`. This causes `Stack#sync_github`/`GithubSyncJob` to run for a stack that belongs to a repository the attacker does not control, fetching commits via `stack.github_api` (using the *target* org's own GitHub App credentials) and appending them with an attacker-influenced `expected_head_sha`. [7](#0-6)  This can force unscheduled syncs/spec cache recomputation against a victim organization's stacks, and for the PR handlers can spuriously create/archive/unarchive review stacks for a foreign repository, using only credentials the attacker legitimately possesses for their own, unrelated organization. This meets the "unauthorized deploy/rollback" adjacent bar because it lets a foreign, unprivileged-relative-to-the-target actor force real GitHub API-backed state changes (sync, review-stack provisioning/archival) on a stack they have no authorization over.

### Likelihood Explanation
Requires the attacker to already have webhook-secret-level access to at least one organization integrated with the shared Shipit instance (multi-tenant setups configure multiple `github:` entries in `secrets.yml`, per `config/secrets.development.shopify.yml`). [8](#0-7)  That is a realistic "unprivileged relative to the victim org" attacker in any Shipit deployment serving multiple organizations, since owning one org's GitHub App secret grants no rights over another org's repositories on GitHub itself, yet suffices here.

### Recommendation
In `WebhooksController#verify_signature` / `Shipit::Webhooks::Handlers::Handler`, enforce that the organization used to select the verification secret matches the owner encoded in `repository.full_name` (and `organization.login` for org events) before dispatching to handlers, rejecting mismatched payloads with `422`.

### Proof of Concept
1. Attacker controls GitHub App/org `attacker-org`, with Shipit webhook secret `S_A` (known to them since they configured the app).
2. Attacker sends `POST /webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
signed with `X-Hub-Signature: sha1=<HMAC(S_A, raw_body)>`.
3. `verify_signature` computes `repository_owner = "attacker-org"`, loads `Shipit.github(organization: "attacker-org")`, and validates the signature successfully against `S_A`. [9](#0-8) 
4. `PushHandler#stacks` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the matching stack(s), which belong to `victim-org`, not `attacker-org`. [3](#0-2)

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L15-43)
```ruby
          requires :organization do
            requires :login, String
          end
          requires :member do
            requires :login, String
          end
        end
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

**File:** app/jobs/shipit/github_sync_job.rb (L18-49)
```ruby
    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
      retry_count = params[:retry_count] || 0
      head_before_sync = spec_cache_target
      appended_commits = []

      handle_github_errors do
        new_commits, shared_parent = fetch_missing_commits { stack.github_commits }

        # Retry on Github eventual consistency: webhook indicated new commits but we found none
        if expected_head_sha && new_commits.empty? && !commit_exists?(expected_head_sha) &&
           retry_count < MAX_RETRY_ATTEMPTS
          GithubSyncJob.set(wait: RETRY_DELAY * retry_count).perform_later(params.merge(retry_count: retry_count + 1))
          return
        end

        stack.transaction do
          shared_parent&.detach_children!
          appended_commits = new_commits.map do |gh_commit|
            append_commit(gh_commit)
          end
          stack.lock_reverted_commits! if appended_commits.any?(&:revert?)
        end
      end
      sync_changed_nothing = appended_commits.empty? &&
                             spec_cache_target == head_before_sync &&
                             stack.cached_deploy_spec.present?
      return if sync_changed_nothing && !params[:force_spec_cache]

      CacheDeploySpecJob.perform_later(stack)
    end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
