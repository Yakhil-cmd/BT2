### Title
Webhook signature verification is fully bypassed when an organization's `webhook_secret` is unset, allowing unauthenticated forgery of GitHub events that write commit statuses and team/user membership - ([File: lib/shipit/github_app.rb])

### Summary
`WebhooksController#verify_signature` derives the organization to authenticate against solely from attacker-controlled payload fields, then delegates to `GitHubApp#verify_webhook_signature`, which unconditionally returns `true` whenever that organization's `webhook_secret` is blank/unset — meaning the signature header is never actually checked in that case.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App config to verify against using `repository_owner`, which is read directly from the untrusted JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`), and then calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` is the actual signature check:
```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [3](#0-2) 

If the organization resolved from the attacker-supplied `repository.owner.login` / `organization.login` field has no `webhook_secret` configured, verification is vacuously `true` for *any* signature (including a missing or garbage one), and the request proceeds to `create`, which dispatches to all registered handlers for the claimed event. [4](#0-3) 

This breaks exactly the trust binding the rules call out: "an organization that authenticated versus the repository that is written." The side that is supposed to be verified (the claimed organization/repository) and the side actually written to by handlers (`payload.dig('repository', 'full_name')` in `Handler#repository_name`, or the raw `member`/`team` payload in the membership handler) are never cryptographically tied together when the org has no secret — the "authentication" step is a no-op. [5](#0-4) 

Concretely reachable handlers once verification is bypassed:
- `StatusHandler#process` creates a `Commit::Status` from fully attacker-controlled `state`/`context`/`sha` fields for any commit that exists in the database, regardless of which repository it actually belongs to. [6](#0-5) 
- The `membership` event handler creates `Team` and `User` records on the fly from the payload, as shown by existing tests exercising this exact behavior. [7](#0-6) 

Because `Shipit.github_teams` membership drives `current_user.authorized?` in `force_github_authentication`, and access decisions are ultimately gated by team membership, forged `membership` events reaching this authorization surface without a valid signature is a real escalation path. [8](#0-7) 

### Impact Explanation
An unauthenticated attacker who knows (or guesses) an organization slug configured in this Shipit instance without a `webhook_secret` can:
- Forge CI `status` events to create arbitrary commit statuses, which is the exact signal `Stack`/`Commit` deployability and CI-gating logic relies on before allowing deploys — a path toward an unauthorized deploy.
- Forge `membership` events to create/attach users and teams, feeding into the `Shipit.github_teams` authorization check that gates access to the entire application.

This matches the report's Critical/High bar: escalation into `Shipit.github_teams` authorization, and a path to an unauthorized deploy via forged deployable-status signals — achieved without any session, `ApiClient` token, or `webhook_secret` knowledge, satisfying the "unprivileged attacker" requirement.

### Likelihood Explanation
Likelihood depends entirely on deployment configuration: it is only exploitable for organizations whose GitHub App config in `Shipit.github` omits `webhook_secret`. The engine code and documentation treat `webhook_secret` as an optional config key rather than a mandatory one, and the fallback behavior (`return true unless webhook_secret`) silently disables authentication instead of failing closed. Any multi-organization Shipit deployment where at least one configured org lacks a secret is immediately exposed on its public `/webhooks` endpoint.

### Recommendation
Fail closed instead of open: `GitHubApp#verify_webhook_signature` should reject (return `false`) when `webhook_secret` is blank, rather than treating a missing secret as an automatic pass. If truly optional per-organization secrets are a supported configuration, the controller should refuse to process any state-changing webhook event for organizations without a configured secret, and this should be enforced/validated at configuration-load time rather than silently degrading to "always verified."

### Proof of Concept
1. Deploy Shipit with at least two configured GitHub organizations, where organization `victim-org` has no `webhook_secret` set in its `Shipit.github` config.
2. Send an unsigned (or arbitrarily signed) `POST /webhooks` request with header `X-Github-Event: status` and body:
```json
{
  "sha": "<existing tracked commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "victim-org" }, "full_name": "victim-org/some-repo" }
}
```
3. `verify_signature` resolves `repository_owner` = `victim-org`, calls `verify_webhook_signature`, which returns `true` unconditionally because `webhook_secret` is blank for `victim-org`.
4. `StatusHandler#process` creates a forged `success` status on the target commit, as confirmed by `Shipit::Commit#create_status_from_github!` (see `app/models/shipit/commit.rb`), potentially satisfying CI-gating requirements that would otherwise block a deploy. [6](#0-5) [3](#0-2)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** test/controllers/webhooks_controller_test.rb (L129-149)
```ruby
    test ":membership creates the mentioned team on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Team.count }, 1 do
        post :create, as: :json, body: membership_params.merge(team: {
                                                                 id: 48,
                                                                 name: 'Ouiche Cooks',
                                                                 slug: 'ouiche-cooks',
                                                                 url: 'https://example.com'
                                                               }).to_json
        assert_response :ok
      end
    end

    test ":membership creates the mentioned user on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      Shipit.github.api.expects(:user).with('george').returns(george)
      assert_difference -> { User.count }, 1 do
        post :create, body: membership_params.merge(member: { login: 'george' }).to_json, as: :json
        assert_response :ok
      end
    end
```

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
```
