This confirms Shipit's multi-tenant GitHub App configuration model: `Shipit.github(organization:)` selects a distinct `GitHubApp` (with its own `webhook_secret`) per configured organization, keyed by `secrets.github` [1](#0-0) . This produces a valid analog of the reported bug class ("an organization that authenticated versus the repository that is written").

### Title
Webhook signature is verified against `repository.owner.login`, but events are processed against `repository.full_name` for any org - cross-tenant webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the HMAC against using the attacker-controlled JSON body itself, then every event `Handler` resolves the target `Stack`/`Repository` from a *different* field of that same untrusted body. The two fields are never cross-checked, so a valid signature for organization A authorizes writes against organization B's repositories.

### Finding Description
`verify_signature` parses the raw, still-unauthenticated request body and picks the GitHub App/secret with `Shipit.github(organization: repository_owner)`, where `repository_owner` is `params.dig('repository','owner','login')` (or `organization.login`) — both attacker-supplied fields read before any signature check occurs [2](#0-1) . It then verifies the raw body's HMAC against that org's `webhook_secret` [3](#0-2) .

Once verification passes, `Handler#stacks` resolves the affected repository from a **different** JSON path: `payload.dig('repository', 'full_name')` [4](#0-3) . Nothing enforces that `repository.full_name`'s owner segment matches `repository.owner.login`/`organization.login` used for signature selection.

Because the entire raw body is attacker-supplied before verification, anyone who knows the `webhook_secret` for organization A (e.g., a legitimate GitHub org admin who configured that org's own webhook in this shared Shipit instance) can craft a payload where `repository.owner.login = "orgA"` (so it authenticates with orgA's secret) but `repository.full_name = "orgB/some-repo"` (an unrelated tenant's repo tracked in this Shipit engine). The signature check passes, and the handler acts on org B's stack — a genuine "organization that authenticated" vs. "repository that is written" binding break, exactly matching the requested analog class.

### Impact Explanation
This breaks tenant isolation between GitHub organizations sharing one Shipit deployment:
- `push` events fabricated this way trigger `GithubSyncJob`/`sync_github` on org B's stacks via `PushHandler#process` [5](#0-4) , which can advance/refresh the tracked ref used to gate deploys.
- `status`/`check_suite`/`merge_status`-class events can inject fabricated commit statuses onto org B's commits (`StatusHandler#process` writes `commit.create_status_from_github!`), potentially flipping "deployable" checks that other automation or humans rely on to authorize a deploy/merge [6](#0-5) .
- `membership` events can create teams/users tied to org B under attacker control, as seen in the existing test coverage of that handler [7](#0-6) .

This does not itself grant `GITHUB_TOKEN`/API write access, but it lets an org-A-privileged actor manipulate state (sync status, fabricated commit statuses, ref advancement) that downstream Shipit logic uses to gate deploys/rollbacks on org B's stacks — an unauthorized-deploy-adjacent impact through cross-tenant data injection, without ever holding write access, an `ApiClient` token, or a privileged account on org B.

### Likelihood Explanation
Requires the attacker to control (or know) the `webhook_secret` of any organization configured on the same multi-tenant Shipit instance — a realistic scenario for hosted/shared Shipit deployments serving multiple GitHub orgs, since organization admins configuring their own GitHub App/webhook naturally know their own secret. No compromise of org B's credentials, GitHub App keys, or Shipit session is required.

### Recommendation
After locating the config via `repository_owner`, re-derive the same owner from `repository.full_name` (or `organization.login`) and reject the request (422) if it does not match the owner used to select the `webhook_secret`, ensuring the authenticated organization and the mutated repository always resolve to the same owner.

### Proof of Concept
1. Shipit instance configured with two orgs in `secrets.github`: `orgA` (attacker knows its `webhook_secret`) and `orgB` (attacker has no access), each with tracked stacks.
2. Attacker crafts JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen sha>",
     "repository": { "owner": {"login": "orgA"}, "full_name": "orgB/victim-repo" }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(orgA_webhook_secret, body)` and sends it with `X-Github-Event: push` to `POST /github_webhooks`.
4. `verify_signature` resolves `repository_owner = "orgA"`, validates the HMAC successfully against orgA's secret [8](#0-7) .
5. `PushHandler#stacks` resolves `Repository.from_github_repo_name("orgB/victim-repo")` and calls `sync_github` on org B's stack, even though the request never authenticated against org B's secret [4](#0-3) , [5](#0-4) .

### Citations

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** test/controllers/webhooks_controller_test.rb (L129-140)
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
```
