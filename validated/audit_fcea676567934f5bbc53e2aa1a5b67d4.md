### Title
Webhook signature is validated against an org selected from an unauthenticated payload field, while handlers act on an unrelated repository field from the same payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App/`webhook_secret` used to validate the HMAC based on `params.dig('repository','owner','login')` (or `organization.login`), a field taken straight out of the untrusted, attacker-supplied JSON body. Once the signature check passes with that org's secret, the controller hands the *entire same payload* to the event handler, and the handlers resolve the target `Stack`/`Repository` using a **different** field of the same payload: `repository.full_name` [1](#0-0) . Nothing ties these two fields together, so the org whose secret authenticated the request is not necessarily the org whose repository gets acted upon.

### Finding Description
`verify_signature` resolves the app config with `Shipit.github(organization: repository_owner)` and `repository_owner` is derived purely from the JSON body: [2](#0-1) [3](#0-2) 

`Shipit.github` supports a multi-organization secrets schema where each org has its own independent `webhook_secret` [4](#0-3) . This is the documented way to run one Shipit instance for several GitHub orgs (`config/secrets.development.example.yml` shows the multi-org format).

After the signature is accepted, `create` passes the parsed body to the handler for the event, unchanged: [5](#0-4) 

The handler base class then locates the target repository using a *different* payload field — `repository.full_name` — with no re-check that its owner matches `repository_owner` used earlier for signature selection: [6](#0-5) 

Concretely, `PushHandler` uses `stacks` (derived from `repository.full_name`) to look up stacks and trigger `stack.sync_github` [7](#0-6) , and `StatusHandler` writes commit statuses purely from `sha`, entirely independent of any repository/org field [8](#0-7) .

**The binding that is broken:** the organization whose credential (webhook secret) authenticated the request ≠ the repository/stack the handler actually writes to. Attacker model: in a Shipit deployment configured for multiple GitHub orgs, the operator of Org A's own GitHub App integration knows Org A's `webhook_secret` (they configured/installed it themselves) — this is not a privileged Shipit credential, it's their own org's webhook signing secret, which they legitimately possess to run their own webhooks. They can craft an arbitrary JSON body where `repository.owner.login` (or `organization.login`) = `"OrgA"` (so `verify_signature` selects Org A's key and HMACs correctly with the secret they hold), but `repository.full_name` = `"OrgB/some-repo"` — a repository belonging to an org they do not control. Because the handler resolves the target purely from `full_name` via `Repository.from_github_repo_name`, and never compares it to `repository_owner`, the forged, validly-signed-by-OrgA payload can trigger `sync_github` jobs, commit status writes, or check-suite refreshes against OrgB's stacks.

### Impact Explanation
This is a cross-organization/cross-repository write achieved with a credential (webhook secret) that is scoped by the application's own design to one organization but is not actually enforced to match the repository being mutated. It lets a webhook signer for one tenant of a multi-org Shipit deployment forge events against another tenant's stacks (queueing syncs, injecting commit statuses that influence deploy/merge gating, or manipulating check-suite state) — an authorization boundary the application explicitly modeled (per-org `webhook_secret`) but failed to enforce end-to-end.

### Likelihood Explanation
Requires a Shipit instance configured with the multi-organization GitHub config schema (`github: <org>: webhook_secret: ...`) as documented, and requires the attacker to actually control/know one org's `webhook_secret` — this is the case for any org onboarded onto the shared instance, since they configure and possess their own secret. No privileged Shipit account, token, or GitHub App private key is needed.

### Recommendation
In `WebhooksController#verify_signature`/`create`, after resolving `repository_owner` and validating the signature, enforce that every repository/organization field consumed downstream (`repository.full_name`'s owner, or `organization.login`) is consistent with the `repository_owner` that selected the signing secret before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two orgs, `orga` and `orgb`, each with a distinct `webhook_secret`, per the multi-org schema in `lib/shipit.rb#github_app_config`.
2. As the legitimate owner/operator of `orga`'s GitHub App (who knows `orga`'s `webhook_secret`), craft a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen-sha>",
     "repository": { "owner": { "login": "orga" }, "full_name": "orgb/target-repo" }
   }
   ```
3. Compute `X-Hub-Signature: sha1=<hmac(orga_webhook_secret, body)>` and POST to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `Shipit.github(organization: "orga")` and the HMAC validates successfully.
5. `PushHandler.call(params)` resolves `stacks` via `Repository.from_github_repo_name("orgb/target-repo")` and calls `sync_github` against `orgb`'s stack, even though the request was only ever authenticated as `orga`.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

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
