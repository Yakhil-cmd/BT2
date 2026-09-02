### Title
Webhook signature verification selects the GitHub App/secret using an unverified payload field, decoupling "organization authenticated" from "repository written" - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary

### Finding Description
`WebhooksController#verify_signature` picks which `GitHubApp` (and thus which `webhook_secret`) to validate the request against by reading `repository_owner` straight out of the **unverified** JSON body, before any signature check has happened: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves this attacker-controlled string against the multi-tenant `github:` config block (documented for "Using Multiple Github Applications", where each org key has its own independent `webhook_secret`): [3](#0-2) 

Crucially, `GitHubApp#verify_webhook_signature` **short-circuits to `true` whenever the resolved organization has no `webhook_secret` configured**: [4](#0-3) 

Meanwhile, the field actually used by the event handlers to select *which repository/stack to act on* is a completely different key in the same untrusted payload — `repository.full_name`, unrelated to `repository.owner.login`: [5](#0-4) [6](#0-5) 

The binding that should hold is: `organization whose secret verified the request == organization owning the repository the handler mutates`. Nothing enforces this. An attacker can set `repository.owner.login` (or `organization.login`) to any org configured on the instance that happens to have a blank/unset `webhook_secret` — a state explicitly supported and documented in the example configs (`webhook_secret: # nil`) — while setting `repository.full_name` to a target repository belonging to a *different*, properly secured org on the same multi-tenant Shipit deployment. `verify_signature` resolves to the unsecured org, returns `true` unconditionally, and the handler then acts on the victim repository's stacks using data taken entirely from the attacker's payload. [7](#0-6) 

This is directly reachable by any unauthenticated caller of the public `POST /github/webhooks` (`WebhooksController#create`) endpoint — no `webhook_secret`, `ApiClient` token, session, or GitHub credential of any kind is required. [8](#0-7) 

### Impact Explanation
The most severe reachable consequence is via the `status` event handler, which writes a `Status` record (state, description, target_url, context) straight from the forged payload for the commit sha the attacker specifies: [9](#0-8) 

A commit's `deployable?` check depends on its aggregated CI status being `success?` and not `blocked?`: [10](#0-9) 

By forging a `state`/`status` webhook event that targets a victim stack's repository (via `repository.full_name`) while bypassing signature verification through an unsecured sibling organization (via `repository.owner.login`), an unauthenticated attacker can mark an arbitrary commit as `success`, satisfying the deployability gate and enabling an **unauthorized deploy** through the stack's normal continuous-delivery path — without ever possessing the victim organization's `webhook_secret`, private key, or any Shipit credential.

### Likelihood Explanation
Requires only: (1) the target Shipit instance uses the documented multi-organization `github:` config, and (2) at least one configured organization has no `webhook_secret` set (explicitly shown as the default/example value in the shipped config templates). Given no secret, token, or session is needed, exploitation is a single unauthenticated POST.

### Recommendation
Verify the webhook signature using the secret associated with the *repository actually referenced by the handler* (`repository.full_name`) or, better, validate the signature against every configured org/secret capable of owning that repository, rather than trusting an unverified field to select the verification key. Also consider rejecting webhooks for organizations configured with a blank `webhook_secret` in multi-tenant mode, since `verify_webhook_signature`'s "no secret configured" bypass is only safe in the single-tenant scheme.

### Proof of Concept
1. Configure Shipit with two orgs: `OrgA` (webhook_secret unset) and `OrgB` (properly configured, owns the target repo/stack).
2. POST to `/github/webhooks` with header `X-Github-Event: status`, body:
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" },
  "organization": { "login": "OrgA" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci",
  "target_url": "https://example.com"
}
```
No `X-Hub-Signature` needed to be valid — `Shipit.github(organization: "OrgA")` resolves to a `webhook_secret`-less app, so `verify_webhook_signature` returns `true` (`lib/shipit/github_app.rb:76-77`).
3. The status handler creates/updates a `Status` for `victim commit sha` in `OrgB/victim-repo`'s stack using attacker-supplied `state: "success"`, potentially making the commit `deployable?` and triggering an unauthorized deploy.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-63)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```
