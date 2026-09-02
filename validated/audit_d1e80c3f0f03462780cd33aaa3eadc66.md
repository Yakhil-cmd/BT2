## Title
Webhook signature verification authenticates a different organization than the repository the event is applied to, allowing cross-tenant webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

## Summary
In `Shipit::WebhooksController#verify_signature`, the GitHub organization whose `webhook_secret` is used to validate the HMAC signature is derived from the `repository.owner.login` (or `organization.login`) field of the *unverified* JSON body. [1](#0-0) [2](#0-1)  However, every event `Handler` resolves the target `Stack`(s) using a *different* field of the same body — `repository.full_name` — via `Handler#repository_name`/`Handler#stacks`. [3](#0-2)  These two fields are never cross-validated against each other, so a valid signature for organization A does not guarantee the payload actually pertains to a repository owned by organization A.

## Finding Description
`Shipit.github(organization:)` looks up a distinct GitHub App configuration (and thus a distinct `webhook_secret`) per organization key in `secrets.yml`, which is the documented multi-tenant configuration schema for this engine. [4](#0-3) 

`verify_signature` computes `repository_owner` purely from attacker-controlled JSON (`params.dig('repository','owner','login')` or `params.dig('organization','login')`) *before* any authenticity is established, uses it to select which organization's secret to check the `X-Hub-Signature` HMAC against, and only rejects the request if that specific org's secret fails to validate:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [5](#0-4) 

Once the signature is accepted, the request is dispatched to handlers (`PushHandler`, `MembershipHandler`, `CheckSuiteHandler`, status handler, pull-request handlers, etc.), all of which derive the acted-upon repository/stack from `Handler#stacks`, which reads `payload.dig('repository', 'full_name')` instead:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end
def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

This is precisely the analog described in the rules: the organization that authenticated the request (via `repository.owner.login` / `organization.login`, matched against a specific org's `webhook_secret`) is not the same field as the repository whose stacks the handler writes to (`repository.full_name`). Nothing forces `full_name`'s owner segment to equal `repository.owner.login`.

**Attack path:** In a multi-organization Shipit deployment, an attacker who legitimately administers one tenant organization ("OrgA", with a known `webhook_secret`, e.g. because they configured it themselves when onboarding OrgA) can craft an arbitrary raw JSON body where:
- `repository.owner.login` (or `organization.login`) = `"orga"` — selects OrgA's secret for signature verification, which the attacker can correctly compute.
- `repository.full_name` = `"orgb/victim-repo"` — points to a completely different, victim-owned repository/stack.

The signature check passes because it only validates that the body was signed with OrgA's secret; it never checks that OrgA actually owns `orgb/victim-repo`. The event handler then acts on the victim's stack(s) using attacker-supplied fields (e.g. `PushHandler` calling `stack.sync_github(expected_head_sha: params.after)` [6](#0-5) , `MembershipHandler` mutating team membership for the `organization.login` in the body [7](#0-6) , or a forged `status` event creating a CI status object on a specific commit sha of the victim's stack, as validated by `WebhooksControllerTest`'s `:state create a Status for the specific commit` test). [8](#0-7) 

## Impact Explanation
This breaks a deployment-trust binding: "an organization that authenticated versus the repository that is written." An attacker who is not authorized on the victim organization's GitHub App/webhook can nonetheless inject webhook-driven state changes into the victim's stacks — including forging commit-status ("green CI") events that gate `continuous_deployment`, potentially causing an unauthorized deploy to proceed, or forging `push`/`check_suite` events that force resyncs, CI-check refreshes, or (via `MembershipHandler`) team membership changes cross-tenant. This lands in the Critical/High bucket described by the rules (unauthorized deploy / escalation of authorization state), since it is a genuine cross-repository (cross-tenant) write achieved purely by exploiting a mismatch between two unrelated fields of the same JSON body.

## Likelihood Explanation
Requires only that the Shipit instance be configured with more than one GitHub organization (the documented multi-org `secrets.yml` schema in `lib/shipit.rb#github_app_config`), and that the attacker legitimately controls (or has the webhook secret for) at least one of those organizations — a realistic scenario for any shared/self-service Shipit deployment serving multiple teams/orgs. No victim secrets, tokens, or GitHub credentials are needed.

## Recommendation
After verifying the signature, cross-check that `repository.owner.login` (the value used to select the verifying organization) matches the owner segment of `repository.full_name` (the value used to resolve the target `Repository`/`Stack`) before dispatching to any handler; reject the request if they diverge.

## Proof of Concept
1. Configure Shipit with two organizations in `secrets.yml`, `orga` and `orgb`, each with its own `webhook_secret`.
2. As an administrator of `orga` (attacker), compute `X-Hub-Signature = HMAC-SHA1(orga_webhook_secret, body)` for body:
```json
{
  "sha": "<commit-sha-existing-in-orgb/victim-repo-stack>",
  "state": "success",
  "target_url": "https://attacker.example/fake-ci",
  "description": "forged",
  "context": "ci/forged",
  "created_at": "2026-09-01T00:00:00Z",
  "repository": { "owner": { "login": "orga" }, "full_name": "orgb/victim-repo" }
}
```
3. POST to `/webhooks` with `X-Github-Event: status` and the computed signature.
4. `verify_signature` validates against `orga`'s secret and succeeds; the status handler resolves stacks via `repository.full_name = "orgb/victim-repo"` and creates/marks a passing CI status on the victim's commit, despite the attacker never being authenticated against `orgb`.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
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
