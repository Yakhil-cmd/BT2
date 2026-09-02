### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but the record that is actually mutated is selected by the unrelated `repository.full_name` field — allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* organization's GitHub App / `webhook_secret` to validate the HMAC against by reading `repository.owner.login` (or `organization.login`) straight out of the still-unverified JSON body. [1](#0-0) [2](#0-1)  Once the signature "passes," every handler (`PushHandler`, status handler, etc.) determines *which* `Repository`/`Stack` to act on using a completely different field of the same body: `repository.full_name`. [3](#0-2)  Nothing ties these two fields together, so the organization whose secret authenticated the request is never checked against the repository that is actually written to.

### Finding Description
The signature check is:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [4](#0-3) 

Handlers, however, resolve the target `Repository`/`Stack` from a different field:

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

`Repository.from_github_repo_name` splits `owner/name` from `full_name` and does a plain DB lookup, so it can resolve to any organization's repository, not necessarily the one used for signature verification. [5](#0-4) 

This is the exact "organization that authenticated versus the repository that is written" binding: the HMAC only proves the request was signed with **org A's** secret; it proves nothing about the `repository.full_name` value the handlers subsequently act on. Because `Shipit.github(organization: ...)` explicitly supports per-organization GitHub Apps/secrets (evidenced by `GithubOrganizationUnknown` handling and org-scoped stubs in tests, e.g. `Shipit.github(organization: 'shopify')`), [6](#0-5) [7](#0-6)  a Shipit instance onboarding multiple organizations has, per organization, an independently known `webhook_secret` — legitimately known to any admin who installed that org's own GitHub App.

An attacker who administers Organization A's GitHub App installation (a routine, unprivileged-w.r.t.-the-victim action, and required by Shipit's own documented setup flow for every org owner) knows Org A's `webhook_secret`. [8](#0-7)  They can craft a JSON body where `repository.owner.login = "org-a"` (so the signature is computed/verified with the secret they legitimately hold) while `repository.full_name = "victim-org/victim-repo"`. `verify_signature` succeeds; every downstream handler then looks up and mutates the victim's `Repository`/`Stack` using `full_name`.

The `status` webhook handler is the most severe instance: it creates a `Status` record straight from the forged payload's `state`, `target_url`, `description` and `context` for the `sha` given, with no re-validation against GitHub's API. [9](#0-8)  If a victim stack's `shipit.yml` gates continuous deployment behind `ci.require` contexts, an attacker can forge a `success` status for the required context on a real commit sha of the victim's stack — flipping the CI gate and causing Shipit's continuous-deployment logic to trigger an actual deploy of that commit, entirely outside the victim organization's control.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" trust boundary and results in an **unauthorized deploy**: an attacker who only controls their own org's GitHub App/webhook secret can inject fabricated CI status (or push/check_suite/membership events) targeting an unrelated victim organization's stack, satisfying continuous-deployment gating and causing Shipit to ship a commit the victim never approved via CI. This matches the Critical impact criterion "an unauthorized deploy, rollback or merge."

### Likelihood Explanation
Requires only that the Shipit instance host more than one organization (a documented, supported configuration — see `Shipit.github(organization:)` and `GithubOrganizationUnknown`), and that the attacker be an admin of any one onboarded organization (not the victim's). No access to the victim's secrets, tokens, or repositories is needed — only knowledge of the attacker's own org's `webhook_secret`, which they legitimately possess.

### Recommendation
Bind the verified organization to the acted-upon repository: after `verify_webhook_signature` succeeds for `repository_owner`, re-derive the target repository/stack strictly from a value scoped to that same verified organization (e.g., require `repository.full_name.split('/').first.downcase == repository_owner.downcase`), and reject the request otherwise. Apply the same owner/full_name consistency check inside `Handler#repository_name`/`Repository.from_github_repo_name` so no handler can resolve a repository outside the authenticated organization.

### Proof of Concept
1. Attacker is an admin of `org-a`, which has its own GitHub App installed on this Shipit instance with a known `webhook_secret` (`SECRET_A`), as required by the setup docs.
2. Attacker crafts:
```json
{
  "repository": { "owner": { "login": "org-a" }, "full_name": "victim-org/victim-repo" },
  "sha": "<real sha of a commit awaiting deploy in victim-org/victim-repo>",
  "state": "success",
  "context": "ci/required-check",
  "target_url": "https://attacker.example.com",
  "description": "forged"
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(SECRET_A, body)` and sends it with `X-Github-Event: status` to `/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: "org-a")` → succeeds with `SECRET_A`.
5. The status handler creates a `Status` for the sha in `victim-org/victim-repo`, satisfying `ci.require`, potentially triggering an unauthorized continuous deployment on the victim stack.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** test/controllers/webhooks_controller_test.rb (L94-107)
```ruby
    test "verifies webhook signature" do
      commit = shipit_commits(:first)

      payload = { "sha" => commit.sha, "state" => "pending", "target_url" => "https://ci.example.com/1000/output" }.merge(repository_params).to_json
      signature = 'sha1=4848deb1c9642cd938e8caa578d201ca359a8249'

      @request.headers['X-Github-Event'] = 'push'
      @request.headers['X-Hub-Signature'] = signature

      Shipit.github(organization: 'shopify').expects(:verify_webhook_signature).with(signature, payload).returns(false)

      post :create, body: payload, as: :json
      assert_response :unprocessable_entity
    end
```

**File:** docs/setup.md (L56-72)
```markdown
## Updating the config/secrets.yml

The `config/secrets.yml` file will hold your secrets, by default it is ignored by git, so it's up to you to decide how secrets are deployed in production, as Rails doesn't enforce any method.

It should look like this:

```yaml
production:
  secret_key_base: some-long-string
  host: example.com
  redis_url: "redis://redis-host"
  github:
    app_id: 42
    installation_id: 43
    bot_login: "my-app[bot]"
    webhook_secret: some-secret-value
    private_key: |
```
