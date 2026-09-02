### Title
Webhook signature verified against `repository.owner.login`/`organization.login` while handlers act on the unrelated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's HMAC secret to validate a webhook against using a field taken directly from the **unauthenticated** JSON body (`repository.owner.login`, falling back to `organization.login`), but the events actually acted upon downstream are resolved from a *different* field of that same untrusted body: `repository.full_name`. The two fields are never cross-checked against each other, so a signature that is valid for organization A does not guarantee the payload's `repository.full_name` actually belongs to organization A.

### Finding Description
`verify_signature` picks the verifying secret like this: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` looks up a per-organization `GithubApp`/secret and raises `Shipit::GithubOrganizationUnknown` for organizations it doesn't know about, confirming the lookup is keyed by the organization named in the attacker-supplied payload rather than by any independently authenticated channel identity [3](#0-2) [4](#0-3) . `verify_webhook_signature` itself only performs an HMAC comparison of the raw body against the resolved organization's `webhook_secret` [5](#0-4) ; it has no knowledge of, or opinion on, which repository the payload claims to touch.

Once the signature check passes, every event handler resolves the target repository from a **separate** field of the same payload: [6](#0-5) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`repository.owner.login` (used to choose the verifying secret) and `repository.full_name` (used to choose the repository whose `Stack`s get commit statuses updated, `GithubSyncJob`s enqueued, PRs progressed, etc.) are two independently attacker-controlled strings in the same JSON body. Nothing enforces `repository.full_name.split('/').first == repository.owner.login`.

The equality the engine relies on but never checks is:
`organization whose secret verified the signature == organization that owns the repository the handlers act on`

Before the report's bug class is applied: this equality holds implicitly only because in a legitimate GitHub-delivered webhook, both fields are populated consistently by GitHub itself. After considering an attacker who can forge arbitrary request bodies (anyone able to compute a valid HMAC for *some* organization configured in the Shipit instance, e.g. because they administer that organization's GitHub App installation/webhook and therefore know or set its `webhook_secret`), the equality breaks: they can sign a payload with organization A's secret while setting `repository.full_name` to `"victim-org/victim-repo"`.

### Impact Explanation
An attacker who knows (or controls) the webhook secret for any single organization onboarded to a multi-tenant Shipit instance can forge webhook deliveries that pass `verify_signature` and then drive Shipit's push/status/check_suite/pull_request handlers against a **completely different repository** they have no access to, by only changing `repository.full_name` while keeping `repository.owner.login` pointing at the organization whose secret they know. This allows cross-repository writes (fabricated commit `Status` rows, PR label/merge state changes) into stacks belonging to organizations the attacker does not control, and can be used to inject a fabricated passing CI status that satisfies `ci.require`, unblocking or otherwise influencing deploy-safety checks for a victim stack — an unauthorized-deploy-adjacent outcome. This matches the "cross-repository writes / unauthorized deploy" impact tier.

### Likelihood Explanation
This requires the attacker to know one organization's webhook secret in a Shipit deployment that hosts multiple organizations (the `GithubOrganizationUnknown` rescue path and per-organization `Shipit.github(organization:)` lookup indicate this multi-tenant configuration is supported/expected). An attacker who is a legitimate but low-privileged owner/admin of one onboarded organization (e.g., able to configure that org's GitHub App/webhook secret, without any Shipit session or repository write access to the victim repo) can exploit this purely by crafting an HTTP POST to the public webhook endpoint. No Shipit credentials, `ApiClient` token, or GitHub write access to the victim repository are needed, satisfying the unprivileged-attacker requirement.

### Recommendation
After signature verification passes, re-derive the organization strictly from the verified `github_app`'s bound organization and assert that `repository.full_name`'s owner segment (and `repository.owner.login`/`organization.login`) matches that organization before dispatching to any handler; reject the webhook otherwise.

### Proof of Concept
1. Attacker owns/administers GitHub organization `attacker-org`, which is configured in Shipit with a known `webhook_secret` (e.g. because the attacker set it up on their own onboarded stack).
2. Attacker crafts a `push` (or `status`, `check_suite`, `pull_request`) JSON body where:
   - `repository.owner.login` = `attacker-org` (so `verify_signature`'s `Shipit.github(organization: 'attacker-org')` lookup succeeds and the HMAC matches).
   - `repository.full_name` = `victim-org/victim-repo` (the repository the attacker wants to affect, tracked as a Shipit `Stack` for `victim-org`).
3. Attacker computes `X-Hub-Signature` as `sha1=` + `HMAC-SHA1(attacker-org's webhook_secret, raw_body)` and POSTs to `/webhooks` (or the engine's mounted webhook route) with `X-Github-Event: status` (or `push`).
4. `verify_signature` passes because it only checked the `attacker-org` secret against the raw body [1](#0-0) .
5. The corresponding handler resolves `repository_name` from `repository.full_name` = `victim-org/victim-repo` and updates commit statuses / enqueues sync jobs for the victim's stack [6](#0-5) , even though the signature never proved anything about `victim-org`.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L39-49)
```ruby
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

**File:** test/controllers/webhooks_controller_test.rb (L109-127)
```ruby
    test "unknown github organization logs and returns unprocessable entity" do
      @request.headers['X-Github-Event'] = 'push'

      payload = JSON.parse(payload(:push_master))
      payload["repository"]["owner"]["login"] = "unknown-org"

      Shipit.stubs(:github).raises(Shipit::GithubOrganizationUnknown.new("unknown-org"))
      Rails.logger.expects(:warn).with([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=push",
        "repository_owner=unknown-org",
        "unknown_organization=unknown-org",
        "status=422"
      ].join(' '))

      post :create, body: payload.to_json, as: :json
      assert_response :unprocessable_entity
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
