### Title
Webhook signature is verified against an attacker-chosen organization, not the repository actually acted upon - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and therefore which `webhook_secret`) to validate the HMAC signature against by reading `repository.owner.login` (or `organization.login`) directly out of the **unverified** JSON body. The handler code that subsequently acts on the payload (creating/looking up commits, statuses, teams, users, and enqueuing `GithubSyncJob`, etc.) operates on `repository.full_name`, which is a *different* field in the same untrusted body and is never cross-checked against the organization that was actually used to verify the signature.

### Finding Description
`verify_signature` computes the org used for secret lookup purely from request data: [1](#0-0) 

and [2](#0-1) 

The signature check itself only proves that *some* string in `Shipit.github(organization: repository_owner)`'s configured secret was used to sign the raw body — it says nothing about which repository the body's `repository.full_name` field refers to: [3](#0-2) 

Once `verify_signature` passes, the raw payload is handed unmodified to every registered handler: [4](#0-3) 

The equality that should hold is:

```
organization used to select webhook_secret (repository.owner.login)
    ==
organization/repository that handlers act on (repository.full_name)
```

Nothing in `WebhooksController` enforces this equality. An attacker who legitimately administers their own GitHub organization/repository connected to the same Shipit instance controls a valid `webhook_secret` for that org (this is normal, unprivileged access — configuring GitHub webhooks on a repo you own requires no Shipit credentials at all). They can then craft a raw POST body whose `repository.owner.login`/`organization.login` field names their own org (so `verify_signature` resolves and validates against their own secret), while `repository.full_name` (and other repository identifying fields consumed by the handlers, e.g. to locate `Stack`/`Commit`/`Team` records) names a victim repository/stack that they do not control. The controller's test suite confirms handlers resolve the affected `Stack` purely from the payload's repository data and tolerate mismatched/unknown repositories without any additional binding check: [5](#0-4) [6](#0-5) 

Because the signature only authenticates "some org I own sent this", not "this org owns the repository this payload claims to describe," the deployment-trust binding between *the organization that authenticated* and *the repository that is written* is broken.

### Impact Explanation
This allows an attacker who owns an unrelated, unprivileged GitHub organization/repository (no Shipit account, session, or API token needed) to inject cross-repository webhook events into any other stack hosted on the same Shipit instance — e.g. forging `push` events to enqueue `GithubSyncJob` for a victim's stack, forging `status`/`check_suite` events to fabricate CI state on a victim's commits (which downstream gates deploy safety checks), or forging `membership` events to create arbitrary `Team`/`User` records. This maps to "cross-repository writes" impact and can indirectly enable unauthorized/incorrectly-gated deploys on stacks the attacker does not own.

### Likelihood Explanation
Any GitHub user can create their own repository/organization, wire up a webhook pointed at the target Shipit instance's public webhook endpoint, and obtain a legitimate `webhook_secret` for that org through the normal GitHub UI — no interaction with Shipit's authentication, session, or API-token systems is required. Crafting the JSON body with mismatched `owner.login` vs `full_name` fields is trivial once the attacker has a valid signature for their own org.

### Recommendation
After `verify_signature` succeeds, re-derive the repository/organization that will actually be acted upon (`params.dig('repository','full_name')` / `params.dig('repository','owner','login')`) and require it to match the organization whose secret validated the signature before dispatching to handlers. Reject (422) any payload where these do not match.

### Proof of Concept
1. Attacker creates GitHub org `attacker-org` and repo `attacker-org/decoy`, and configures a webhook secret `S` for it in Shipit's github config.
2. Attacker crafts a `push` event JSON body with:
   - `repository.owner.login = "attacker-org"`
   - `repository.full_name = "victim-org/victim-repo"` (a real Shipit-tracked stack)
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(S, raw_body)` using their own known secret `S`.
4. POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` resolves `repository_owner` to `attacker-org`, fetches the attacker's own valid config, and the signature check passes.
5. `Shipit::Webhooks.for_event('push')` handler runs against the full payload, using `repository.full_name = "victim-org/victim-repo"` to enqueue `GithubSyncJob` (or otherwise mutate state) for a repository the attacker never proved ownership of. [7](#0-6)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L1-63)
```ruby
# frozen_string_literal: true

module Shipit
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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

**File:** test/controllers/webhooks_controller_test.rb (L12-32)
```ruby
    test "create github repository which is not yet present in the datastore" do
      request.headers['X-Github-Event'] = 'push'
      unknown_repo_payload = JSON.parse(payload(:push_master))
      unknown_repo_payload["repository"]["full_name"] = "owner/unknown-repository"
      unknown_repo_payload = unknown_repo_payload.to_json

      assert_nothing_raised do
        post :create, body: unknown_repo_payload, as: :json
      end
    end

    test ":push with the target branch queues a GithubSyncJob" do
      request.headers['X-Github-Event'] = 'push'

      parsed_body = JSON.parse(payload(:push_master))
      expected_head_sha = parsed_body["after"]

      assert_enqueued_with(job: GithubSyncJob, args: [stack_id: @stack.id, expected_head_sha:]) do
        post :create, body: parsed_body.to_json, as: :json
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
