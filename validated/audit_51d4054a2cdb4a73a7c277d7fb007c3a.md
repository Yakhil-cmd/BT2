### Title
Cross-Organization Webhook Forgery via Signature Scoped to Attacker-Controlled `repository.owner.login` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification by reading `repository.owner.login` (or `organization.login`) directly out of the **unverified** JSON body, then only checks the signature against that org's secret. The handlers that subsequently act on the payload (e.g. `PushHandler`, `StatusHandler`) look up the target `Stack`/`Commit` by the payload's `repository` full name/branch, without re-confirming that repository actually belongs to the organization whose secret was used to authenticate the request. This breaks the binding "organization that authenticated == repository that is written."

### Finding Description
`verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`), fetches `Shipit.github(organization: repository_owner)`, and verifies `X-Hub-Signature` against that specific org's `webhook_secret`: [1](#0-0) [2](#0-1) 

The actual signature primitive only proves the caller knows *some* org's `webhook_secret`, using `SecureCompare.secure_compare` against the HMAC computed with that org's secret: [3](#0-2) 

Once the signature check passes, `create` dispatches the entire (attacker-controlled) JSON body to the registered handlers for the event type, with no further correlation to `repository_owner`: [4](#0-3) 

`PushHandler`, for example, resolves target stacks purely from `branch` and an (unshown) `stacks` scope, and never re-validates the organization used for signing: [5](#0-4) 

Because Shipit supports multiple GitHub organizations configured with independent `webhook_secret`s (as shown in `config/secrets.development.shopify.yml` and `docs/setup.md`), an actor who legitimately administers **one** configured organization (Org A) — and therefore knows Org A's `webhook_secret` — can forge a webhook whose `repository.owner.login` is set to `"org-a"` (so the signature check selects and passes against Org A's secret) while the rest of the payload (`repository.full_name`, `sha`, `branches`, commit `state`, etc.) references a stack belonging to a different, victim organization (Org B). Nothing in `verify_signature` or the handlers cross-checks that the signed organization matches the repository being mutated.

This is analogous to the reported bug class: the "unique identifier"/binding that should tie the authenticated principal to the acted-upon resource (in the original report: an event ID tying the emission to a specific bridge transaction; here: the organization that signed the webhook tying it to the specific repository/stack being modified) is missing, letting a validly-authenticated-but-wrong-scope message be replayed against another target.

### Impact Explanation
The `status` webhook handler creates `Status` records directly from attacker-supplied `sha`, `state`, `description`, `context`, and `target_url` for a `Commit`, as demonstrated in the controller test: [6](#0-5) 

Since Shipit stacks typically gate deploys behind commit statuses/checks, an org administrator for one configured (possibly low-trust) organization could forge `success` statuses for commits on a different organization's stack, satisfying deploy-gating checks and enabling an **unauthorized deploy** — matching the Critical impact category (unauthorized deploy) defined for this scan.

### Likelihood Explanation
Requires the attacker to already administer at least one GitHub organization/App configured in the same Shipit instance (multi-org deployments are explicitly documented and supported), which is a lower bar than compromising the victim organization's own secret or gaining a Shipit session/API token. This satisfies the "organization that authenticated versus the repository that is written" binding-break class called out in scope.

### Recommendation
After selecting `github_app` and verifying the HMAC, re-validate that every repository referenced in the payload (`repository.full_name`, and any repository fields consumed by handlers) actually belongs to the same `repository_owner`/organization that produced a valid signature, rejecting the webhook otherwise. Alternatively, bind webhook secrets per-repository (not per-organization) or include the expected org/repo as part of the value being HMAC'd and checked by each handler.

### Proof of Concept
1. Attacker administers Org A's GitHub App configured in Shipit and knows `webhook_secret` for `org-a`.
2. Attacker crafts:
```json
{
  "repository": {"owner": {"login": "org-a"}, "full_name": "victim-org/victim-repo"},
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "target_url": "https://attacker.example/fake"
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac-sha1(org-a secret, body)>` and POSTs to `/github/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner = "org-a"`, verifies against Org A's secret, and passes. [7](#0-6) 
5. `StatusHandler` creates/updates the `Status` for `victim-org/victim-repo`'s commit as if a legitimate CI provider reported it, without any check that `org-a` owns `victim-org/victim-repo`.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L55-62)
```ruby
    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
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
