### Title
Cross-organization webhook forgery: `repository_owner` used for signature verification is independent of `repository.full_name` used to select the target repository, allowing an attacker who controls Org A's webhook secret to provision review stacks on Org B's repository - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's webhook secret to validate the HMAC against using `repository_owner`, itself read from the same untrusted JSON body (`repository.owner.login`/`organization.login`), while `PullRequest::OpenedHandler#repository` independently resolves the *target* `Shipit::Repository` from `params.repository.full_name`. Nothing binds these two values together, so a webhook that is validly signed for organization A (using A's own webhook secret) can declare `repository.full_name` as any other org B's repo, and the handler will act on B's repository, including satisfying `provisioning_behavior_allow_with_label?` with attacker-fabricated `pull_request.labels`.

### Finding Description
The broken binding is: `repository_owner` (the org whose secret authenticates the request) `==` org(`repository.full_name`) (the repo the handler actually mutates). This equality is never enforced.

- `WebhooksController#repository_owner` reads `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0)  and `verify_signature` uses it solely to pick which `Shipit.github(organization:)` webhook secret to HMAC-check the raw body against [2](#0-1) .
- `GitHubApp#verify_webhook_signature` only proves the raw body was signed with *that selected org's* secret — it says nothing about which repository the body's other fields describe [3](#0-2) .
- `PullRequest::OpenedHandler#repository` independently derives the target `Shipit::Repository` from `params.repository.full_name`, with no cross-check against `repository_owner`/the authenticated org [4](#0-3) .
- `provision?` and `pull_request_has_provisioning_label?` then evaluate the label policy of the *resolved target repository* (B) against `pull_request["labels"]`, an array taken verbatim from the same attacker-authored JSON body with no relation to real GitHub state [5](#0-4) .
- `process` then runs `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` against B's `review_stacks` scope [6](#0-5) .

Exploit flow: attacker legitimately controls organization A and possesses/knows A's configured `webhook_secret` (since they set up A's own GitHub App/webhook integration with Shipit — this is the only secret they need, and it is scoped to their own org, not a privileged Shipit-wide secret). They send `POST /webhooks` with `X-Github-Event: pull_request`, a body whose `repository.owner.login` (or `organization.login`) is `"A"`, but whose `repository.full_name` is `"B/victim-repo"`, and `pull_request.labels` = `[{"name": "<B's provisioning_label_name>"}]`, `action: "opened"`. The request's raw body is HMAC-signed with A's webhook secret. `verify_signature` passes because it only checks the signature against A's secret, selected via the attacker-controlled `repository_owner` field. `OpenedHandler` then resolves repository B, evaluates `provision?` true (because B has `provisioning_behavior_allow_with_label?` and the forged labels match), and provisions a review stack on B without B's knowledge or consent.

No existing guard prevents this: `verify_signature` never compares `repository_owner` to `repository.full_name`'s owner; `drop_unhandled_event` and `check_if_ping` are unrelated; there's no `ExplicitParameters` validation tying signature identity to the acted-upon repository; `Repository.from_github_repo_name` performs no ownership/ACL check against the authenticated org [7](#0-6) .

### Impact Explanation
An attacker who legitimately controls one Shipit-integrated organization (A) can write records (a `Stack`, its associated `PullRequest`, provisioning state) for a completely different tenant organization's repository (B), bypassing B's label-based provisioning access control entirely. This is a cross-tenant write ("a payload for one repository mutating another's stack") and matches the Critical severity category. It is repeatable against any repository B that (a) is registered in this Shipit instance, (b) has `review_stacks_enabled`, and (c) has `provisioning_behavior_allow_with_label?` (or even `allow_all`, which needs no label at all) — the blast radius spans every tenant repository hosted on the same Shipit instance whose provisioning policy the attacker can guess or discover (e.g. default/generic label names like `"shipit"`).

### Likelihood Explanation
Preconditions: attacker must be a legitimate, integrated organization (A) within the same Shipit instance (i.e., already has a working webhook secret for their own org — a normal, unprivileged tenant capability, not a Shipit operator secret) and must know/guess victim B's `provisioning_label_name`. Cost is a single crafted HTTP POST to `/webhooks` with a self-signed body; no interaction with B, no GitHub API access to B, and no compromise of Shipit's or B's secrets is required. This is straightforward and repeatable for any B repository configured with `allow_with_label` or `allow_all`.

### Recommendation
In `WebhooksController#verify_signature`, after selecting the organization/secret and validating the signature, cross-validate that the organization owning `params.repository.full_name` matches `repository_owner` before dispatching to handlers (or better, resolve the target `Shipit::Repository` first and verify the signature using that repository's own organization's secret exclusively, rejecting any request where `repository.full_name`'s owner disagrees with `repository.owner.login`/`organization.login`).

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "rejects webhook where repository.full_name org differs from repository.owner.login org" do
  org_a_secret = "org-a-secret"
  Shipit.stubs(:github).with(organization: "org-a").returns(
    Shipit::GitHubApp.new("org-a", webhook_secret: org_a_secret)
  )
  victim_repo = shipit_repositories(:shipit) # owned by org "shopify" in fixtures
  victim_repo.update!(
    review_stacks_enabled: true,
    provisioning_behavior: :allow_with_label,
    provisioning_label_name: "shipit"
  )

  body = payload_json(:pull_request_opened) # base fixture
  body = JSON.parse(body)
  body["repository"]["owner"]["login"] = "org-a"          # attacker's own org (A)
  body["repository"]["full_name"] = victim_repo.github_repo_name  # victim's repo (B)
  body["pull_request"]["labels"] = [{ "name" => "shipit" }]        # attacker-fabricated label
  raw = body.to_json
  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", org_a_secret, raw)

  assert_no_difference -> { Shipit::Stack.count } do
    post shipit.github_webhooks_path,
      params: raw,
      headers: { "X-Github-Event" => "pull_request", "X-Hub-Signature" => signature },
      as: :json
  end
  # Binding check: repository_owner ("org-a") must equal org(repository.full_name) ("shopify")
  # for the request to be trusted for victim_repo; current code has no such equality check.
end
```
This asserts that `Stack.count` for the victim repository does not increase when the authenticating org (`repository.owner.login`) diverges from the org that actually owns `repository.full_name`; under current code the equality is never checked, so a stack would be created and the test as written (expecting no difference) would fail, proving the vulnerability.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-78)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end

          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
          end

          def pull_request_label_names
            Array.new(pull_request["labels"]).map { |label| label["name"] }
          end
```
