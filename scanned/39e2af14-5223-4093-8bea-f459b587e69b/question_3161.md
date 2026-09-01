# Q3161: GET /status/version: enumerate existence of stacks by repo/branch

## Question
Using the unauthenticated/token-in-URL route `GET /status/version` (Shipit::StatusController#version), can an unprivileged attacker enumerate existence of stacks by repo/branch?

## Target
- File/function: route /status/version
- Entrypoint: GET /status/version (Shipit::StatusController#version)
- Attacker controls: request params, headers, cookies, and any token embedded in the URL
- Exploit idea: the route is reachable without a Shipit session because bare ActionController::Base with no authentication, renders `Shipit.revision`; the attacker leverages it to enumerate existence of stacks by repo/branch
- Invariant to test: Every stack/task/output disclosure and every state change is gated by force_github_authentication + authorized? (or a correctly-scoped token).
- Expected Immunefi impact: High — Unauthenticated disclosure of stack state, task streams, or deploy output
- Fast validation: minitest ActionDispatch::IntegrationTest: hit `GET /status/version` unauthenticated with crafted params, assert whether enumerate succeeds.
