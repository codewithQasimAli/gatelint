# Security policy

## Reporting a vulnerability

Please report security problems in gatelint privately through GitHub's security advisories:
[Report a vulnerability](https://github.com/codewithQasimAli/gatelint/security/advisories/new).

Do not open a public issue for a vulnerability. Include the gatelint version (`gatelint version`), the input that triggers the problem, and what you expected. You should receive an acknowledgement within a week.

Relevant problems include, for example: a crafted CI file that makes gatelint hang, crash or read files outside the scanned paths; or a neutering pattern that gatelint reports as gating (a false negative that could give false confidence).

## Scope

gatelint only reads files. It does not execute scripts, contact registries or call remote APIs while scanning.

## Findings in other projects

If gatelint finds a neutered gate in someone else's public repository, report it to that project privately, through its own security policy, rather than publicly.

## Supported versions

Security fixes are made on the latest release.
