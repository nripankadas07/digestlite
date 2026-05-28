        # Project Brief

        digestlite exists to solve a narrow, inspectable developer-tooling problem:
        Zero-dep wrapper unifying SHA-1/256/512 + HMAC + base32/64 with a streaming Hasher/Hmac API, alias-tolerant resolution, and constant-time verify.

        ## Portfolio Role

        This repository is part of the local-first engineering portfolio around
        agentic AI infrastructure, evaluation, parsing, safety boundaries, and
        small tools that can be understood from a fresh source checkout. It is not
        here to inflate repository count; it should either provide a reusable
        primitive, a benchmark surface, or a concrete local workflow.

        Topics: crypto, hashing, hmac, python, sha256, zero-dependencies

        ## Current Gates

        - Latest completed CI: success
        - Source files counted by audit: 8
        - Test files counted by audit: 9
        - Latest release: not release-tracked yet
        - License: MIT

        ## Upgrade Path

        - Add golden-output fixtures for narrow terminals, Unicode width, and ANSI escape handling.
- Document compatibility with pipes, files, and non-interactive shells.
- Add performance notes for large inputs and streaming behavior where applicable.

        ## Reviewer Contract

        A serious reviewer should be able to clone the repository, read the
        README and this brief, run the tests, and understand exactly what is
        claimed. Future work should prefer deeper correctness, better fixtures,
        clearer limits, and stronger local demos over broad feature lists.
