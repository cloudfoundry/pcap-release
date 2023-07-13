module.exports = {
    rules: {
        // rules are defined as [ severity (2=error), "always"|"never", argument? ]. See
        // https://commitlint.js.org/#/reference-rules?id=rules

        // log-commit-info is used for debugging. It outputs the dict passed to a plugin.
        // 'log-commit-info': [2, 'always'],
        // enforce that commits with a breaking change indicator ("!") must also contain an explanation of the breaking change.
        'breaking-change-indicator': [2, 'always'],
        // enforce that only the types below are allowed
        'type-enum': [2, 'always',
            [
                'feat',
                'fix',
                'dep',
                'ci',
                'refactor',
                'doc',
                'test',
            ]
        ],
        // enforce that a type is mandatory
        'type-empty': [2, 'never'],
        // enforce the maximum subject length (without type and scope)
        'subject-max-length': [2, 'always', 75],
        // enforce the maximum scope length
        'scope-max-length': [2, 'always', 25],
    },
    parserPreset: {
        parserOpts: {
            // add matching groups for `!` before and after scope. Before scope is invalid, after scope is correct
            // and enforces the "breaking-change" header (see below).
            headerPattern: /^(\w*)(?:(!?)\(([\w\$\.\-\* ]*)\))?(!?)\: (.*)$/,
            headerCorrespondence: ["type", "wrong_breaking", "scope", "breaking", "subject"],
        },
    },
    plugins: [
        {
            rules: {
                // log-commit-info is used for debugging. It outputs the dict passed to a plugin.
                // 'log-commit-info': (input) => {
                //     console.log(input)
                //     return [true, "see above"]
                // },
                'breaking-change-indicator': ({wrong_breaking, breaking, scope, body, footer}) => {
                    if (wrong_breaking) {
                        return [
                            false, "The breaking change indicator `!` can only be used right before `:`, e.g. `feat(scope)!:`."
                        ]
                    }

                    const rxBreakingChange = /^breaking(\s|-)change: .+/img

                    // The marker "breaking change:" is treated as footer and "note" by commitlint, and not considered part of the body.
                    // When a breaking change indicator ("!") is there, we need to check body and footer to cover both variants (with and without "-").

                    // `commitOk` indicates, if the commit passes the rules.
                    const commitOk =
                        !breaking // if there is no "!" in the commit, we don't enforce a footer
                        || body?.match(rxBreakingChange) // if there is a "!", and a body exists, it must match the breaking change pattern
                        || footer?.match(rxBreakingChange) // if there is a "!", and a footer exists, it must match the breaking change pattern

                    return [
                        commitOk,
                        'For a breaking change (indicated with `!` after the type), the commit must mention a trailer `breaking-change:` or `breaking change:` (case in-sensitive)'
                    ];
                },
            },
        },
    ],
};