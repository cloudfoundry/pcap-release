// parser opts ensure that breaking changes indicated with `!` after the scope (before `:`)
// are valid commits and are processed correctly.
const parserOpts = {
    "headerPattern": /^(\w*)(?:\(([\w\$\.\-\* ]*)\))?(!?)\: (.*)$/,
    "headerCorrespondence": ["type", "scope", "breaking", "subject"],
    "noteKeywords": ["BREAKING CHANGE", "BREAKING-CHANGE"]
}

// template based on https://github.com/conventional-changelog/conventional-changelog/blob/master/packages/conventional-changelog-angular/templates/template.hbs,
// but with the "footer" moved to the top as it contains the breaking changes.
const template = `{{> header}}
{{> footer}}

{{#each commitGroups}}

{{#if title}}
### {{title}}

{{/if}}
{{#each commits}}
    {{> commit root=@root}}
{{/each}}

{{/each}}`

// commit metadata transform based on writer opts from @conventional-changelog/conventional-changelog-angular
// https://github.com/conventional-changelog/conventional-changelog/blob/master/packages/conventional-changelog-angular/writerOpts.js
// Adapted for our convention.
const releaseNoteTransform = (commit, context) => {
    const issues = []

    console.log(commit, context)

    // These commit types that will show in the release note. Generally they affect the resulting release.
    const changeTypes = {
        feat: "Features",
        fix: "Bug Fixes",
        doc: "Documentation",
        refactor: "Code Refactoring",
        dep: "Dependencies",
    }

    // These commit types are generally ignored for the release note, as they do not affect the resulting release.
    const hiddenTypes = {
        test: "Tests",
        ci: "Continuous Integration",
    }

    const change = changeTypes[commit.type]
    const hidden = hiddenTypes[commit.type]

    if (hidden !== undefined) {
        // commits with a hidden type are still shown if they contain a relevant note and are not
        // marked as "discarded".
        commit.type = hidden

        // skip processing hidden commits without relevant note.
        if (commit.notes.length === 0) {
            return
        }
    } else if (change !== undefined) {
        // change commits are always shown
        commit.type = change
    } else {
        // "other" commit types are always shown. They should never occur as they are not allowed via commitlint.
        // This is a safety fallback.
        commit.type = "Other"
    }

    commit.notes.forEach(note => {
        note.title = 'BREAKING CHANGES'
    })

    if (commit.scope === '*') {
        commit.scope = ''
    }

    if (typeof commit.hash === 'string') {
        commit.shortHash = commit.hash.substring(0, 7)
    }

    if (typeof commit.subject === 'string') {
        let url = context.repository
            ? `${context.host}/${context.owner}/${context.repository}`
            : context.repoUrl
        if (url) {
            url = `${url}/issues/`
            // Issue URLs.
            commit.subject = commit.subject.replace(/#([0-9]+)/g, (_, issue) => {
                issues.push(issue)
                return `[#${issue}](${url}${issue})`
            })
        }
        if (context.host) {
            // User URLs.
            commit.subject = commit.subject.replace(/\B@([a-z0-9](?:-?[a-z0-9/]){0,38})/g, (_, username) => {
                if (username.includes('/')) {
                    return `@${username}`
                }
                return `[@${username}](${context.host}/${username})`
            })
        }
    }

    // remove references that already appear in the subject
    commit.references = commit.references.filter(reference => {
        return issues.indexOf(reference.issue) === -1;
    })

    if (commit.notes.length > 0) {
        commit.subject = `*Breaking Change!* ${commit.subject || ""}`.trim()
    }

    return commit
}

// the configuration for semantic-release
module.exports = {
    "ci": false,
    "branches": ["main", {"name": "alpha", "prerelease": true}, {"name": "beta", "prerelease": true}],
    "plugins": [
        ["@semantic-release/commit-analyzer", {
            "preset": "angular",
            "releaseRules": [
                {"type": "dep", "release": "patch"}
            ],
            // use parserOpts from above
            parserOpts
        }],
        ["@semantic-release/release-notes-generator",
            {
                // use parserOpts from above
                parserOpts,
                // use transform and template defined above
                writerOpts: {
                    transform: releaseNoteTransform,
                    mainTemplate: template,
                }
            }
        ],
        ["@semantic-release/exec", {
            "verifyReleaseCmd": "bosh -n create-release --final --version ${nextRelease.version} --tarball /tmp/pcap-${nextRelease.gitTag}.tgz",
            "publishCmd": "./ci/scripts/publish.sh ${nextRelease.gitTag}",
            "generateNotesCmd": "./ci/scripts/notes.sh ${nextRelease.gitTag} ${nextRelease.version}"
        }],
        ["@semantic-release/github", {
            "assets": [
                {"path": "/tmp/pcap-*.tgz"}
            ]
        }]
    ]
}
