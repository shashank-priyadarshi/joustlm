module.exports = {
    extends: ['@commitlint/config-conventional'],
    parserPreset: 'conventional-changelog-conventionalcommits',
    rules: {
        'body-leading-blank': [2, 'always'],
        'body-case': [1, 'always', 'lower-case'],
        'body-empty': [2, 'never'],
        'body-max-line-length': [2, 'always', 72],
        'footer-leading-blank': [2, 'always'],
        'type-case': [2, 'always', 'lower-case'],
        'type-enum': [
            2,
            'always',
            [
                'init',
                'build',
                'chore',
                'ci',
                'docs',
                'feat',
                'fix',
                'perf',
                'refactor',
                'revert',
                'style',
                'test',
            ],
        ],
        'scope-case': [2, 'always', 'lower-case'],
        'scope-empty': [2, 'never'],
        'scope-max-length': [2, 'always', 30],
        'signed-off-by': [2, 'always'],
        'subject-case': [2, 'always', 'lower-case'],
        'subject-empty': [2, 'never'],
        'subject-full-stop': [2, 'never'],
        'subject-max-length': [2, 'always', 72]
    },
    prompt: {
        questions: {
            type: {
                description: "Select the type of change that you're committing",
                enum: {
                    init: {
                        description: 'Initializing repository or components',
                        title: 'Init',
                        emoji: '⏩'
                    },
                    build: {
                        description: 'Adding build related files/configs like Dockerfile, docker-compose, helm, etc',
                        title: 'Builds',
                        emoji: '🛠',
                    },
                    chore: {
                        description: 'Updating grunt tasks etc; no production code change',
                        title: 'Chores',
                        emoji: '♻️',
                    },
                    ci: {
                        description: 'Adding ci related files/configs like GitHub workflows, GitLab CI yaml, etc',
                        title: 'Continuous Integrations',
                        emoji: '⚙️',
                    },
                    docs: {
                        description: 'Changes to documentation',
                        title: 'Documentation',
                        emoji: '📚',
                    },
                    feat: {
                        description: 'New feature',
                        title: 'Features',
                        emoji: '✨',
                    },
                    fix: {
                        description: 'Bug fix',
                        title: 'Bug Fixes',
                        emoji: '🐛',
                    },
                    perf: {
                        description: 'Bug fix',
                        title: 'Performance Improvements',
                        emoji: '🚀',
                    },
                    refactor: {
                        description: 'Refactoring production code',
                        title: 'Code Refactoring',
                        emoji: '📦',
                    },
                    revert: {
                        description: 'Reverting previous commit',
                        title: 'Reverts',
                        emoji: '🗑',
                    },
                    style: {
                        description: 'Formatting, missing semi colons, etc; no code change',
                        title: 'Styles',
                        emoji: '💎',
                    },
                    test: {
                        description: 'Adding or refactoring tests; no production code change',
                        title: 'Tests',
                        emoji: '🚨',
                    },
                },
            },
            scope: {
                description:
                    'What is the scope of this change (e.g. component or file name)',
            },
            subject: {
                description:
                    'Write a short, imperative tense description of the change',
            },
            body: {
                description: 'Provide a longer description of the change',
            }
        },
    },
};
