# Contributing

## Fork & Pull Request Workflow

1. Fork this repository
2. Create a feature branch: `git checkout -b feature/your-feature`
   (or `bugfix/your-bugfix`)
3. Install dependencies: `composer install`
4. Make your changes
5. Run the quality checks (see below)
6. Commit following the [commit message rules](#commit-messages)
7. Push: `git push origin feature/your-feature`
8. Create a pull request on GitHub

## Requirements

- PHP 8.3+
- All tests must pass
- Code must pass PHPStan level max
- Follow the existing code style: `final readonly` classes, and public readonly
  properties for data. Use methods only for derived values.

## Quality checks

`composer ci` is the full gate. CI runs its parts as separate steps.

```bash
composer ci      # validate, audit, every check and the tests
```

The parts, one by one:

| Command                  | Description                  |
|--------------------------|------------------------------|
| `composer check`         | All checks below, no tests   |
| `composer check:style`   | Check code style             |
| `composer check:static`  | Static analysis              |
| `composer check:deps`    | Dependency analysis          |
| `composer check:refactor`| Check for pending migrations |
| `composer fix`           | Apply automatic fixes        |
| `composer test`          | Unit tests                   |
| `composer test:mutation` | Mutation tests               |

## Testing

```bash
composer test                    # All tests
composer test:unit               # Unit tests only
composer test:coverage           # With coverage (needs a coverage driver)
```

Run specific tests:

```bash
vendor/bin/phpunit -c build/tests/phpunit.xml tests/Unit/Matching/AssessmentMatcherTest.php
vendor/bin/phpunit -c build/tests/phpunit.xml --filter testMethodName
```

Use hand-written test doubles named by role, such as `FrozenClock`.
Do not mock the library's own interfaces.

### Mutation testing

[Infection](https://infection.github.io) changes the code in small ways and
checks that a test fails each time. It needs a coverage driver, such as PCOV.

```bash
composer test:mutation           # Mutate all of src/
composer test:mutation:diff      # Mutate only the lines changed since origin/main
```

CI mutates the lines a pull request changes, and all lines on every push to
`main`. Both runs fail below 85% MSI. A changed line can pull in the whole
expression it belongs to, so touching weakly tested code means strengthening
its tests.

The reports land in `build/tests/infection/`.

## Commit Messages

Prefix each commit with a type in brackets, followed by a short summary in the
imperative mood.

| Type         | Use for                                                                                                                                               |
|--------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| `[FEATURE]`  | New functionality                                                                                                                                     |
| `[BUGFIX]`   | Bug fixes                                                                                                                                             |
| `[TASK]`     | Maintenance, refactoring, code cleanup                                                                                                                |
| `[DOCS]`     | Documentation changes                                                                                                                                 |
| `[SECURITY]` | Security fixes. Always approach the maintainers before committing security related patches, please. Consult the [security policy](SECURITY.md) first. |
| `[!!!]`      | Breaking changes. Always include this when changing public API.                                                                                       |

Examples:

```text
[FEATURE] Write assessments as a CycloneDX VEX document
[BUGFIX] Release an affected assessment when the severity rises
[TASK] Remove redundant default parameter
[DOCS] Explain the alarm order of statuses
[!!!][FEATURE] Rename the Justification cases
```
