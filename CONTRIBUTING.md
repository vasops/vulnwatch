# Contributing

Issues and pull requests are welcome. For a security problem, see
[`SECURITY.md`](SECURITY.md) instead of opening an issue.

## Development

Go (the version in `go.mod`), `make`, and Helm for the chart checks.

```sh
make lint         # go vet + golangci-lint
make test         # go test -race ./...
make build        # bin/vulnwatch
make chart-lint   # after touching charts/ or defaults/
make security     # govulncheck + capslock
```

CI runs the same checks on every pull request. More in
[Development](docs/development.md): the layout of the code,
[adding a product](docs/development.md#adding-a-product) and releasing.

## Pull requests

- Keep a pull request to one change, with a test for it.
- After editing `defaults/*.yaml` run `make chart-sync`: the chart ships
  copies and CI compares them.
- After an output change refresh the golden files:
  `go test ./internal/output/... -update`.
- A new capability in the binary (network, files, exec, ...) fails
  `make capslock`. Say why it is needed in the pull request, then run
  `make capslock-baseline`.
- Never put real inventories, host names, tokens or customer names into
  tests, examples or docs. Use `example.com`, `acme` and invented versions.

## Commit messages

One line, [Conventional Commits](https://www.conventionalcommits.org/), with
the changed folder as the scope and a capitalized description:

```
fix(internal/match): Treat a partial version without wildcard as a release line
docs(README.md): Describe the news channel
```

## License

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE).
