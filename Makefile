.PHONY: gorelease
gorelease: ARGS=--snapshot --clean
gorelease:
	goreleaser release $(ARGS)

.PHONY: clean
clean:
	rm -rf dist