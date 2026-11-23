# One s9pk that contains both arches. The release workflow runs `make $(TARGETS)`.
TARGETS := universal
include node_modules/@start9labs/start-sdk/s9pk.mk
