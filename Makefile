.RECIPEPREFIX = >
PY ?= python
CAMPAIGN := $(firstword $(wildcard src/data/mordor/apt29_evals_day1_manual_*.json))

.PHONY: data demo test

data:
> bash scripts/fetch_datasets.sh

# Needs ~2.3 GB RAM and ~2 minutes.
demo:
> @test -n "$(CAMPAIGN)" || { echo "Campaign not found - run 'make data' first"; exit 1; }
> mkdir -p docs/demo
> cd src && $(PY) -m app.orchestrator ../$(CAMPAIGN) > ../docs/demo/campaign_result.json
> @echo "Saved docs/demo/campaign_result.json"

test:
> cd src && $(PY) -m pytest -q
