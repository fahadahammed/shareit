securityCheck:
	@( \
		bandit -r shareit/cli.py -f json | jq '.metrics._totals'; \
		bandit -r shareit/cli.py -f json | jq -e '.metrics._totals."SEVERITY.HIGH" == 0'; \
	)