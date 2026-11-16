.PHONY: test lint restore-drill restore-evidence

test:
	bash examples/backup/restore-test.sh
	python3 -m unittest discover -s tests

restore-drill:
	python3 tools/restore_drill.py

restore-evidence:
	python3 tools/restore_drill.py --data-class standard --evidence restore-evidence.json
	python3 tools/verify_evidence.py restore-evidence.json

lint:
	bash -n examples/backup/restore-test.sh
	bash -n examples/docs-sync/pull-docs.sh
	python3 -c "import yaml,sys; yaml.safe_load(open('examples/ansible/baseline.yml'))"
