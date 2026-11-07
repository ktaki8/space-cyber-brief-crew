# Common tasks. Run `make help` to list them.
PY ?= python

.PHONY: help install test audit-demo injection-demo redteam intel dashboard docker

help:
	@echo "make install         install pipeline and auditor dependencies"
	@echo "make test            run the test suite"
	@echo "make audit-demo      audit the planted-error example brief (writes output/audit_example.html)"
	@echo "make injection-demo  run the pipeline on demo/injection with defenses off, then on, and audit both"
	@echo "make redteam         offline sanitizer audit across all red-team attacks"
	@echo "make intel           refresh MITRE ATT&CK, ATLAS and CISA KEV reference data"
	@echo "make dashboard       start the web dashboard on http://127.0.0.1:8000/dashboard"
	@echo "make docker          build and run the dashboard in Docker"

install:
	$(PY) -m pip install -r requirements.txt
	$(PY) -m pip install -e .

test:
	$(PY) -m pytest -q

audit-demo:
	-$(PY) -m briefaudit audit demo/audit_example/flawed_brief.md --sources demo/injection \
		--brief-format --canaries demo/injection_canaries.json --html output/audit_example.html

injection-demo:
	$(PY) main.py --sources demo/injection --output output/injection_before.md --ungoverned
	$(PY) main.py --sources demo/injection --output output/injection_after.md
	-$(PY) -m briefaudit audit output/injection_before.md --sources demo/injection --brief-format \
		--canaries demo/injection_canaries.json --html output/injection_before.html
	-$(PY) -m briefaudit audit output/injection_after.md --sources demo/injection --brief-format \
		--canaries demo/injection_canaries.json --html output/injection_after.html

redteam:
	$(PY) -m redteam audit

intel:
	$(PY) -m briefaudit update-intel

dashboard:
	$(PY) -m uvicorn api:app --reload

docker:
	docker build -t space-cyber-brief-crew .
	docker run --rm -p 8000:8000 --env-file .env space-cyber-brief-crew
