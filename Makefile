lint:
	( \
		python3 -m venv .venv; \
		. .venv/bin/activate; \
		pip install -r src/requirements.txt; \
		black .; \
		deactivate \
	)

start_docker:
	( \
		docker compose up --build -d; \
		docker compose logs -f datalake2anomali \
	)

stop_docker:
	docker compose down --remove-orphans

start_standalone:
	( \
		python3 -m venv .venv; \
		. .venv/bin/activate; \
		pip install -r src/requirements.txt; \
		python src/core.py; \
		deactivate \
	)