.PHONY: build run stop test logs clean

build:
	docker-compose build

run:
	docker-compose up -d

stop:
	docker-compose down

test:
	python -c "from app.services.log_parser import parse_logs, detect_bruteforce; print('Import OK')"

logs:
	docker-compose logs -f

clean:
	docker-compose down -v
