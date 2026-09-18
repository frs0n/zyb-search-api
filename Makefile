.PHONY: install test run

install:
	python3 -m pip install -e .

test:
	PYTHONPATH=src python3 -m unittest discover -s tests -v

run:
	PYTHONPATH=src python3 -m zyb_search_api --host 127.0.0.1 --port 8080
