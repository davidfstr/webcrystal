# Run all automated tests
test:
	python3 test.py

# Collect code coverage metrics
coverage:
	coverage run test.py && coverage combine && coverage html
