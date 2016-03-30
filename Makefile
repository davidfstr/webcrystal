# Run all automated tests
test:
	nosetests
	@#python3 test.py  # if nose is not available

# Collect code coverage metrics
coverage:
	coverage run test.py && coverage combine && coverage html
