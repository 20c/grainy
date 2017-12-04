import pytest

def pytest_addoption(parser):
    parser.addoption("-P", "--performance", action="store_true", help="run performance tests")
