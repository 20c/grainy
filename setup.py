
from setuptools import find_packages, setup


version = open('facsimile/VERSION').read().strip()
requirements = open('facsimile/requirements.txt').read().split("\n")
test_requirements = open('facsimile/requirements-test.txt').read().split("\n")


setup(
    name='grainy',
    version=version,
    author='20C',
    author_email='code@20c.com',
    description='granular permissions utility',
    long_description='',
    license='LICENSE.txt',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3'
    ],
    packages = find_packages(),
    include_package_data=True,
    url='https://github.com/20c/grainy',
    download_url='https://github.com/20c/grainy/%s' % version,

    install_requires=requirements,
    test_requires=test_requirements,

    zip_safe=True
)
