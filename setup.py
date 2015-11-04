from setuptools import setup

version = open('facsimile/VERSION').read().strip()
requirements = open('facsimile/requirements.txt').read().split("\n")

setup(
    name='twentyc.perms',
    version=open('facsimile/VERSION').read().rstrip(),
    author='20C',
    author_email='code@20c.com',
    description='granular permissions utility',
    long_description=open('README.md').read(),
    license='LICENSE',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Internet',
        'License :: OSI Approved :: Apache Software License',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    packages=['twentyc.perms'],
    namespace_packages=['twentyc'],
    url='https://github.com/20c/twentyc.perms',
    download_url='https://github.com/20c/twentyc.perms/%s'%version,
    install_requires=requirements,
    include_package_data=True,
    maintainer='20C',
    maintainer_email='code@20c.com',
    zip_safe=False
)
