from setuptools import setup


install_requires = [
    'pytest-rerunfailures',
    'websocket-client',
]

setup(
    name='middlewared',
    description='TrueNAS Middleware Daemon Integration Test Facilities',
    packages=[
        'middlewared',
        'middlewared.client',
        'middlewared.test.integration.assets',
        'middlewared.test.integration.utils',
    ],
    package_data={},
    include_package_data=True,
    license='BSD',
    platforms='any',
    namespace_packages=[str('middlewared')],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
    ],
    install_requires=install_requires,
)
