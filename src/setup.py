from setuptools import find_namespace_packages, setup

setup(
    name="restic-compose-backup",
    url="https://github.com/ZettaIO/restic-compose-backup",
    version="0.7.1",
    author="Einar Forselv",
    author_email="eforselv@gmail.com",
    packages=find_namespace_packages(
        include=[
            "restic_compose_backup",
            "restic_compose_backup.*",
        ]
    ),
    install_requires=[
        "docker~=6.1.3",
    ],
    entry_points={
        "console_scripts": [
            "restic-compose-backup = restic_compose_backup.cli:main",
            "rcb = restic_compose_backup.cli:main",
        ]
    },
)
