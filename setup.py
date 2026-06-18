from setuptools import setup, find_packages

def read_requirements():
    try:
        with open("requirements.txt") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        return []

setup(
    name="ares_mem",
    version="0.1.0",
    description="Project ARES-Mem: Production-Grade Cybersecurity Multi-Agent System",
    author="Manus Project Manager",
    # Ensure find_packages correctly identifies the 'src' directory
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    # Include all files in src
    include_package_data=True,
    install_requires=read_requirements(),
    python_requires=">=3.11",
    entry_points={
        "console_scripts": [
            "ares-run=orchestrator:main",
        ],
    },
)
