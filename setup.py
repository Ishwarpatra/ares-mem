from setuptools import setup, find_packages

setup(
    name="ares_mem",
    version="0.1.0",
    description="Project ARES-Mem: Production-Grade Cybersecurity Multi-Agent System",
    author="Manus Project Manager",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "langgraph==0.0.26",
        "langchain==0.1.12",
        "langchain-openai==0.1.1",
        "chromadb==0.4.24",
        "sentence-transformers==2.5.1",
        "numpy==1.26.4",
        "scikit-learn==1.4.1.post1",
        "spacy==3.7.4",
        "pytest==8.0.2",
        "black==24.2.0",
        "python-dotenv==1.0.1",
        "opensandbox==0.1.8",
    ],
    python_requires=">=3.11",
    entry_points={
        "console_scripts": [
            "ares-test=test_agents:run_test_pipeline",
        ],
    },
)
