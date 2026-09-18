from setuptools import find_packages, setup

setup(
    name="zyb-search-api",
    version="1.0.0",
    description="Pure-Python HTTP API for the Zyb 14.53.0 image-search protocol",
    packages=find_packages("src"),
    package_dir={"": "src"},
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "zyb-search-api=zyb_search_api.api:main",
            "zyb-search=zyb_search_api.client:main",
        ]
    },
)
