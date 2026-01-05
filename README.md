
# IOC Extractor

> Small utility to extract Indicators of Compromise (IOCs) from web pages and text.

This repository contains a lightweight Python tool to fetch a URL or local content and extract IOCs such as domains, IPs, and URLs. It was created to help security researchers quickly gather indicators from reports and articles.

## Features

- Fetch a webpage and extract domains, URLs, and other IOCs.
- Uses a simple, dependency-light implementation suitable for quick use and automation.

## Requirements

- Python 3.8+

## Installation

1. Clone the repository

	git clone https://github.com/jcv-/ioc-extractor.git

2. (Optional) Create a virtual environment and install dependencies if any

	python -m venv venv
	venv\Scripts\activate  # on Windows
	pip install -r requirements.txt

## Usage

Run the main script with a target URL (example):

```
python main.py https://example.com/report
```

The tool will print extracted IOCs to stdout or save them depending on flags (see script help).

The repository also includes a `tlds.txt` file used for domain extraction heuristics.

## Contributing

Contributions are welcome. Please open issues or pull requests with improvements or bug fixes.

## Using `uv`

This project is commonly run using the `uv` tool to provide a lightweight, reproducible environment for running Python commands.

- Run the script with `uv` (example):

```
uv run python main.py https://example.com/report
```

- If you don't already have `uv`, install it according to its project documentation (for many setups you can try `pip install uv`).

- `uv run` executes the given command inside `uv`'s managed environment so pinned dependencies are used consistently.

Consult the `uv` documentation for advanced usage and environment management.

## License

MIT — see LICENSE file if provided.

