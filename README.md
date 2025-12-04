# WAF Test Tool

A Python tool to test Web Application Firewall (WAF) payload size limits using binary search algorithms.

## Overview

This tool identifies the maximum payload size accepted by a WAF-protected endpoint before requests are blocked. It uses a two-phase approach:
1. **Binary search** to quickly find an approximate maximum payload size
2. **Boundary refinement** to determine the byte-precise threshold

## Features

- Efficient binary search algorithm for fast payload size discovery
- Byte-precise boundary detection
- Extracts and displays Azion-specific metadata from response headers
- Async HTTP client for optimal performance
- Clear progress indicators and result formatting

## Requirements

- Python >= 3.14.0
- httpx >= 0.27.0

## Installation

Using `uv`:

```bash
uv sync
```

## Usage

Run the tool directly:

```bash
uv run waf-test
```

Or execute the script:

```bash
uv run python waftest.py
```

## Configuration

Edit the following constants in `waftest.py` to customize behavior:

- `URL`: Target endpoint to test (default: `https://alv.azion.app`)
- `MIN_SIZE`: Starting payload size in bytes (default: 64KB)
- `MAX_SIZE`: Maximum payload size to test (default: 10MB)

## Output

The tool provides:
- Real-time progress of payload size testing
- HTTP status codes for each test (501 = OK, 400 = WAF blocked)
- Maximum accepted payload size in bytes and KB
- Azion metadata from response headers (cache status, server info, etc.)

## How It Works

1. **Initial Binary Search**: Tests payload sizes between MIN_SIZE and MAX_SIZE to find an approximate maximum
2. **Upper Bound Detection**: Increments from the approximate max to find where WAF blocks (HTTP 400)
3. **Byte-Precise Refinement**: Uses binary search between the last successful size and first blocked size
4. **Metadata Extraction**: Captures Azion-specific headers from the final successful request

## License

This project is for testing purposes only.
