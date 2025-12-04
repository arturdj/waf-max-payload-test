# WAF Test Tool

A Python tool to test Web Application Firewall (WAF) limits using binary search algorithms.

## Overview

This tool identifies both **header** and **payload (body)** size limits for a WAF-protected endpoint. It uses a two-phase approach for each test:
1. **Binary search** to quickly find an approximate maximum size
2. **Boundary refinement** to determine the byte-precise threshold

## Features

- Tests **HEADER limits** and **PAYLOAD (body) limits** separately
- Efficient binary search algorithm for fast size discovery
- Byte-precise boundary detection
- Guesses common limit patterns (64KB, 128KB, 256KB, 512KB, 1MB, etc.)
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
- `HEADER_MIN_SIZE`: Starting header size in bytes (default: 1KB)
- `HEADER_MAX_SIZE`: Maximum header size to test (default: 1MB)

## Output

The tool provides a comprehensive report with:

### Phase 1: Header Limit Testing
- Real-time progress of header size testing
- HTTP status codes (501 = OK, 400/431 = blocked)
- Maximum accepted header size
- Likely limit pattern guess

### Phase 2: Payload Limit Testing
- Real-time progress of payload size testing
- HTTP status codes (501 = OK, 400 = WAF blocked)
- Maximum accepted payload size
- Likely limit pattern guess

### Final Summary
- Both limits displayed side-by-side
- Sizes shown in bytes, KB, and MB
- Common limit pattern identification
- Azion metadata from response headers

## How It Works

### For Each Limit Type (Header & Payload):

1. **Initial Binary Search**: Tests sizes between MIN and MAX to find an approximate maximum
2. **Upper Bound Detection**: Increments from the approximate max to find where WAF blocks (HTTP 400/431)
3. **Byte-Precise Refinement**: Uses binary search between the last successful size and first blocked size
4. **Metadata Extraction**: Captures Azion-specific headers from the final successful request

### Limit Pattern Guessing:

The tool compares discovered limits against common patterns:
- **Headers**: 8KB, 16KB, 32KB
- **Payloads**: 64KB, 128KB, 256KB, 512KB, 1MB, 2MB, 5MB, 10MB

If a discovered limit is within 5% of a common pattern, it reports the likely configuration.

## License

This project is for testing purposes only.
