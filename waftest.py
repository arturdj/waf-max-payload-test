#!/usr/bin/env python3

import httpx
import asyncio
import sys

# Configuration
URL = "https://alv.azion.app"
MIN_SIZE = 64000        # Start at 64KB
MAX_SIZE = 10485760    # Max 10MB
HEADER_MIN_SIZE = 1000  # Start at 1KB for headers
HEADER_MAX_SIZE = 1048576  # Max 1MB for headers

async def test_payload(client: httpx.AsyncClient, size: int) -> tuple[int, dict]:
    """Test a payload of given size and return HTTP status code and headers."""
    payload = 'A' * size
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'pragma': 'azion-debug-cache'
    }
    
    try:
        response = await client.post(
            URL,
            headers=headers,
            data={'data': payload},
            timeout=30.0
        )
        return response.status_code, dict(response.headers)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 0, {}

async def test_header(client: httpx.AsyncClient, size: int) -> tuple[int, dict]:
    """Test a header of given size and return HTTP status code and headers."""
    header_value = 'A' * size
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'pragma': 'azion-debug-cache',
        'X-Custom-Header': header_value
    }
    
    try:
        response = await client.post(
            URL,
            headers=headers,
            data={'data': 'small_payload'},
            timeout=30.0
        )
        return response.status_code, dict(response.headers)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 0, {}

async def binary_search_max_payload(client: httpx.AsyncClient) -> int:
    """Use binary search to find maximum accepted payload size before WAF blocks."""
    low = MIN_SIZE
    high = MAX_SIZE
    found_max = 0
    
    print(f"Testing maximum PAYLOAD (body) size for {URL}")
    print("Using binary search algorithm...")
    print("Note: HTTP 501 = OK, HTTP 400 = WAF blocked")
    print()
    
    while low <= high:
        mid = (low + high) // 2
        
        print(f"Testing payload size: {mid:,} bytes... ", end='', flush=True)
        
        http_code, _ = await test_payload(client, mid)
        
        # Success codes: request accepted (including 501)
        if http_code in (200, 201, 204, 501):
            print(f"✓ OK (HTTP {http_code})")
            found_max = mid
            low = mid + 1
        # 400 or other codes: WAF blocked or error
        else:
            if http_code == 400:
                print(f"✗ WAF BLOCKED (HTTP {http_code})")
            else:
                print(f"✗ FAILED (HTTP {http_code})")
            high = mid - 1
    
    return found_max

async def binary_search_max_header(client: httpx.AsyncClient) -> int:
    """Use binary search to find maximum accepted header size before WAF blocks."""
    low = HEADER_MIN_SIZE
    high = HEADER_MAX_SIZE
    found_max = 0
    
    print(f"Testing maximum HEADER size for {URL}")
    print("Using binary search algorithm...")
    print("Note: HTTP 501 = OK, HTTP 400/431 = WAF/Server blocked")
    print()
    
    while low <= high:
        mid = (low + high) // 2
        
        print(f"Testing header size: {mid:,} bytes... ", end='', flush=True)
        
        http_code, _ = await test_header(client, mid)
        
        # Success codes: request accepted (including 501)
        if http_code in (200, 201, 204, 501):
            print(f"✓ OK (HTTP {http_code})")
            found_max = mid
            low = mid + 1
        # 400, 431 or other codes: WAF blocked or error
        else:
            if http_code == 400:
                print(f"✗ WAF BLOCKED (HTTP {http_code})")
            elif http_code == 431:
                print(f"✗ HEADER TOO LARGE (HTTP {http_code})")
            else:
                print(f"✗ FAILED (HTTP {http_code})")
            high = mid - 1
    
    return found_max

async def refine_boundary(client: httpx.AsyncClient, base_size: int, test_func, label: str = "payload") -> tuple[int, dict]:
    """Refine the boundary to find byte-precise size where status changes from 501 to 400."""
    print()
    print(f"Refining {label} boundary to byte-precise accuracy...")
    print()
    
    # First, find a size that triggers 400
    print("Finding upper bound where WAF blocks...")
    current = base_size
    step = 10000  # Start with 10KB increments
    
    while True:
        print(f"Testing {label} size: {current:,} bytes... ", end='', flush=True)
        http_code, _ = await test_func(client, current)
        
        if http_code in (400, 431):
            print(f"✗ BLOCKED (HTTP {http_code})")
            break
        elif http_code in (200, 201, 204, 501):
            print(f"✓ OK (HTTP {http_code})")
            current += step
        else:
            print(f"✗ FAILED (HTTP {http_code})")
            break
    
    # Now we have: base_size returns 501, current returns 400
    # Use binary search between them for byte precision
    print()
    print("Using binary search for byte-precise boundary...")
    low = base_size
    high = current
    last_ok = base_size
    last_headers = {}
    
    while low <= high:
        mid = (low + high) // 2
        
        print(f"Testing {label} size: {mid:,} bytes... ", end='', flush=True)
        http_code, headers = await test_func(client, mid)
        
        if http_code in (200, 201, 204, 501):
            print(f"✓ OK (HTTP {http_code})")
            last_ok = mid
            last_headers = headers
            low = mid + 1
        elif http_code in (400, 431):
            print(f"✗ BLOCKED (HTTP {http_code})")
            high = mid - 1
        else:
            print(f"✗ FAILED (HTTP {http_code})")
            high = mid - 1
    
    print()
    print(f"Byte-precise boundary found!")
    print(f"Last OK size: {last_ok:,} bytes")
    print(f"First blocked size: {last_ok + 1:,} bytes")
    
    return last_ok, last_headers

def extract_azion_metadata(headers: dict) -> dict:
    """Extract Azion-specific metadata from response headers."""
    azion_headers = {}
    prefixes = ['x-azion', 'azion', 'x-cache', 'server']
    
    for key, value in headers.items():
        key_lower = key.lower()
        if any(key_lower.startswith(prefix) for prefix in prefixes):
            azion_headers[key] = value
    
    return azion_headers

def guess_limit_type(size: int) -> str:
    """Guess the type of limit based on common size patterns."""
    # Common limit patterns
    common_limits = {
        65536: "64 KB (common WAF limit)",
        131072: "128 KB (common WAF limit)",
        262144: "256 KB (common WAF limit)",
        524288: "512 KB (common WAF limit)",
        1048576: "1 MB (common WAF limit)",
        2097152: "2 MB (common WAF limit)",
        5242880: "5 MB (common WAF limit)",
        10485760: "10 MB (common WAF limit)",
        8192: "8 KB (common header limit)",
        16384: "16 KB (common header limit)",
        32768: "32 KB (common header limit)",
    }
    
    # Check if it's close to a common limit (within 5%)
    for limit, description in common_limits.items():
        if abs(size - limit) / limit < 0.05:
            return description
    
    # Return generic description
    return f"{size / 1024:.2f} KB (custom limit)"

async def async_main():
    """Async main entry point for the WAF test tool."""
    async with httpx.AsyncClient() as client:
        print("=" * 70)
        print("WAF LIMIT DISCOVERY TOOL")
        print("=" * 70)
        print()
        
        # Test 1: Header limit
        print("🔍 PHASE 1: TESTING HEADER LIMITS")
        print("=" * 70)
        max_header_size = await binary_search_max_header(client)
        
        header_result = None
        if max_header_size > 0:
            refined_header_size, header_headers = await refine_boundary(
                client, max_header_size, test_header, "header"
            )
            header_result = {
                'size': refined_header_size,
                'headers': header_headers,
                'guess': guess_limit_type(refined_header_size)
            }
        
        print()
        print()
        
        # Test 2: Payload limit
        print("🔍 PHASE 2: TESTING PAYLOAD (BODY) LIMITS")
        print("=" * 70)
        max_payload_size = await binary_search_max_payload(client)
        
        payload_result = None
        if max_payload_size > 0:
            refined_payload_size, payload_headers = await refine_boundary(
                client, max_payload_size, test_payload, "payload"
            )
            payload_result = {
                'size': refined_payload_size,
                'headers': payload_headers,
                'guess': guess_limit_type(refined_payload_size)
            }
        
        # Final summary
        print()
        print()
        print("=" * 70)
        print("📊 FINAL RESULTS SUMMARY")
        print("=" * 70)
        
        if header_result:
            print()
            print("🔹 HEADER LIMIT:")
            print(f"   Maximum size: {header_result['size']:,} bytes")
            print(f"   In KB: {header_result['size'] / 1024:.2f} KB")
            print(f"   Likely limit: {header_result['guess']}")
            print(f"   First blocked: {header_result['size'] + 1:,} bytes")
        else:
            print()
            print("🔹 HEADER LIMIT: No successful header size found")
        
        if payload_result:
            print()
            print("🔹 PAYLOAD (BODY) LIMIT:")
            print(f"   Maximum size: {payload_result['size']:,} bytes")
            print(f"   In KB: {payload_result['size'] / 1024:.2f} KB")
            print(f"   In MB: {payload_result['size'] / (1024 * 1024):.2f} MB")
            print(f"   Likely limit: {payload_result['guess']}")
            print(f"   First blocked: {payload_result['size'] + 1:,} bytes")
        else:
            print()
            print("🔹 PAYLOAD (BODY) LIMIT: No successful payload size found")
        
        # Show Azion metadata if available
        if payload_result or header_result:
            headers = payload_result['headers'] if payload_result else header_result['headers']
            azion_metadata = extract_azion_metadata(headers)
            
            if azion_metadata:
                print()
                print("🔹 AZION METADATA:")
                for key, value in azion_metadata.items():
                    print(f"   {key}: {value}")
        
        print()
        print("=" * 70)

def main():
    """Main entry point for the WAF test tool."""
    asyncio.run(async_main())

if __name__ == "__main__":
    main()
