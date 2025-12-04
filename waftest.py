#!/usr/bin/env python3

import httpx
import asyncio
import sys

# Configuration
URL = "https://alv.azion.app"
MIN_SIZE = 64000        # Start at 64KB
MAX_SIZE = 10485760    # Max 10MB

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

async def binary_search_max_payload(client: httpx.AsyncClient) -> int:
    """Use binary search to find maximum accepted payload size before WAF blocks."""
    low = MIN_SIZE
    high = MAX_SIZE
    found_max = 0
    
    print(f"Testing maximum payload size for {URL}")
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

async def refine_boundary(client: httpx.AsyncClient, base_size: int) -> tuple[int, dict]:
    """Refine the boundary to find byte-precise size where status changes from 501 to 400."""
    print()
    print("Refining boundary to byte-precise accuracy...")
    print()
    
    # First, find a size that triggers 400
    print("Finding upper bound where WAF blocks...")
    current = base_size
    step = 10000  # Start with 10KB increments
    
    while True:
        print(f"Testing payload size: {current:,} bytes... ", end='', flush=True)
        http_code, _ = await test_payload(client, current)
        
        if http_code == 400:
            print(f"✗ WAF BLOCKED (HTTP {http_code})")
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
    last_501 = base_size
    last_headers = {}
    
    while low <= high:
        mid = (low + high) // 2
        
        print(f"Testing payload size: {mid:,} bytes... ", end='', flush=True)
        http_code, headers = await test_payload(client, mid)
        
        if http_code in (200, 201, 204, 501):
            print(f"✓ OK (HTTP {http_code})")
            last_501 = mid
            last_headers = headers
            low = mid + 1
        elif http_code == 400:
            print(f"✗ WAF BLOCKED (HTTP {http_code})")
            high = mid - 1
        else:
            print(f"✗ FAILED (HTTP {http_code})")
            high = mid - 1
    
    print()
    print(f"Byte-precise boundary found!")
    print(f"Last OK size: {last_501:,} bytes")
    print(f"First blocked size: {last_501 + 1:,} bytes")
    
    return last_501, last_headers

def extract_azion_metadata(headers: dict) -> dict:
    """Extract Azion-specific metadata from response headers."""
    azion_headers = {}
    prefixes = ['x-azion', 'azion', 'x-cache', 'server']
    
    for key, value in headers.items():
        key_lower = key.lower()
        if any(key_lower.startswith(prefix) for prefix in prefixes):
            azion_headers[key] = value
    
    return azion_headers

async def async_main():
    """Async main entry point for the WAF test tool."""
    async with httpx.AsyncClient() as client:
        max_size = await binary_search_max_payload(client)
        
        if max_size > 0:
            # Refine to find exact boundary where 501 changes to 400
            refined_size, headers = await refine_boundary(client, max_size)
            
            # Extract Azion metadata
            azion_metadata = extract_azion_metadata(headers)
            
            print()
            print("=" * 60)
            print(f"Maximum payload size (HTTP 501): {refined_size:,} bytes")
            print(f"Approximately: {refined_size / 1024:.2f} KB")
            print(f"Next size triggers WAF block (HTTP 400)")
            print("=" * 60)
            
            if azion_metadata:
                print()
                print("Azion Metadata:")
                print("-" * 60)
                for key, value in azion_metadata.items():
                    print(f"  {key}: {value}")
                print("-" * 60)
        else:
            print()
            print("=" * 60)
            print("No successful payload size found")
            print("=" * 60)

def main():
    """Main entry point for the WAF test tool."""
    asyncio.run(async_main())

if __name__ == "__main__":
    main()
