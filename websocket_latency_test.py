# websocket_latency_test.py
import asyncio
import websockets
import time
import statistics
import json

async def measure_websocket_latency(user_id, token, iterations=10):
    """Measure round-trip latency of WebSocket messages"""
    uri = f"ws://localhost:8000/ws/{user_id}?token={token}"
    latencies = []
    
    try:
        async with websockets.connect(uri) as websocket:
            for i in range(iterations):
                start = time.perf_counter()
                await websocket.send(json.dumps({"type": "ping"}))
                response = await websocket.recv()
                end = time.perf_counter()
                latencies.append((end - start) * 1000)
                await asyncio.sleep(0.1)  # Small delay between pings
    except Exception as e:
        print(f"WebSocket error: {e}")
        return None
    
    if latencies:
        return {
            'avg_latency': statistics.mean(latencies),
            'min_latency': min(latencies),
            'max_latency': max(latencies),
            'iterations': len(latencies)
        }
    return None

def run_websocket_test(user_id, token, iterations=10):
    """Wrapper to run async function"""
    return asyncio.run(measure_websocket_latency(user_id, token, iterations))