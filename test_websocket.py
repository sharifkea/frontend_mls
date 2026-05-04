# test_websocket.py
from websocket_latency_test import run_websocket_test

# Replace with actual user_id and token
result = run_websocket_test("your_user_id", "your_token", iterations=20)

if result:
    print(f"WebSocket Latency - Avg: {result['avg_latency']:.2f}ms, Min: {result['min_latency']:.2f}ms, Max: {result['max_latency']:.2f}ms")

#WebSocket Latency - Avg: 0.72ms, Min: 0.41ms, Max: 1.63ms