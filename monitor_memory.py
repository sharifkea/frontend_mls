# monitor_memory.py
import tracemalloc
import requests
import time

def measure_memory_of_operation(operation_name, func, *args, **kwargs):
    """Measure peak memory usage of a specific operation"""
    
    # Start tracking
    tracemalloc.start()
    
    # Take snapshot before
    snapshot_before = tracemalloc.take_snapshot()
    
    # Run operation
    start_time = time.perf_counter()
    result = func(*args, **kwargs)
    end_time = time.perf_counter()
    
    # Take snapshot after
    snapshot_after = tracemalloc.take_snapshot()
    
    # Calculate memory usage
    stats = snapshot_after.compare_to(snapshot_before, 'lineno')
    
    # Get peak memory
    peak_memory = tracemalloc.get_traced_memory()
    
    tracemalloc.stop()
    
    print(f"\n📊 Operation: {operation_name}")
    print(f"   Time: {(end_time - start_time)*1000:.2f} ms")
    print(f"   Peak memory: {peak_memory[1] / 1024 / 1024:.2f} MB")
    print(f"   Current memory: {peak_memory[0] / 1024 / 1024:.2f} MB")
    
    # Show top memory allocations
    print("   Top allocations:")
    for stat in stats[:5]:
        print(f"      {stat}")
    
    return result


# Example usage with your API
def test_load_messages(group_id_hex, token):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(
        "http://localhost:5000/api/messages/get",
        json={"group_id_hex": group_id_hex},
        headers=headers
    )
    return response.json()


def test_send_message(group_id_hex, token, message):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(
        "http://localhost:5000/api/messages/send",
        json={"group_id_hex": group_id_hex, "message": message},
        headers=headers
    )
    return response.json()


if __name__ == "__main__":
    # Get credentials from user
    TOKEN = input("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiOWM2YjNiMjctYWVlNy00MGE3LWFkMWYtYThiMjlkMmEwODliIiwiZXhwIjoxNzc3OTQwNzkwfQ.yHw85FSfPD0JI4ko1z_mUre3RXA7tQ7DwpJU7il5jHg").strip()
    GROUP_ID_HEX = input("feabe16aa9a9c341f7cbfd5305b35775").strip()
    
    # Measure load_messages memory
    measure_memory_of_operation(
        "Load Messages",
        test_load_messages,
        GROUP_ID_HEX,
        TOKEN
    )
    
    # Measure send_message memory
    measure_memory_of_operation(
        "Send Message",
        test_send_message,
        GROUP_ID_HEX,
        TOKEN,
        "Test message for memory analysis"
    )