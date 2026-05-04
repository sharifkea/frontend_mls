# performance_test.py
import time
import statistics
import api_client
import api_client_2
from app import user_crypto_store

class PerformanceTest:
    def __init__(self):
        self.results = {}
    
    def measure_time(self, func, *args, iterations=100, **kwargs):
        """Measure average execution time over multiple iterations"""
        times = []
        for _ in range(iterations):
            start = time.perf_counter()
            result = func(*args, **kwargs)
            end = time.perf_counter()
            times.append((end - start) * 1000)  # Convert to ms
        return {
            'mean': statistics.mean(times),
            'median': statistics.median(times),
            'min': min(times),
            'max': max(times),
            'stddev': statistics.stdev(times) if len(times) > 1 else 0
        }
    
    def test_encryption_performance(self, group_id_b64, token, user_id, group_state):
        """Test message encryption with different message sizes"""
        sizes = [64, 256, 1024, 4096, 16384]  # bytes
        results = {}
        for size in sizes:
            message = "X" * size
            print(f"   Testing encryption with {size} bytes...")
            results[size] = self.measure_time(
                api_client.encrypt_and_send_message,
                group_id_b64, message, token, user_id, group_state,
                iterations=10  # Reduce for testing
            )
        return results
    
    def test_decryption_performance(self, msg_data, group_state, user_id):
        """Test message decryption performance"""
        return self.measure_time(
            api_client.decrypt_message,
            msg_data, group_state, user_id,
            iterations=10
        )
    
    def test_tree_build_performance(self, group_id_b64, token):
        """Test tree rebuild time with different group sizes"""
        start = time.perf_counter()
        tree, epoch, members = api_client.build_tree_by_replay(group_id_b64, token)
        end = time.perf_counter()
        return (end - start) * 1000