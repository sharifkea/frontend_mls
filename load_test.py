# load_test.py
import concurrent.futures
import time
import statistics
import requests

class LoadTest:
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
        self.latencies = []
        self.errors = []
    
    def simulate_user(self, user_id, group_id_hex, token):
        """Simulate a user sending a single message"""
        start = time.perf_counter()
        try:
            response = requests.post(
                f"{self.base_url}/api/messages/send",
                json={
                    "group_id_hex": group_id_hex,
                    "message": f"Test message from user {user_id}"
                },
                headers={"Authorization": f"Bearer {token}"},
                timeout=10
            )
            end = time.perf_counter()
            
            if response.status_code == 200:
                return (end - start) * 1000  # Return latency in ms
            else:
                self.errors.append(f"User {user_id}: HTTP {response.status_code}")
                return None
        except Exception as e:
            self.errors.append(f"User {user_id}: {str(e)}")
            return None
    
    def run_concurrent_test(self, group_id_hex, token, num_users=10, messages_per_user=5):
        """Run test with concurrent users"""
        print(f"\n🚀 Running load test with {num_users} users, {messages_per_user} messages each")
        
        all_latencies = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_users) as executor:
            futures = []
            for user_id in range(num_users):
                for msg_num in range(messages_per_user):
                    futures.append(
                        executor.submit(self.simulate_user, user_id, group_id_hex, token)
                    )
            
            # Collect results
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result is not None:
                    all_latencies.append(result)
        
        if all_latencies:
            return {
                'total_requests': len(all_latencies),
                'total_errors': len(self.errors),
                'avg_latency': statistics.mean(all_latencies),
                'min_latency': min(all_latencies),
                'max_latency': max(all_latencies),
                'p95_latency': statistics.quantiles(all_latencies, n=100)[94] if len(all_latencies) >= 100 else max(all_latencies),
                'p99_latency': statistics.quantiles(all_latencies, n=100)[98] if len(all_latencies) >= 100 else max(all_latencies)
            }
        else:
            return {'error': 'No successful requests', 'errors': self.errors}