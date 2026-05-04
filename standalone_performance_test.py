# standalone_performance_test.py
import time
import statistics
import requests
import base64
import json
from datetime import datetime

class StandalonePerformanceTest:
    def __init__(self, token, user_id, group_id_hex, group_id_b64, flask_url="http://localhost:5000", fastapi_url="http://localhost:8000"):
        self.token = token
        self.user_id = user_id
        self.group_id_hex = group_id_hex
        self.group_id_b64 = group_id_b64
        self.flask_url = flask_url
        self.fastapi_url = fastapi_url
        self.results = {}
    
    def get_headers(self):
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
    
    def test_encryption_send(self, iterations=10):
        """Test encrypt and send message performance"""
        print(f"\n🔐 Testing encryption & send ({iterations} iterations)...")
        
        times = []
        errors = 0
        
        for i in range(iterations):
            start = time.perf_counter()
            try:
                response = requests.post(
                    f"{self.flask_url}/api/messages/send",
                    json={
                        "group_id_hex": self.group_id_hex,
                        "message": f"Performance test message {i}"
                    },
                    headers=self.get_headers(),
                    timeout=30
                )
                end = time.perf_counter()
                
                if response.status_code == 200:
                    times.append((end - start) * 1000)
                else:
                    errors += 1
                    print(f"   Error {i+1}: HTTP {response.status_code}")
                    
            except Exception as e:
                errors += 1
                print(f"   Error {i+1}: {str(e)}")
        
        if times:
            return {
                'mean': statistics.mean(times),
                'median': statistics.median(times),
                'min': min(times),
                'max': max(times),
                'stddev': statistics.stdev(times) if len(times) > 1 else 0,
                'success_rate': (iterations - errors) / iterations * 100,
                'iterations': len(times)
            }
        return {'error': 'No successful requests', 'success_rate': 0}
    
    def test_get_messages(self, iterations=10):
        """Test get messages performance"""
        print(f"\n📩 Testing get messages ({iterations} iterations)...")
        
        times = []
        errors = 0
        
        for i in range(iterations):
            start = time.perf_counter()
            try:
                response = requests.post(
                    f"{self.flask_url}/api/messages/get",
                    json={"group_id_hex": self.group_id_hex},
                    headers=self.get_headers(),
                    timeout=30
                )
                end = time.perf_counter()
                
                if response.status_code == 200:
                    times.append((end - start) * 1000)
                else:
                    errors += 1
                    
            except Exception as e:
                errors += 1
        
        if times:
            return {
                'mean': statistics.mean(times),
                'median': statistics.median(times),
                'min': min(times),
                'max': max(times),
                'stddev': statistics.stdev(times) if len(times) > 1 else 0,
                'success_rate': (iterations - errors) / iterations * 100
            }
        return {'error': 'No successful requests'}
    
    def test_fastapi_messages(self, iterations=10):
        """Test direct FastAPI messages endpoint"""
        print(f"\n🗄️ Testing FastAPI messages endpoint ({iterations} iterations)...")
        
        times = []
        errors = 0
        
        for i in range(iterations):
            start = time.perf_counter()
            try:
                response = requests.get(
                    f"{self.fastapi_url}/groups/{self.group_id_hex}/messages?limit=50",
                    headers=self.get_headers(),
                    timeout=30
                )
                end = time.perf_counter()
                
                if response.status_code == 200:
                    times.append((end - start) * 1000)
                else:
                    errors += 1
                    
            except Exception as e:
                errors += 1
        
        if times:
            return {
                'mean': statistics.mean(times),
                'median': statistics.median(times),
                'min': min(times),
                'max': max(times),
                'stddev': statistics.stdev(times) if len(times) > 1 else 0,
                'success_rate': (iterations - errors) / iterations * 100
            }
        return {'error': 'No successful requests'}
    
    def test_load(self, num_users=5, messages_per_user=3):
        """Simple load test with concurrent requests"""
        print(f"\n🚦 Running load test: {num_users} users × {messages_per_user} messages = {num_users * messages_per_user} total requests")
        
        import concurrent.futures
        
        def send_message(thread_id, msg_num):
            start = time.perf_counter()
            try:
                response = requests.post(
                    f"{self.flask_url}/api/messages/send",
                    json={
                        "group_id_hex": self.group_id_hex,
                        "message": f"Load test {thread_id}:{msg_num}"
                    },
                    headers=self.get_headers(),
                    timeout=30
                )
                end = time.perf_counter()
                if response.status_code == 200:
                    return (end - start) * 1000
                return None
            except:
                return None
        
        all_latencies = []
        errors = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_users) as executor:
            futures = []
            for user in range(num_users):
                for msg in range(messages_per_user):
                    futures.append(executor.submit(send_message, user, msg))
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    all_latencies.append(result)
                else:
                    errors += 1
        
        if all_latencies:
            return {
                'total_requests': len(all_latencies),
                'errors': errors,
                'success_rate': (len(all_latencies) / (len(all_latencies) + errors)) * 100,
                'avg_latency': statistics.mean(all_latencies),
                'min_latency': min(all_latencies),
                'max_latency': max(all_latencies),
                'p95_latency': statistics.quantiles(all_latencies, n=100)[94] if len(all_latencies) >= 100 else max(all_latencies),
                'p99_latency': statistics.quantiles(all_latencies, n=100)[98] if len(all_latencies) >= 100 else max(all_latencies)
            }
        return {'error': 'No successful requests'}
    
    def test_websocket_latency(self, iterations=10):
        """Test WebSocket latency"""
        print(f"\n🔌 Testing WebSocket latency ({iterations} iterations)...")
        
        import asyncio
        import websockets
        
        async def measure():
            uri = f"ws://localhost:8000/ws/{self.user_id}?token={self.token}"
            latencies = []
            
            try:
                async with websockets.connect(uri) as websocket:
                    for i in range(iterations):
                        start = time.perf_counter()
                        await websocket.send(json.dumps({"type": "ping"}))
                        response = await websocket.recv()
                        end = time.perf_counter()
                        latencies.append((end - start) * 1000)
                        await asyncio.sleep(0.1)
            except Exception as e:
                print(f"   WebSocket error: {e}")
                return None
            
            return latencies
        
        latencies = asyncio.run(measure())
        
        if latencies:
            return {
                'avg_latency': statistics.mean(latencies),
                'min_latency': min(latencies),
                'max_latency': max(latencies),
                'stddev': statistics.stdev(latencies) if len(latencies) > 1 else 0,
                'iterations': len(latencies)
            }
        return {'error': 'WebSocket connection failed'}
    
    def run_all_tests(self):
        """Run complete test suite"""
        print("=" * 70)
        print("📊 STANDALONE PERFORMANCE TEST SUITE")
        print("=" * 70)
        
        # Test 1: Basic connectivity
        print("\n✅ Checking connectivity...")
        try:
            resp = requests.get(f"{self.flask_url}/api/online-users", headers=self.get_headers())
            if resp.status_code == 200:
                print("   Flask API: OK")
            else:
                print(f"   Flask API: Error {resp.status_code}")
        except Exception as e:
            print(f"   Flask API: {e}")
            return
        
        # Test 2: Encryption/Send
        self.results['encrypt_send'] = self.test_encryption_send(iterations=10)
        
        # Test 3: Get messages
        self.results['get_messages'] = self.test_get_messages(iterations=10)
        
        # Test 4: FastAPI direct
        self.results['fastapi_messages'] = self.test_fastapi_messages(iterations=10)
        
        # Test 5: Load test
        self.results['load_test'] = self.test_load(num_users=5, messages_per_user=3)
        
        # Test 6: WebSocket
        self.results['websocket'] = self.test_websocket_latency(iterations=10)
        
        self.generate_report()
        return self.results
    
    def generate_report(self):
        """Generate and save report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"performance_report_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print("\n" + "=" * 70)
        print("📊 PERFORMANCE SUMMARY")
        print("=" * 70)
        
        if 'encrypt_send' in self.results and 'mean' in self.results['encrypt_send']:
            print(f"  🔐 Encrypt + Send:     {self.results['encrypt_send']['mean']:.2f} ms (avg)")
            print(f"                         {self.results['encrypt_send']['success_rate']:.0f}% success")
        
        if 'get_messages' in self.results and 'mean' in self.results['get_messages']:
            print(f"  📩 Get Messages:       {self.results['get_messages']['mean']:.2f} ms (avg)")
        
        if 'fastapi_messages' in self.results and 'mean' in self.results['fastapi_messages']:
            print(f"  🗄️ FastAPI Direct:     {self.results['fastapi_messages']['mean']:.2f} ms (avg)")
        
        if 'load_test' in self.results and 'avg_latency' in self.results['load_test']:
            print(f"  🚦 Load Test:          {self.results['load_test']['avg_latency']:.2f} ms (avg)")
            print(f"                         P95: {self.results['load_test']['p95_latency']:.2f} ms")
            print(f"                         {self.results['load_test']['success_rate']:.0f}% success")
        
        if 'websocket' in self.results and 'avg_latency' in self.results['websocket']:
            print(f"  🔌 WebSocket:          {self.results['websocket']['avg_latency']:.2f} ms (avg)")
        
        print("=" * 70)
        print(f"📁 Report saved: {filename}")
        
        # Save readable version
        readable_filename = f"performance_report_{timestamp}.txt"
        with open(readable_filename, 'w') as f:
            f.write("MLS PERFORMANCE TEST REPORT\n")
            f.write("=" * 50 + "\n\n")
            f.write(json.dumps(self.results, indent=2))
        
        print(f"📁 Readable report: {readable_filename}")


# ============ MAIN ============
if __name__ == "__main__":
    import sys
    
    print("=" * 70)
    print("MLS STANDALONE PERFORMANCE TEST")
    print("=" * 70)
    
    if len(sys.argv) >= 5:
        token = sys.argv[1]
        user_id = sys.argv[2]
        group_id_hex = sys.argv[3]
        group_id_b64 = sys.argv[4]
        
        print(f"\n📋 Test Configuration:")
        print(f"   User ID: {user_id[:20]}...")
        print(f"   Group ID: {group_id_hex[:20]}...")
        print(f"   Token: {token[:50]}...")
        
        tester = StandalonePerformanceTest(token, user_id, group_id_hex, group_id_b64)
        tester.run_all_tests()
        
    else:
        print("\n❌ Missing arguments!")
        print("\nUsage:")
        print("  python standalone_performance_test.py <token> <user_id> <group_id_hex> <group_id_b64>")
        print("\nExample:")
        print("  python standalone_performance_test.py \"eyJhbGciOiJIUzI1NiIs...\" \"35e9acb6-bd39-4ec5-a1a6-cb30cfe89a71\" \"ae214897af81bf7ec1c58900dae0c828\" \"riFIl6+Bv37BxYkA2uDIKA==\"")
        
        # Interactive mode
        print("\n🔧 Running in interactive mode...")
        token = input("Enter your token: ").strip()
        user_id = input("Enter your user_id: ").strip()
        group_id_hex = input("Enter group_id_hex: ").strip()
        group_id_b64 = input("Enter group_id_b64: ").strip()
        
        if token and user_id and group_id_hex and group_id_b64:
            tester = StandalonePerformanceTest(token, user_id, group_id_hex, group_id_b64)
            tester.run_all_tests()
        else:
            print("❌ All fields are required!")