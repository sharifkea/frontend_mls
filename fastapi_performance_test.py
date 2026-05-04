# fastapi_performance_test.py
import requests
import time
import statistics
import json
from datetime import datetime

class FastAPIPerformanceTest:
    def __init__(self, token, group_id_hex, fastapi_url="http://localhost:8000"):
        self.token = token
        self.group_id_hex = group_id_hex
        self.fastapi_url = fastapi_url
        self.results = {}
    
    def get_headers(self):
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
    
    def test_get_messages(self, iterations=10):
        """Test FastAPI get messages endpoint"""
        print(f"\n📩 Testing FastAPI get messages ({iterations} iterations)...")
        
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
                    latency = (end - start) * 1000
                    times.append(latency)
                    print(f"   Request {i+1}: {latency:.2f} ms")
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
    
    def test_get_group_members(self, iterations=10):
        """Test FastAPI get group members endpoint"""
        print(f"\n👥 Testing FastAPI get group members ({iterations} iterations)...")
        
        times = []
        errors = 0
        
        for i in range(iterations):
            start = time.perf_counter()
            try:
                response = requests.get(
                    f"{self.fastapi_url}/groups/{self.group_id_hex}/members",
                    headers=self.get_headers(),
                    timeout=30
                )
                end = time.perf_counter()
                
                if response.status_code == 200:
                    latency = (end - start) * 1000
                    times.append(latency)
                    print(f"   Request {i+1}: {latency:.2f} ms")
                else:
                    errors += 1
            except:
                errors += 1
        
        if times:
            return {
                'mean': statistics.mean(times),
                'median': statistics.median(times),
                'min': min(times),
                'max': max(times),
                'success_rate': (iterations - errors) / iterations * 100
            }
        return {'error': 'No successful requests'}
    
    def test_check_health(self):
        """Test basic connectivity"""
        print("\n🏥 Checking FastAPI health...")
        
        start = time.perf_counter()
        try:
            response = requests.get(
                f"{self.fastapi_url}/test-db",
                timeout=10
            )
            end = time.perf_counter()
            
            if response.status_code == 200:
                latency = (end - start) * 1000
                print(f"   FastAPI is healthy ({latency:.2f} ms)")
                return True
        except:
            pass
        
        print("   FastAPI is not responding!")
        return False
    
    def run_all_tests(self):
        """Run complete test suite"""
        print("=" * 60)
        print("🚀 FASTAPI PERFORMANCE TEST SUITE")
        print("=" * 60)
        
        print(f"\n📋 Configuration:")
        print(f"   Group ID: {self.group_id_hex}")
        print(f"   Token: {self.token[:50]}...")
        
        if not self.test_check_health():
            return
        
        self.results['get_messages'] = self.test_get_messages(iterations=10)
        self.results['get_members'] = self.test_get_group_members(iterations=10)
        
        self.generate_report()
        return self.results
    
    def generate_report(self):
        """Generate report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"fastapi_performance_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print("\n" + "=" * 60)
        print("📊 PERFORMANCE SUMMARY")
        print("=" * 60)
        
        if 'get_messages' in self.results and 'mean' in self.results['get_messages']:
            print(f"  Get Messages:    {self.results['get_messages']['mean']:.2f} ms (avg)")
            print(f"                   Min: {self.results['get_messages']['min']:.2f} ms")
            print(f"                   Max: {self.results['get_messages']['max']:.2f} ms")
        
        if 'get_members' in self.results and 'mean' in self.results['get_members']:
            print(f"  Get Members:     {self.results['get_members']['mean']:.2f} ms (avg)")
        
        print("=" * 60)
        print(f"📁 Report saved: {filename}")


if __name__ == "__main__":
    import sys
    
    # Use your existing token
    TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMzVlOWFjYjYtYmQzOS00ZWM1LWExYTYtY2IzMGNmZTg5YTcxIiwiZXhwIjoxNzc3ODgzOTA5fQ.irwFkTGxGDTEGo1XUeP55v-oX0djEUu1soCWVS_fMx0"
    GROUP_ID_HEX = "FEABE16AA9A9C341F7CBFD5305B35775"
    
    tester = FastAPIPerformanceTest(TOKEN, GROUP_ID_HEX)
    tester.run_all_tests()