# run_performance_tests.py
import json
import time
from datetime import datetime
import requests
import base64

# Import your modules
import api_client
from app import user_crypto_store

class PerformanceTestSuite:
    def __init__(self, token, user_id, group_id_hex, group_id_b64):
        self.token = token
        self.user_id = user_id
        self.group_id_hex = group_id_hex
        self.group_id_b64 = group_id_b64
        self.results = {}
    
    def test_encryption_decryption(self):
        """Test encryption and decryption performance"""
        print("\n[1/3] Testing encryption/decryption...")
        
        from performance_test import PerformanceTest
        pt = PerformanceTest()
        
        # Get group state
        group_state = user_crypto_store[self.user_id]['groups'][self.group_id_b64]
        
        # Test encryption
        test_message = "X" * 256
        result = pt.measure_time(
            api_client.encrypt_and_send_message,
            self.group_id_b64, test_message, self.token, self.user_id, group_state,
            iterations=10
        )
        self.results['encryption'] = result
        
        print(f"   Encryption: {result['mean']:.2f} ms avg")
        return True
    
    def test_tree_rebuild(self):
        """Test tree rebuild performance"""
        print("\n[2/3] Testing tree rebuild...")
        
        from performance_test import PerformanceTest
        pt = PerformanceTest()
        
        start = time.perf_counter()
        tree, epoch, members = api_client.build_tree_by_replay(self.group_id_b64, self.token)
        end = time.perf_counter()
        
        self.results['tree_rebuild'] = (end - start) * 1000
        print(f"   Tree rebuild: {self.results['tree_rebuild']:.2f} ms")
        print(f"   Members: {len(members)}, Leaves: {len(tree.leaves)}")
        return True
    
    def test_load(self):
        """Run load test"""
        print("\n[3/3] Running load test...")
        
        from load_test import LoadTest
        lt = LoadTest()
        
        result = lt.run_concurrent_test(
            self.group_id_hex, self.token, 
            num_users=5, messages_per_user=3
        )
        
        self.results['load'] = result
        print(f"   Load test: {result.get('avg_latency', 0):.2f} ms avg, {result.get('total_errors', 0)} errors")
        return True
    
    def run_all_tests(self):
        """Run all performance tests"""
        print("=" * 60)
        print("PERFORMANCE TEST SUITE")
        print("=" * 60)
        
        self.test_encryption_decryption()
        self.test_tree_rebuild()
        self.test_load()
        
        self.generate_report()
        return self.results
    
    def generate_report(self):
        """Generate JSON report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"performance_report_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print("\n" + "=" * 60)
        print("PERFORMANCE SUMMARY")
        print("=" * 60)
        if 'encryption' in self.results:
            print(f"  Encryption (avg):     {self.results['encryption']['mean']:.2f} ms")
        if 'tree_rebuild' in self.results:
            print(f"  Tree Rebuild:         {self.results['tree_rebuild']:.2f} ms")
        if 'load' in self.results:
            print(f"  Load Test (avg):      {self.results['load'].get('avg_latency', 0):.2f} ms")
            print(f"  Load Test (p95):      {self.results['load'].get('p95_latency', 0):.2f} ms")
        print("=" * 60)
        print(f"📊 Report saved to: {filename}")


# ============ MAIN EXECUTION ============
if __name__ == "__main__":
    import sys
    
    print("=" * 60)
    print("MLS Performance Test Runner")
    print("=" * 60)
    
    # You need to provide these values
    print("\n⚠️  Before running, you need to:")
    print("   1. Login to the application")
    print("   2. Have a group created")
    print("   3. Copy your token, user_id, and group info")
    print("\n📝 Example:")
    print("   python run_performance_tests.py <token> <user_id> <group_id_hex> <group_id_b64>")
    
    if len(sys.argv) >= 5:
        token = sys.argv[1]
        user_id = sys.argv[2]
        group_id_hex = sys.argv[3]
        group_id_b64 = sys.argv[4]
        
        runner = PerformanceTestSuite(token, user_id, group_id_hex, group_id_b64)
        runner.run_all_tests()
    else:
        print("\n❌ Missing arguments. Please provide:")
        print("   token, user_id, group_id_hex, group_id_b64")
        
        # Interactive mode
        print("\n🔧 Running in interactive mode...")
        token = input("Enter your token: ").strip()
        user_id = input("Enter your user_id: ").strip()
        group_id_hex = input("Enter group_id_hex: ").strip()
        group_id_b64 = input("Enter group_id_b64: ").strip()
        
        if token and user_id and group_id_hex and group_id_b64:
            runner = PerformanceTestSuite(token, user_id, group_id_hex, group_id_b64)
            runner.run_all_tests()
        else:
            print("❌ All fields are required!")