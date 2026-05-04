# performance_timers.py
import time
import statistics
from api_client import encrypt_and_send_message, decrypt_message
from app import add_member_to_group, create_group_with_online
import api_client
import api_client_2
import json
from datetime import datetime

class PerformanceTimer:
    """Safe timer wrapper - does not modify existing code"""
    
    @staticmethod
    def time_encryption(group_id_b64, message_text, token, user_id, group_state, iterations=10):
        """Measure encryption time without modifying encrypt_and_send_message"""
        print(f"\n{'='*60}")
        print(f"🔐 MEASURING ENCRYPTION PERFORMANCE ({iterations} iterations)")
        print(f"{'='*60}")
        
        times = []
        results = []
        
        for i in range(iterations):
            start = time.perf_counter()
            result = encrypt_and_send_message(
                group_id_b64, message_text, token, user_id, group_state
            )
            end = time.perf_counter()
            elapsed_ms = (end - start) * 1000
            times.append(elapsed_ms)
            results.append(result)
            
            status = "✅" if result.get('success') else "❌"
            print(f"   Iteration {i+1}: {elapsed_ms:.2f}ms {status}")
        
        if times:
            return {
                'mean': statistics.mean(times),
                'median': statistics.median(times),
                'min': min(times),
                'max': max(times),
                'stddev': statistics.stdev(times) if len(times) > 1 else 0,
                'success_rate': sum(1 for r in results if r.get('success')) / iterations * 100,
                'all_times': times
            }
        return None
    
    @staticmethod
    def time_decryption(msg_data, group_state, user_id, iterations=10):
        """Measure decryption time without modifying decrypt_message"""
        print(f"\n{'='*60}")
        print(f"🔓 MEASURING DECRYPTION PERFORMANCE ({iterations} iterations)")
        print(f"{'='*60}")
        
        times = []
        results = []
        
        for i in range(iterations):
            start = time.perf_counter()
            result = decrypt_message(msg_data, group_state, user_id)
            end = time.perf_counter()
            elapsed_ms = (end - start) * 1000
            times.append(elapsed_ms)
            results.append(result)
            
            print(f"   Iteration {i+1}: {elapsed_ms:.2f}ms")
        
        if times:
            return {
                'mean': statistics.mean(times),
                'median': statistics.median(times),
                'min': min(times),
                'max': max(times),
                'stddev': statistics.stdev(times) if len(times) > 1 else 0,
                'all_times': times
            }
        return None
    
    @staticmethod
    def time_tree_build(group_id_b64, token, iterations=5):
        """Measure tree rebuild time"""
        print(f"\n{'='*60}")
        print(f"🌲 MEASURING TREE REBUILD PERFORMANCE ({iterations} iterations)")
        print(f"{'='*60}")
        
        times = []
        
        for i in range(iterations):
            start = time.perf_counter()
            tree, epoch, members = api_client.build_tree_by_replay(group_id_b64, token)
            end = time.perf_counter()
            elapsed_ms = (end - start) * 1000
            times.append(elapsed_ms)
            
            print(f"   Iteration {i+1}: {elapsed_ms:.2f}ms (leaves: {len(tree.leaves)})")
        
        if times:
            return {
                'mean': statistics.mean(times),
                'median': statistics.median(times),
                'min': min(times),
                'max': max(times),
                'stddev': statistics.stdev(times) if len(times) > 1 else 0,
                'all_times': times
            }
        return None
    
    @staticmethod
    def time_epoch_derivation(tree, cipher_suite, final_secret, iterations=100):
        """Measure epoch secret derivation time"""
        print(f"\n{'='*60}")
        print(f"🔑 MEASURING EPOCH DERIVATION ({iterations} iterations)")
        print(f"{'='*60}")
        
        times = []
        
        for i in range(iterations):
            start = time.perf_counter()
            epoch_secret, root_secret = api_client_2.derive_epoch_secret_from_tree(
                tree, cipher_suite, final_secret
            )
            end = time.perf_counter()
            elapsed_ms = (end - start) * 1000
            times.append(elapsed_ms)
        
        if times:
            return {
                'mean': statistics.mean(times),
                'median': statistics.median(times),
                'min': min(times),
                'max': max(times),
                'stddev': statistics.stdev(times) if len(times) > 1 else 0,
            }
        return None


class APIPerformanceTest:
    """Test API endpoints without modifying them"""
    
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
        self.session = None
    
    def test_get_messages_api(self, group_id_hex, token, iterations=10):
        """Test GET messages API endpoint"""
        import requests
        
        print(f"\n{'='*60}")
        print(f"📩 MEASURING GET MESSAGES API ({iterations} iterations)")
        print(f"{'='*60}")
        
        times = []
        headers = {"Authorization": f"Bearer {token}"}
        
        for i in range(iterations):
            start = time.perf_counter()
            response = requests.post(
                f"{self.base_url}/api/messages/get",
                json={"group_id_hex": group_id_hex},
                headers=headers
            )
            end = time.perf_counter()
            elapsed_ms = (end - start) * 1000
            times.append(elapsed_ms)
            
            status = "✅" if response.status_code == 200 else "❌"
            print(f"   Iteration {i+1}: {elapsed_ms:.2f}ms {status}")
        
        if times:
            return {
                'mean': statistics.mean(times),
                'median': statistics.median(times),
                'min': min(times),
                'max': max(times),
                'stddev': statistics.stdev(times) if len(times) > 1 else 0,
            }
        return None


def run_performance_tests():
    """Run all performance tests"""
    print("\n" + "=" * 70)
    print("🚀 MLS PERFORMANCE TEST SUITE")
    print("=" * 70)
    print("\n⚠️  Note: This test does not modify any working code.")
    print("   It only measures performance of existing functions.\n")
    
    results = {}
    
    # You need to provide these values from your actual session
    print("📋 Please provide the following from your browser console:")
    print("   - user_id")
    print("   - token")
    print("   - group_id_hex")
    print("   - group_id_b64")
    print()
    
    # For demonstration, you would call the timers like this:
    # timer = PerformanceTimer()
    # results['encryption'] = timer.time_encryption(...)
    # results['decryption'] = timer.time_decryption(...)
    # results['tree_build'] = timer.time_tree_build(...)
    
    return results


if __name__ == "__main__":
    print("=" * 70)
    print("MLS Performance Measurement Tool")
    print("=" * 70)
    print("\nThis module provides timing functions WITHOUT modifying")
    print("your existing working code. Use it as:")
    print()
    print("  from performance_timers import PerformanceTimer")
    print()
    print("  timer = PerformanceTimer()")
    print("  result = timer.time_encryption(group_id_b64, message, token, user_id, group_state)")
    print("  print(f\"Encryption avg: {result['mean']:.2f}ms\")")
    print()