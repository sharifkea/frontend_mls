# monitoring.py
import psutil
import threading
import time
import statistics

class PerformanceMonitor:
    def __init__(self):
        self.metrics = {
            'cpu_usage': [],
            'memory_usage': [],
            'request_count': 0,
            'avg_response_time': 0,
            'running': False
        }
    
    def start_monitoring(self):
        """Start monitoring in background thread"""
        self.metrics['running'] = True
        
        def monitor():
            while self.metrics['running']:
                self.metrics['cpu_usage'].append(psutil.cpu_percent(interval=1))
                self.metrics['memory_usage'].append(psutil.virtual_memory().percent)
                time.sleep(5)
        
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
        print("📊 Performance monitoring started")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.metrics['running'] = False
    
    def get_metrics(self):
        """Get current metrics"""
        cpu_history = self.metrics['cpu_usage'][-60:] if len(self.metrics['cpu_usage']) >= 60 else self.metrics['cpu_usage']
        memory_history = self.metrics['memory_usage'][-60:] if len(self.metrics['memory_usage']) >= 60 else self.metrics['memory_usage']
        
        return {
            'avg_cpu': statistics.mean(cpu_history) if cpu_history else 0,
            'max_cpu': max(cpu_history) if cpu_history else 0,
            'avg_memory': statistics.mean(memory_history) if memory_history else 0,
            'max_memory': max(memory_history) if memory_history else 0,
            'total_requests': self.metrics['request_count'],
            'avg_response_time': self.metrics['avg_response_time']
        }
    
    def record_request(self, response_time_ms):
        """Record a request response time"""
        self.metrics['request_count'] += 1
        # Update rolling average
        self.metrics['avg_response_time'] = (
            (self.metrics['avg_response_time'] * (self.metrics['request_count'] - 1) + response_time_ms) 
            / self.metrics['request_count']
        )