# Create a separate script run_monitor.py
from monitoring import PerformanceMonitor
import time

monitor = PerformanceMonitor()
monitor.start_monitoring()

print("Monitoring for 60 seconds...")
time.sleep(60)

metrics = monitor.get_metrics()
print(f"CPU: {metrics['avg_cpu']}%")
print(f"Memory: {metrics['avg_memory']}%")
monitor.stop_monitoring()