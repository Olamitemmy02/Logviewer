from logviewer.discovery import get_log_summary
from logviewer.system import get_system_info


print("\nSYSTEM INFORMATION")
print("=" * 50)

info = get_system_info()

for key, value in info.items():
    print(f"{key}: {value}")


print("\nDISCOVERED LOG FILES")
print("=" * 50)

logs = get_log_summary()

for log in logs:
    print(log["path"])

print()
print(f"Found {len(logs)} accessible log files.")
