from logviewer.discovery import discover_log_files
from logviewer.sources.file_source import FileLogSource


logs = discover_log_files()

if not logs:
    print("No accessible logs found.")
    raise SystemExit(0)


print("Available logs:")
print()

for index, path in enumerate(logs, start=1):
    print(f"[{index}] {path}")

print()

choice = input("Select a log number: ").strip()

try:
    index = int(choice) - 1
    selected = logs[index]

except (ValueError, IndexError):
    print("Invalid selection.")
    raise SystemExit(1)


print()
print(f"Reading: {selected}")
print("=" * 70)

source = FileLogSource(selected)

for line in source.read_last(20):
    print(line)
