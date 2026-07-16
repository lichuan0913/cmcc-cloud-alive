"""Small stdlib replacement for the official getDeviceInfos() payload."""

import shutil
import socket


def _read_cpu_model():
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return "unknown"


def _meminfo():
    result = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                key, value = line.split(":", 1)
                result[key] = int(value.strip().split()[0]) * 1024
    except OSError:
        pass
    return result


def _device_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def collect_device_info(width=1920, height=1080):
    mem = _meminfo()
    total_mem = mem.get("MemTotal") or 0
    free_mem = (mem.get("MemAvailable") or mem.get("MemFree") or 0)
    used_mem_pct = int((1 - free_mem / total_mem) * 100) if total_mem else 0
    disk = shutil.disk_usage("/")
    used_disk_pct = int(disk.used / disk.total * 100) if disk.total else 0
    return {
        "cpuModel": _read_cpu_model(),
        "cpuUsageRate": "0%",
        "memory": f"{max(1, int(total_mem / 1024 / 1024 / 1024))}GB" if total_mem else "0GB",
        "memoryUsageRate": f"{used_mem_pct}%",
        "storage": f"{max(1, int(disk.total / 1024 / 1024 / 1024))}GB",
        "storageUsageRate": f"{used_disk_pct}%",
        "deviceResolutionRatio": f"{width}*{height}",
        "width": str(width),
        "height": str(height),
        "deviceIp": _device_ip(),
    }
