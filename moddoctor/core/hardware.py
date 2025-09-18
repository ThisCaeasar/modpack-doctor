"""Hardware detection and JVM optimization recommendations."""

import platform
from typing import Dict, Any, Optional

try:
    import psutil
except ImportError:
    psutil = None


def detect_system_info() -> Dict[str, Any]:
    """
    Detect system hardware and OS information.
    
    Returns:
        Dictionary with system information
    """
    info = {
        "os": platform.system(),
        "os_version": platform.release(),
        "architecture": platform.machine(),
        "cpu_count": 1,
        "cpu_name": "Unknown",
        "total_ram_gb": 0.0,
        "available_ram_gb": 0.0
    }
    
    if psutil:
        try:
            # CPU information
            info["cpu_count"] = psutil.cpu_count(logical=True)
            
            # Memory information
            memory = psutil.virtual_memory()
            info["total_ram_gb"] = round(memory.total / (1024**3), 1)
            info["available_ram_gb"] = round(memory.available / (1024**3), 1)
            
        except Exception:
            pass
    
    # Try to get more detailed CPU info
    try:
        if platform.system() == "Windows":
            import subprocess
            result = subprocess.run(
                ["wmic", "cpu", "get", "name"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    info["cpu_name"] = lines[1].strip()
        elif platform.system() == "Linux":
            try:
                with open('/proc/cpuinfo', 'r') as f:
                    for line in f:
                        if line.startswith('model name'):
                            info["cpu_name"] = line.split(':')[1].strip()
                            break
            except Exception:
                pass
        elif platform.system() == "Darwin":
            import subprocess
            try:
                result = subprocess.run(
                    ["sysctl", "-n", "machdep.cpu.brand_string"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    info["cpu_name"] = result.stdout.strip()
            except Exception:
                pass
    except Exception:
        pass
    
    return info


def recommend_jvm_args(total_ram_gb: Optional[float] = None, 
                      user_ram_gb: Optional[float] = None) -> Dict[str, Any]:
    """
    Recommend JVM arguments based on system specs.
    
    Args:
        total_ram_gb: Total system RAM in GB (detected if None)
        user_ram_gb: User-specified RAM allocation in GB
        
    Returns:
        Dictionary with JVM recommendations
    """
    system_info = detect_system_info()
    
    if total_ram_gb is None:
        total_ram_gb = system_info["total_ram_gb"]
    
    # Determine recommended RAM allocation
    if user_ram_gb:
        allocated_ram_gb = user_ram_gb
    else:
        allocated_ram_gb = _calculate_recommended_ram(total_ram_gb)
    
    # Generate JVM arguments
    jvm_args = _generate_jvm_args(allocated_ram_gb, system_info)
    
    return {
        "system_info": system_info,
        "allocated_ram_gb": allocated_ram_gb,
        "jvm_args": jvm_args,
        "recommendations": _get_performance_recommendations(system_info, allocated_ram_gb)
    }


def _calculate_recommended_ram(total_ram_gb: float) -> float:
    """Calculate recommended RAM allocation based on total system RAM."""
    if total_ram_gb <= 4:
        return max(2.0, total_ram_gb * 0.5)
    elif total_ram_gb <= 8:
        return max(3.0, total_ram_gb * 0.6)
    elif total_ram_gb <= 16:
        return max(4.0, total_ram_gb * 0.7)
    else:
        return max(8.0, min(12.0, total_ram_gb * 0.75))


def _generate_jvm_args(ram_gb: float, system_info: Dict[str, Any]) -> str:
    """Generate JVM arguments string."""
    ram_mb = int(ram_gb * 1024)
    
    args = [
        f"-Xms{ram_mb//2}m",  # Initial heap size (half of max)
        f"-Xmx{ram_mb}m",     # Maximum heap size
    ]
    
    # Garbage collector selection based on RAM
    if ram_gb >= 4:
        # G1GC for larger heaps
        args.extend([
            "-XX:+UseG1GC",
            "-XX:+ParallelRefProcEnabled",
            "-XX:MaxGCPauseMillis=200",
            "-XX:+UnlockExperimentalVMOptions",
            "-XX:+DisableExplicitGC",
            "-XX:+AlwaysPreTouch",
            "-XX:G1NewSizePercent=30",
            "-XX:G1MaxNewSizePercent=40",
            "-XX:G1HeapRegionSize=8M",
            "-XX:G1ReservePercent=20",
            "-XX:G1HeapWastePercent=5",
            "-XX:G1MixedGCCountTarget=4",
            "-XX:InitiatingHeapOccupancyPercent=15",
            "-XX:G1MixedGCLiveThresholdPercent=90",
            "-XX:G1RSetUpdatingPauseTimePercent=5",
            "-XX:SurvivorRatio=32",
            "-XX:+PerfDisableSharedMem",
            "-XX:MaxTenuringThreshold=1"
        ])
    else:
        # Parallel GC for smaller heaps
        args.extend([
            "-XX:+UseParallelGC",
            "-XX:+ParallelRefProcEnabled",
            "-XX:+DisableExplicitGC"
        ])
    
    # JVM optimizations
    args.extend([
        "-Dusing.aikars.flags=https://mcflags.emc.gs",
        "-Daikars.new.flags=true",
        "-XX:+UseCompressedOops",
        "-XX:+UseCompressedClassPointers"
    ])
    
    # Platform-specific optimizations
    if system_info["os"] == "Windows":
        args.append("-XX:+UseParallelOldGC")
    
    return " ".join(args)


def _get_performance_recommendations(system_info: Dict[str, Any], 
                                   allocated_ram_gb: float) -> list:
    """Generate performance recommendations based on system specs."""
    recommendations = []
    
    total_ram = system_info["total_ram_gb"]
    cpu_count = system_info["cpu_count"]
    
    # RAM recommendations
    if total_ram < 8:
        recommendations.append(
            "Consider upgrading to at least 8GB RAM for better modded Minecraft performance"
        )
    elif allocated_ram_gb / total_ram > 0.8:
        recommendations.append(
            "Allocated RAM is high relative to total system RAM. Consider reducing allocation or adding more RAM"
        )
    
    # CPU recommendations
    if cpu_count < 4:
        recommendations.append(
            "Consider upgrading to a CPU with at least 4 cores for better performance with many mods"
        )
    
    # OS recommendations
    if system_info["os"] == "Windows":
        recommendations.append(
            "For Windows: Ensure Windows Game Mode is enabled for better performance"
        )
    elif system_info["os"] == "Linux":
        recommendations.append(
            "For Linux: Consider using a low-latency kernel for better performance"
        )
    
    # General recommendations
    recommendations.extend([
        "Close unnecessary background applications before playing",
        "Use a fast SSD for better world loading times",
        "Keep your graphics drivers updated"
    ])
    
    return recommendations