"""Hardware detection and JVM optimization recommendations."""

import platform
from typing import Dict, Optional, Tuple

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class HardwareInfo:
    """Hardware information and JVM recommendations."""
    
    def __init__(self):
        """Initialize hardware detection."""
        self.cpu_info = self._get_cpu_info()
        self.memory_info = self._get_memory_info()
        self.system_info = self._get_system_info()
    
    def _get_cpu_info(self) -> Dict[str, any]:
        """Get CPU information."""
        info = {
            "cores": 1,
            "logical_cores": 1,
            "frequency": None,
            "name": "Unknown"
        }
        
        if PSUTIL_AVAILABLE:
            try:
                info["cores"] = psutil.cpu_count(logical=False) or 1
                info["logical_cores"] = psutil.cpu_count(logical=True) or 1
                
                freq = psutil.cpu_freq()
                if freq:
                    info["frequency"] = freq.max or freq.current
                    
            except Exception:
                pass
        
        # Try to get CPU name from platform
        try:
            if platform.system() == "Windows":
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                  r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
                    info["name"] = winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
            elif platform.system() == "Linux":
                try:
                    with open("/proc/cpuinfo", "r") as f:
                        for line in f:
                            if "model name" in line:
                                info["name"] = line.split(":")[1].strip()
                                break
                except Exception:
                    pass
        except Exception:
            pass
        
        return info
    
    def _get_memory_info(self) -> Dict[str, any]:
        """Get memory information."""
        info = {
            "total_gb": 4.0,  # Default assumption
            "available_gb": 2.0,
            "usage_percent": 50.0
        }
        
        if PSUTIL_AVAILABLE:
            try:
                memory = psutil.virtual_memory()
                info["total_gb"] = memory.total / (1024**3)
                info["available_gb"] = memory.available / (1024**3)
                info["usage_percent"] = memory.percent
            except Exception:
                pass
        
        return info
    
    def _get_system_info(self) -> Dict[str, str]:
        """Get system information."""
        return {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "architecture": platform.architecture()[0]
        }
    
    def get_recommended_ram_allocation(self) -> Tuple[float, str]:
        """
        Get recommended RAM allocation for Minecraft.
        
        Returns:
            Tuple of (recommended_gb, explanation)
        """
        total_ram = self.memory_info["total_gb"]
        
        if total_ram <= 4:
            return 2.0, "Limited system RAM detected"
        elif total_ram <= 8:
            return 4.0, "Moderate system RAM - safe allocation"
        elif total_ram <= 16:
            return 6.0, "Good system RAM - recommended for modded"
        elif total_ram <= 32:
            return 8.0, "High system RAM - optimal for heavy modpacks"
        else:
            return 12.0, "Very high system RAM - maximum recommended"
    
    def generate_jvm_arguments(self, ram_gb: Optional[float] = None) -> str:
        """
        Generate optimized JVM arguments.
        
        Args:
            ram_gb: RAM allocation in GB. If None, uses recommended amount.
            
        Returns:
            JVM arguments string
        """
        if ram_gb is None:
            ram_gb, _ = self.get_recommended_ram_allocation()
        
        # Ensure minimum and maximum bounds
        ram_gb = max(1.0, min(ram_gb, 32.0))
        
        ram_mb = int(ram_gb * 1024)
        
        # Base arguments
        args = [
            f"-Xms{ram_mb}m",
            f"-Xmx{ram_mb}m"
        ]
        
        # G1GC arguments for better performance
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
        
        # Additional optimizations
        args.extend([
            "-Dsun.rmi.dgc.server.gcInterval=2147483646",
            "-Dsun.rmi.dgc.client.gcInterval=2147483646",
            "-Dfile.encoding=UTF-8"
        ])
        
        # Java 17+ specific optimizations
        try:
            java_version = platform.java_ver()[0]
            if java_version and int(java_version.split('.')[0]) >= 17:
                args.extend([
                    "-XX:+UseZGC",  # Alternative to G1GC for Java 17+
                    "--add-modules=jdk.incubator.vector"
                ])
        except Exception:
            pass
        
        return " ".join(args)
    
    def get_performance_recommendations(self) -> Dict[str, str]:
        """Get performance recommendations based on hardware."""
        recommendations = {}
        
        # CPU recommendations
        cores = self.cpu_info["cores"]
        if cores >= 8:
            recommendations["cpu"] = "Excellent CPU for modded Minecraft. Consider high-performance modpacks."
        elif cores >= 4:
            recommendations["cpu"] = "Good CPU for modded Minecraft. Most modpacks should run well."
        else:
            recommendations["cpu"] = "Limited CPU cores. Stick to lighter modpacks for best performance."
        
        # RAM recommendations
        total_ram = self.memory_info["total_gb"]
        if total_ram >= 16:
            recommendations["ram"] = "Excellent RAM for heavy modpacks. You can run large kitchen-sink packs."
        elif total_ram >= 8:
            recommendations["ram"] = "Good RAM for most modpacks. Avoid extremely large packs."
        elif total_ram >= 4:
            recommendations["ram"] = "Minimum RAM for modded Minecraft. Stick to smaller focused packs."
        else:
            recommendations["ram"] = "Very limited RAM. Modded Minecraft may struggle."
        
        # System recommendations
        system = self.system_info["system"]
        if system == "Windows":
            recommendations["system"] = "Windows detected. Consider disabling Windows Defender scanning of Minecraft folder for better performance."
        elif system == "Linux":
            recommendations["system"] = "Linux detected. Generally good performance for modded Minecraft."
        elif system == "Darwin":
            recommendations["system"] = "macOS detected. Performance may vary depending on hardware."
        
        return recommendations
    
    def get_hardware_summary(self) -> str:
        """Get a human-readable hardware summary."""
        cpu = self.cpu_info
        mem = self.memory_info
        sys = self.system_info
        
        summary = []
        summary.append(f"System: {sys['system']} {sys['release']} ({sys['architecture']})")
        summary.append(f"CPU: {cpu['name']} ({cpu['cores']} cores, {cpu['logical_cores']} threads)")
        
        if cpu['frequency']:
            summary.append(f"CPU Frequency: {cpu['frequency']:.1f} MHz")
        
        summary.append(f"RAM: {mem['total_gb']:.1f} GB total, {mem['available_gb']:.1f} GB available")
        summary.append(f"RAM Usage: {mem['usage_percent']:.1f}%")
        
        recommended_ram, reason = self.get_recommended_ram_allocation()
        summary.append(f"Recommended Minecraft RAM: {recommended_ram:.1f} GB ({reason})")
        
        return "\n".join(summary)


def get_hardware_info() -> HardwareInfo:
    """Get current hardware information."""
    return HardwareInfo()


def generate_optimized_jvm_args(ram_gb: Optional[float] = None) -> str:
    """
    Generate optimized JVM arguments for the current system.
    
    Args:
        ram_gb: RAM allocation in GB. If None, uses recommended amount.
        
    Returns:
        JVM arguments string
    """
    hardware = get_hardware_info()
    return hardware.generate_jvm_arguments(ram_gb)