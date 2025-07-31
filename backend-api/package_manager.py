"""
Linux-Link Package Manager

Provides comprehensive package management capabilities with support for
pacman, AUR helpers, and package search functionality.
"""

import os
import json
import subprocess
import logging
import re
from typing import Dict, List, Optional, Union, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import threading
import time

logger = logging.getLogger(__name__)


class PackageStatus(Enum):
    INSTALLED = "installed"
    AVAILABLE = "available"
    UPGRADABLE = "upgradable"
    ORPHANED = "orphaned"
    EXPLICIT = "explicit"


class PackageSource(Enum):
    OFFICIAL = "official"
    AUR = "aur"
    LOCAL = "local"
    UNKNOWN = "unknown"


@dataclass
class Package:
    """Represents a package with its metadata"""
    name: str
    version: str
    description: str
    status: PackageStatus
    source: PackageSource
    size: Optional[int] = None
    installed_size: Optional[int] = None
    dependencies: List[str] = None
    provides: List[str] = None
    conflicts: List[str] = None
    replaces: List[str] = None
    groups: List[str] = None
    url: Optional[str] = None
    licenses: List[str] = None
    architecture: Optional[str] = None
    build_date: Optional[str] = None
    install_date: Optional[str] = None
    packager: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['status'] = self.status.value
        data['source'] = self.source.value
        return data


@dataclass
class PackageOperation:
    """Represents a package operation (install, remove, upgrade)"""
    operation_id: str
    operation_type: str
    packages: List[str]
    status: str
    started_at: float
    completed_at: Optional[float] = None
    progress: int = 0
    output: List[str] = None
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


class PackageManagerError(Exception):
    """Base exception for package manager operations"""
    def __init__(self, message: str, error_code: str, details: Dict = None):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)


class PacmanManager:
    """Core pacman package manager interface"""
    
    def __init__(self):
        self.pacman_cmd = self._find_pacman()
        self.operations = {}
        self.cache_timeout = 3600  # 1 hour
        self._package_cache = {}
        self._cache_timestamp = 0
        logger.info("Pacman manager initialized")
    
    def _find_pacman(self) -> str:
        """Find pacman executable"""
        for path in ['/usr/bin/pacman', '/bin/pacman']:
            if os.path.exists(path):
                return path
        raise PackageManagerError(
            "Pacman not found on system",
            "PACMAN_NOT_FOUND"
        )
    
    def _run_command(self, cmd: List[str], timeout: int = 300) -> Tuple[int, str, str]:
        """Run a command and return exit code, stdout, stderr"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            raise PackageManagerError(
                f"Command timed out: {' '.join(cmd)}",
                "COMMAND_TIMEOUT"
            )
        except Exception as e:
            raise PackageManagerError(
                f"Command execution failed: {str(e)}",
                "COMMAND_FAILED"
            )
    
    def refresh_database(self) -> bool:
        """Refresh package database"""
        try:
            cmd = [self.pacman_cmd, '-Sy']
            exit_code, stdout, stderr = self._run_command(cmd)
            
            if exit_code == 0:
                logger.info("Package database refreshed successfully")
                self._invalidate_cache()
                return True
            else:
                logger.error(f"Failed to refresh database: {stderr}")
                return False
        
        except Exception as e:
            logger.error(f"Database refresh failed: {e}")
            return False
    
    def search_packages(self, query: str, include_aur: bool = False) -> List[Package]:
        """Search for packages by name or description"""
        try:
            packages = []
            
            # Search official repositories
            cmd = [self.pacman_cmd, '-Ss', query]
            exit_code, stdout, stderr = self._run_command(cmd)
            
            if exit_code == 0:
                packages.extend(self._parse_search_output(stdout, PackageSource.OFFICIAL))
            
            # Search AUR if requested
            if include_aur:
                aur_packages = self._search_aur(query)
                packages.extend(aur_packages)
            
            logger.info(f"Found {len(packages)} packages matching '{query}'")
            return packages
        
        except Exception as e:
            logger.error(f"Package search failed: {e}")
            return []
    
    def get_package_info(self, package_name: str) -> Optional[Package]:
        """Get detailed information about a package"""
        try:
            # Try installed packages first
            cmd = [self.pacman_cmd, '-Qi', package_name]
            exit_code, stdout, stderr = self._run_command(cmd)
            
            if exit_code == 0:
                return self._parse_package_info(stdout, PackageStatus.INSTALLED)
            
            # Try available packages
            cmd = [self.pacman_cmd, '-Si', package_name]
            exit_code, stdout, stderr = self._run_command(cmd)
            
            if exit_code == 0:
                return self._parse_package_info(stdout, PackageStatus.AVAILABLE)
            
            return None
        
        except Exception as e:
            logger.error(f"Failed to get package info for {package_name}: {e}")
            return None
    
    def list_installed_packages(self) -> List[Package]:
        """List all installed packages"""
        try:
            if self._is_cache_valid():
                return list(self._package_cache.values())
            
            cmd = [self.pacman_cmd, '-Q']
            exit_code, stdout, stderr = self._run_command(cmd)
            
            if exit_code != 0:
                raise PackageManagerError(
                    f"Failed to list packages: {stderr}",
                    "LIST_FAILED"
                )
            
            packages = []
            for line in stdout.strip().split('\\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        name, version = parts[0], parts[1]
                        package = Package(
                            name=name,
                            version=version,
                            description="",
                            status=PackageStatus.INSTALLED,
                            source=PackageSource.OFFICIAL
                        )
                        packages.append(package)
                        self._package_cache[name] = package
            
            self._cache_timestamp = time.time()
            logger.info(f"Listed {len(packages)} installed packages")
            return packages
        
        except Exception as e:
            logger.error(f"Failed to list installed packages: {e}")
            return []
    
    def list_upgradable_packages(self) -> List[Package]:
        """List packages that can be upgraded"""
        try:
            cmd = [self.pacman_cmd, '-Qu']
            exit_code, stdout, stderr = self._run_command(cmd)
            
            packages = []
            if exit_code == 0 and stdout.strip():
                for line in stdout.strip().split('\\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 4:  # name current -> new
                            name = parts[0]
                            current_version = parts[1]
                            new_version = parts[3]
                            
                            package = Package(
                                name=name,
                                version=f"{current_version} -> {new_version}",
                                description="",
                                status=PackageStatus.UPGRADABLE,
                                source=PackageSource.OFFICIAL
                            )
                            packages.append(package)
            
            logger.info(f"Found {len(packages)} upgradable packages")
            return packages
        
        except Exception as e:
            logger.error(f"Failed to list upgradable packages: {e}")
            return []
    
    def install_packages(self, package_names: List[str], no_confirm: bool = False) -> str:
        """Install packages and return operation ID"""
        try:
            operation_id = f"install_{int(time.time())}"
            
            operation = PackageOperation(
                operation_id=operation_id,
                operation_type="install",
                packages=package_names,
                status="running",
                started_at=time.time(),
                output=[]
            )
            
            self.operations[operation_id] = operation
            
            # Start installation in background thread
            thread = threading.Thread(
                target=self._install_packages_thread,
                args=(operation_id, package_names, no_confirm)
            )
            thread.daemon = True
            thread.start()
            
            logger.info(f"Started package installation: {operation_id}")
            return operation_id
        
        except Exception as e:
            logger.error(f"Failed to start package installation: {e}")
            raise PackageManagerError(
                f"Installation failed: {str(e)}",
                "INSTALL_FAILED"
            )
    
    def remove_packages(self, package_names: List[str], no_confirm: bool = False, 
                       cascade: bool = False) -> str:
        """Remove packages and return operation ID"""
        try:
            operation_id = f"remove_{int(time.time())}"
            
            operation = PackageOperation(
                operation_id=operation_id,
                operation_type="remove",
                packages=package_names,
                status="running",
                started_at=time.time(),
                output=[]
            )
            
            self.operations[operation_id] = operation
            
            # Start removal in background thread
            thread = threading.Thread(
                target=self._remove_packages_thread,
                args=(operation_id, package_names, no_confirm, cascade)
            )
            thread.daemon = True
            thread.start()
            
            logger.info(f"Started package removal: {operation_id}")
            return operation_id
        
        except Exception as e:
            logger.error(f"Failed to start package removal: {e}")
            raise PackageManagerError(
                f"Removal failed: {str(e)}",
                "REMOVE_FAILED"
            )
    
    def upgrade_system(self, no_confirm: bool = False) -> str:
        """Upgrade all packages and return operation ID"""
        try:
            operation_id = f"upgrade_{int(time.time())}"
            
            operation = PackageOperation(
                operation_id=operation_id,
                operation_type="upgrade",
                packages=["system"],
                status="running",
                started_at=time.time(),
                output=[]
            )
            
            self.operations[operation_id] = operation
            
            # Start upgrade in background thread
            thread = threading.Thread(
                target=self._upgrade_system_thread,
                args=(operation_id, no_confirm)
            )
            thread.daemon = True
            thread.start()
            
            logger.info(f"Started system upgrade: {operation_id}")
            return operation_id
        
        except Exception as e:
            logger.error(f"Failed to start system upgrade: {e}")
            raise PackageManagerError(
                f"Upgrade failed: {str(e)}",
                "UPGRADE_FAILED"
            )
    
    def _install_packages_thread(self, operation_id: str, package_names: List[str], 
                                no_confirm: bool):
        """Install packages in background thread"""
        try:
            operation = self.operations[operation_id]
            
            cmd = [self.pacman_cmd, '-S'] + package_names
            if no_confirm:
                cmd.append('--noconfirm')
            
            exit_code, stdout, stderr = self._run_command(cmd, timeout=1800)  # 30 minutes
            
            operation.completed_at = time.time()
            operation.output = stdout.split('\\n') if stdout else []
            
            if exit_code == 0:
                operation.status = "completed"
                operation.progress = 100
                self._invalidate_cache()
                logger.info(f"Package installation completed: {operation_id}")
            else:
                operation.status = "failed"
                operation.error_message = stderr
                logger.error(f"Package installation failed: {operation_id}, {stderr}")
        
        except Exception as e:
            operation = self.operations.get(operation_id)
            if operation:
                operation.status = "failed"
                operation.error_message = str(e)
                operation.completed_at = time.time()
            logger.error(f"Package installation thread failed: {e}")
    
    def _remove_packages_thread(self, operation_id: str, package_names: List[str], 
                               no_confirm: bool, cascade: bool):
        """Remove packages in background thread"""
        try:
            operation = self.operations[operation_id]
            
            cmd = [self.pacman_cmd, '-R'] + package_names
            if no_confirm:
                cmd.append('--noconfirm')
            if cascade:
                cmd.append('-c')
            
            exit_code, stdout, stderr = self._run_command(cmd, timeout=600)  # 10 minutes
            
            operation.completed_at = time.time()
            operation.output = stdout.split('\\n') if stdout else []
            
            if exit_code == 0:
                operation.status = "completed"
                operation.progress = 100
                self._invalidate_cache()
                logger.info(f"Package removal completed: {operation_id}")
            else:
                operation.status = "failed"
                operation.error_message = stderr
                logger.error(f"Package removal failed: {operation_id}, {stderr}")
        
        except Exception as e:
            operation = self.operations.get(operation_id)
            if operation:
                operation.status = "failed"
                operation.error_message = str(e)
                operation.completed_at = time.time()
            logger.error(f"Package removal thread failed: {e}")
    
    def _upgrade_system_thread(self, operation_id: str, no_confirm: bool):
        """Upgrade system in background thread"""
        try:
            operation = self.operations[operation_id]
            
            cmd = [self.pacman_cmd, '-Syu']
            if no_confirm:
                cmd.append('--noconfirm')
            
            exit_code, stdout, stderr = self._run_command(cmd, timeout=3600)  # 1 hour
            
            operation.completed_at = time.time()
            operation.output = stdout.split('\\n') if stdout else []
            
            if exit_code == 0:
                operation.status = "completed"
                operation.progress = 100
                self._invalidate_cache()
                logger.info(f"System upgrade completed: {operation_id}")
            else:
                operation.status = "failed"
                operation.error_message = stderr
                logger.error(f"System upgrade failed: {operation_id}, {stderr}")
        
        except Exception as e:
            operation = self.operations.get(operation_id)
            if operation:
                operation.status = "failed"
                operation.error_message = str(e)
                operation.completed_at = time.time()
            logger.error(f"System upgrade thread failed: {e}")
    
    def get_operation_status(self, operation_id: str) -> Optional[PackageOperation]:
        """Get status of a package operation"""
        return self.operations.get(operation_id)
    
    def _parse_search_output(self, output: str, source: PackageSource) -> List[Package]:
        """Parse pacman search output"""
        packages = []
        lines = output.strip().split('\\n')
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line and not line.startswith(' '):
                # Package name line
                parts = line.split()
                if len(parts) >= 2:
                    name_version = parts[0]
                    if '/' in name_version:
                        name = name_version.split('/')[-1]
                    else:
                        name = name_version
                    
                    version = parts[1] if len(parts) > 1 else ""
                    
                    # Description line (next line)
                    description = ""
                    if i + 1 < len(lines):
                        desc_line = lines[i + 1].strip()
                        if desc_line.startswith(' '):
                            description = desc_line.strip()
                    
                    package = Package(
                        name=name,
                        version=version,
                        description=description,
                        status=PackageStatus.AVAILABLE,
                        source=source
                    )
                    packages.append(package)
            i += 1
        
        return packages
    
    def _parse_package_info(self, output: str, status: PackageStatus) -> Package:
        """Parse detailed package information"""
        lines = output.strip().split('\\n')
        info = {}
        
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                info[key.strip()] = value.strip()
        
        return Package(
            name=info.get('Name', ''),
            version=info.get('Version', ''),
            description=info.get('Description', ''),
            status=status,
            source=PackageSource.OFFICIAL,
            size=self._parse_size(info.get('Download Size')),
            installed_size=self._parse_size(info.get('Installed Size')),
            dependencies=self._parse_list(info.get('Depends On')),
            provides=self._parse_list(info.get('Provides')),
            conflicts=self._parse_list(info.get('Conflicts With')),
            replaces=self._parse_list(info.get('Replaces')),
            groups=self._parse_list(info.get('Groups')),
            url=info.get('URL'),
            licenses=self._parse_list(info.get('Licenses')),
            architecture=info.get('Architecture'),
            build_date=info.get('Build Date'),
            install_date=info.get('Install Date'),
            packager=info.get('Packager')
        )
    
    def _parse_size(self, size_str: Optional[str]) -> Optional[int]:
        """Parse size string to bytes"""
        if not size_str or size_str == 'None':
            return None
        
        try:
            # Remove units and convert to bytes
            size_str = size_str.replace(',', '')
            if 'KiB' in size_str:
                return int(float(size_str.replace('KiB', '').strip()) * 1024)
            elif 'MiB' in size_str:
                return int(float(size_str.replace('MiB', '').strip()) * 1024 * 1024)
            elif 'GiB' in size_str:
                return int(float(size_str.replace('GiB', '').strip()) * 1024 * 1024 * 1024)
            else:
                return int(float(size_str.split()[0]))
        except (ValueError, IndexError):
            return None
    
    def _parse_list(self, list_str: Optional[str]) -> List[str]:
        """Parse space-separated list string"""
        if not list_str or list_str == 'None':
            return []
        return [item.strip() for item in list_str.split() if item.strip()]
    
    def _search_aur(self, query: str) -> List[Package]:
        """Search AUR packages using AUR helper"""
        try:
            aur_helper = self._find_aur_helper()
            if not aur_helper:
                logger.warning("No AUR helper found")
                return []
            
            cmd = [aur_helper, '-Ss', query]
            exit_code, stdout, stderr = self._run_command(cmd)
            
            if exit_code == 0:
                return self._parse_search_output(stdout, PackageSource.AUR)
            else:
                logger.warning(f"AUR search failed: {stderr}")
                return []
        
        except Exception as e:
            logger.error(f"AUR search failed: {e}")
            return []
    
    def _is_cache_valid(self) -> bool:
        """Check if package cache is still valid"""
        return (time.time() - self._cache_timestamp) < self.cache_timeout
    
    def _invalidate_cache(self):
        """Invalidate package cache"""
        self._package_cache.clear()
        self._cache_timestamp = 0
    
    def _find_aur_helper(self) -> Optional[str]:
        """Find available AUR helper"""
        aur_helpers = ['yay', 'paru', 'trizen', 'yaourt', 'aurman']
        
        for helper in aur_helpers:
            for path in [f'/usr/bin/{helper}', f'/usr/local/bin/{helper}', f'/bin/{helper}']:
                if os.path.exists(path):
                    logger.info(f"Found AUR helper: {helper}")
                    return path
        
        return None
    
    def install_aur_packages(self, package_names: List[str], no_confirm: bool = False) -> str:
        """Install AUR packages and return operation ID"""
        try:
            aur_helper = self._find_aur_helper()
            if not aur_helper:
                raise PackageManagerError(
                    "No AUR helper found",
                    "AUR_HELPER_NOT_FOUND"
                )
            
            operation_id = f"aur_install_{int(time.time())}"
            
            operation = PackageOperation(
                operation_id=operation_id,
                operation_type="aur_install",
                packages=package_names,
                status="running",
                started_at=time.time(),
                output=[]
            )
            
            self.operations[operation_id] = operation
            
            # Start AUR installation in background thread
            thread = threading.Thread(
                target=self._install_aur_packages_thread,
                args=(operation_id, package_names, no_confirm, aur_helper)
            )
            thread.daemon = True
            thread.start()
            
            logger.info(f"Started AUR package installation: {operation_id}")
            return operation_id
        
        except Exception as e:
            logger.error(f"Failed to start AUR package installation: {e}")
            raise PackageManagerError(
                f"AUR installation failed: {str(e)}",
                "AUR_INSTALL_FAILED"
            )
    
    def _install_aur_packages_thread(self, operation_id: str, package_names: List[str], 
                                    no_confirm: bool, aur_helper: str):
        """Install AUR packages in background thread"""
        try:
            operation = self.operations[operation_id]
            
            cmd = [aur_helper, '-S'] + package_names
            if no_confirm:
                cmd.append('--noconfirm')
            
            exit_code, stdout, stderr = self._run_command(cmd, timeout=3600)  # 1 hour for AUR builds
            
            operation.completed_at = time.time()
            operation.output = stdout.split('\\n') if stdout else []
            
            if exit_code == 0:
                operation.status = "completed"
                operation.progress = 100
                self._invalidate_cache()
                logger.info(f"AUR package installation completed: {operation_id}")
            else:
                operation.status = "failed"
                operation.error_message = stderr
                logger.error(f"AUR package installation failed: {operation_id}, {stderr}")
        
        except Exception as e:
            operation = self.operations.get(operation_id)
            if operation:
                operation.status = "failed"
                operation.error_message = str(e)
                operation.completed_at = time.time()
            logger.error(f"AUR package installation thread failed: {e}")
    
    def get_aur_package_info(self, package_name: str) -> Optional[Package]:
        """Get detailed information about an AUR package"""
        try:
            aur_helper = self._find_aur_helper()
            if not aur_helper:
                return None
            
            cmd = [aur_helper, '-Si', package_name]
            exit_code, stdout, stderr = self._run_command(cmd)
            
            if exit_code == 0:
                return self._parse_aur_package_info(stdout)
            
            return None
        
        except Exception as e:
            logger.error(f"Failed to get AUR package info for {package_name}: {e}")
            return None
    
    def _parse_aur_package_info(self, output: str) -> Package:
        """Parse AUR package information"""
        lines = output.strip().split('\\n')
        info = {}
        
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                info[key.strip()] = value.strip()
        
        return Package(
            name=info.get('Name', ''),
            version=info.get('Version', ''),
            description=info.get('Description', ''),
            status=PackageStatus.AVAILABLE,
            source=PackageSource.AUR,
            size=self._parse_size(info.get('Download Size')),
            installed_size=self._parse_size(info.get('Installed Size')),
            dependencies=self._parse_list(info.get('Depends On')),
            provides=self._parse_list(info.get('Provides')),
            conflicts=self._parse_list(info.get('Conflicts With')),
            replaces=self._parse_list(info.get('Replaces')),
            groups=self._parse_list(info.get('Groups')),
            url=info.get('URL'),
            licenses=self._parse_list(info.get('Licenses')),
            architecture=info.get('Architecture'),
            build_date=info.get('Build Date'),
            install_date=info.get('Install Date'),
            packager=info.get('Packager')
        )
    
    def upgrade_aur_packages(self, no_confirm: bool = False) -> str:
        """Upgrade AUR packages and return operation ID"""
        try:
            aur_helper = self._find_aur_helper()
            if not aur_helper:
                raise PackageManagerError(
                    "No AUR helper found",
                    "AUR_HELPER_NOT_FOUND"
                )
            
            operation_id = f"aur_upgrade_{int(time.time())}"
            
            operation = PackageOperation(
                operation_id=operation_id,
                operation_type="aur_upgrade",
                packages=["aur"],
                status="running",
                started_at=time.time(),
                output=[]
            )
            
            self.operations[operation_id] = operation
            
            # Start AUR upgrade in background thread
            thread = threading.Thread(
                target=self._upgrade_aur_packages_thread,
                args=(operation_id, no_confirm, aur_helper)
            )
            thread.daemon = True
            thread.start()
            
            logger.info(f"Started AUR package upgrade: {operation_id}")
            return operation_id
        
        except Exception as e:
            logger.error(f"Failed to start AUR package upgrade: {e}")
            raise PackageManagerError(
                f"AUR upgrade failed: {str(e)}",
                "AUR_UPGRADE_FAILED"
            )
    
    def _upgrade_aur_packages_thread(self, operation_id: str, no_confirm: bool, aur_helper: str):
        """Upgrade AUR packages in background thread"""
        try:
            operation = self.operations[operation_id]
            
            cmd = [aur_helper, '-Sua']
            if no_confirm:
                cmd.append('--noconfirm')
            
            exit_code, stdout, stderr = self._run_command(cmd, timeout=3600)  # 1 hour
            
            operation.completed_at = time.time()
            operation.output = stdout.split('\\n') if stdout else []
            
            if exit_code == 0:
                operation.status = "completed"
                operation.progress = 100
                self._invalidate_cache()
                logger.info(f"AUR package upgrade completed: {operation_id}")
            else:
                operation.status = "failed"
                operation.error_message = stderr
                logger.error(f"AUR package upgrade failed: {operation_id}, {stderr}")
        
        except Exception as e:
            operation = self.operations.get(operation_id)
            if operation:
                operation.status = "failed"
                operation.error_message = str(e)
                operation.completed_at = time.time()
            logger.error(f"AUR package upgrade thread failed: {e}")
    
    def list_aur_updates(self) -> List[Package]:
        """List available AUR package updates"""
        try:
            aur_helper = self._find_aur_helper()
            if not aur_helper:
                return []
            
            cmd = [aur_helper, '-Qua']
            exit_code, stdout, stderr = self._run_command(cmd)
            
            packages = []
            if exit_code == 0 and stdout.strip():
                for line in stdout.strip().split('\\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 4:  # name current -> new
                            name = parts[0]
                            current_version = parts[1]
                            new_version = parts[3]
                            
                            package = Package(
                                name=name,
                                version=f"{current_version} -> {new_version}",
                                description="",
                                status=PackageStatus.UPGRADABLE,
                                source=PackageSource.AUR
                            )
                            packages.append(package)
            
            logger.info(f"Found {len(packages)} AUR packages with updates")
            return packages
        
        except Exception as e:
            logger.error(f"Failed to list AUR updates: {e}")
            return []


class ComprehensivePackageManager:
    """Comprehensive package manager combining pacman and AUR functionality"""
    
    def __init__(self):
        self.pacman = PacmanManager()
        self.has_aur_helper = self.pacman._find_aur_helper() is not None
        logger.info(f"Comprehensive package manager initialized (AUR: {self.has_aur_helper})")
    
    def search_packages(self, query: str, include_aur: bool = True) -> List[Package]:
        """Search packages in both official repos and AUR"""
        return self.pacman.search_packages(query, include_aur and self.has_aur_helper)
    
    def get_package_info(self, package_name: str, check_aur: bool = True) -> Optional[Package]:
        """Get package info from official repos or AUR"""
        # Try official repos first
        package = self.pacman.get_package_info(package_name)
        if package:
            return package
        
        # Try AUR if enabled
        if check_aur and self.has_aur_helper:
            return self.pacman.get_aur_package_info(package_name)
        
        return None
    
    def list_installed_packages(self) -> List[Package]:
        """List all installed packages"""
        return self.pacman.list_installed_packages()
    
    def list_upgradable_packages(self, include_aur: bool = True) -> List[Package]:
        """List all upgradable packages from official repos and AUR"""
        packages = self.pacman.list_upgradable_packages()
        
        if include_aur and self.has_aur_helper:
            aur_packages = self.pacman.list_aur_updates()
            packages.extend(aur_packages)
        
        return packages
    
    def install_packages(self, package_names: List[str], from_aur: bool = False, 
                        no_confirm: bool = False) -> str:
        """Install packages from official repos or AUR"""
        if from_aur and self.has_aur_helper:
            return self.pacman.install_aur_packages(package_names, no_confirm)
        else:
            return self.pacman.install_packages(package_names, no_confirm)
    
    def remove_packages(self, package_names: List[str], no_confirm: bool = False, 
                       cascade: bool = False) -> str:
        """Remove packages"""
        return self.pacman.remove_packages(package_names, no_confirm, cascade)
    
    def upgrade_system(self, include_aur: bool = True, no_confirm: bool = False) -> Dict[str, str]:
        """Upgrade system packages and optionally AUR packages"""
        operations = {}
        
        # Upgrade official packages
        operations['official'] = self.pacman.upgrade_system(no_confirm)
        
        # Upgrade AUR packages if requested
        if include_aur and self.has_aur_helper:
            operations['aur'] = self.pacman.upgrade_aur_packages(no_confirm)
        
        return operations
    
    def refresh_database(self) -> bool:
        """Refresh package database"""
        return self.pacman.refresh_database()
    
    def get_operation_status(self, operation_id: str) -> Optional[PackageOperation]:
        """Get status of a package operation"""
        return self.pacman.get_operation_status(operation_id)
    
    def get_package_stats(self) -> Dict[str, Any]:
        """Get package statistics"""
        try:
            installed = self.list_installed_packages()
            upgradable = self.list_upgradable_packages()
            
            official_upgradable = [p for p in upgradable if p.source == PackageSource.OFFICIAL]
            aur_upgradable = [p for p in upgradable if p.source == PackageSource.AUR]
            
            return {
                'total_installed': len(installed),
                'total_upgradable': len(upgradable),
                'official_upgradable': len(official_upgradable),
                'aur_upgradable': len(aur_upgradable),
                'has_aur_helper': self.has_aur_helper,
                'aur_helper': self.pacman._find_aur_helper()
            }
        
        except Exception as e:
            logger.error(f"Failed to get package stats: {e}")
            return {}


# Global package manager instance
_package_manager = None


def get_package_manager() -> ComprehensivePackageManager:
    """Get global comprehensive package manager instance"""
    global _package_manager
    if _package_manager is None:
        _package_manager = ComprehensivePackageManager()
    return _package_manager