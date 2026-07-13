"""Configuration management for FWSpoof."""

from dataclasses import dataclass, field
from typing import List, Optional, Set
import os
import yaml


# Valid connection types for iptables
VALID_CONNECTION_TYPES: Set[str] = {"INPUT", "FORWARD", "OUTPUT"}


class ConfigValidationError(Exception):
    """Raised when configuration validation fails."""
    pass


@dataclass
class Config:
    """
    Configuration settings for FWSpoof.
    
    Attributes:
        max_flag_count: Global threshold for SYN/SYN+RESET attacks
        max_flag_count_per_cidr: Per-range (/24) SYN threshold
        max_flag_count_per_cidr_sr: Per-range SYN+RESET threshold
        connection_type: iptables chain (INPUT, FORWARD, or OUTPUT)
        dont_unblock: If True, blocked IPs stay blocked permanently
        test_mode: If True, don't execute iptables commands
        specific_ip: If True, block specific IPs instead of /24 ranges
        verbose: Enable debug output
        show_stats: Show statistics summary at exit
        flags: Comma-separated TCP flags to monitor
        allowed_ips: List of whitelisted IPs (loaded from file)
    """
    
    # Attack thresholds
    max_flag_count: int = 20
    max_flag_count_per_cidr: int = 3
    max_flag_count_per_cidr_sr: int = 5
    
    # Connection settings
    connection_type: str = "FORWARD"
    
    # Behavior flags
    dont_unblock: bool = False
    test_mode: bool = False
    specific_ip: bool = False
    verbose: bool = False
    show_stats: bool = False
    
    # Monitoring flags
    flags: str = "[S],[R]"
    
    # Allowed IPs (loaded from file)
    allowed_ips: List[str] = field(default_factory=list)
    
    # Environment variable prefix
    ENV_PREFIX: str = "FWSPOOF_"
    
    @property
    def flag_list(self) -> List[str]:
        """Parse flags string into list."""
        return [f.strip() for f in self.flags.split(",") if f.strip()]
    
    def validate(self) -> None:
        """
        Validate all configuration settings.
        
        Raises:
            ConfigValidationError: If any setting is invalid.
        """
        errors = []
        
        # Validate thresholds are positive
        if self.max_flag_count <= 0:
            errors.append(f"max_flag_count must be positive, got {self.max_flag_count}")
        if self.max_flag_count_per_cidr <= 0:
            errors.append(f"max_flag_count_per_cidr must be positive, got {self.max_flag_count_per_cidr}")
        if self.max_flag_count_per_cidr_sr <= 0:
            errors.append(f"max_flag_count_per_cidr_sr must be positive, got {self.max_flag_count_per_cidr_sr}")
        
        # Validate connection type
        if self.connection_type not in VALID_CONNECTION_TYPES:
            errors.append(
                f"Invalid connection_type '{self.connection_type}'. "
                f"Must be one of: {', '.join(sorted(VALID_CONNECTION_TYPES))}"
            )
        
        # Validate flags are not empty
        if not self.flag_list:
            errors.append("flags cannot be empty")
        
        # Validate per-cidr thresholds don't exceed global
        if self.max_flag_count_per_cidr > self.max_flag_count:
            errors.append(
                f"max_flag_count_per_cidr ({self.max_flag_count_per_cidr}) "
                f"cannot exceed max_flag_count ({self.max_flag_count})"
            )
        if self.max_flag_count_per_cidr_sr > self.max_flag_count:
            errors.append(
                f"max_flag_count_per_cidr_sr ({self.max_flag_count_per_cidr_sr}) "
                f"cannot exceed max_flag_count ({self.max_flag_count})"
            )
        
        if errors:
            raise ConfigValidationError("\n".join(errors))
    
    @classmethod
    def _get_env_name(cls, field_name: str) -> str:
        """Convert field name to environment variable name."""
        return f"{cls.ENV_PREFIX}{field_name.upper()}"
    
    @classmethod
    def from_environment(cls) -> "Config":
        """
        Load configuration from environment variables.
        
        Environment variables should be prefixed with FWSPOOF_.
        Example: FWSPOOF_MAX_FLAG_COUNT=50
        
        Boolean values: true, yes, 1 -> True; false, no, 0 -> False
        
        Returns:
            Config instance with values from environment.
        """
        config = cls()
        
        # Map of field names to their types
        bool_fields = {'dont_unblock', 'test_mode', 'specific_ip', 'verbose', 'show_stats'}
        int_fields = {'max_flag_count', 'max_flag_count_per_cidr', 'max_flag_count_per_cidr_sr'}
        str_fields = {'connection_type', 'flags'}
        
        for field_name in cls.__dataclass_fields__:
            if field_name in ('allowed_ips', 'ENV_PREFIX'):
                continue
                
            env_name = cls._get_env_name(field_name)
            env_value = os.environ.get(env_name)
            
            if env_value is None:
                continue
            
            # Parse based on field type
            if field_name in bool_fields:
                setattr(config, field_name, env_value.lower() in ('true', 'yes', '1'))
            elif field_name in int_fields:
                try:
                    setattr(config, field_name, int(env_value))
                except ValueError:
                    raise ConfigValidationError(
                        f"Environment variable {env_name} must be an integer, got '{env_value}'"
                    )
            elif field_name in str_fields:
                setattr(config, field_name, env_value)
        
        return config
    
    @classmethod
    def from_yaml(cls, filepath: str) -> "Config":
        """
        Load configuration from YAML file.
        
        Args:
            filepath: Path to YAML configuration file.
            
        Returns:
            Config instance with values from file, or defaults if file doesn't exist.
        """
        if not os.path.exists(filepath):
            return cls()
        
        try:
            with open(filepath, 'r') as f:
                data = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ConfigValidationError(f"Failed to parse YAML file {filepath}: {e}")
        
        # Filter only valid Config fields
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        valid_fields.discard('ENV_PREFIX')  # Class variable, not instance field
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        
        return cls(**filtered_data)
    
    @classmethod
    def load(cls, yaml_path: Optional[str] = None, use_env: bool = True) -> "Config":
        """
        Load configuration from multiple sources with precedence:
        1. Environment variables (highest priority)
        2. YAML file
        3. Default values (lowest priority)
        
        Args:
            yaml_path: Path to YAML config file, or None to skip.
            use_env: Whether to load from environment variables.
            
        Returns:
            Config instance with merged values.
        """
        # Start with defaults
        config = cls()
        
        # Load from YAML if provided
        if yaml_path and os.path.exists(yaml_path):
            yaml_config = cls.from_yaml(yaml_path)
            for field_name in cls.__dataclass_fields__:
                if field_name in ('allowed_ips', 'ENV_PREFIX'):
                    continue
                value = getattr(yaml_config, field_name)
                if value != getattr(cls(), field_name):  # Only override if different from default
                    setattr(config, field_name, value)
        
        # Environment variables override everything
        if use_env:
            env_config = cls.from_environment()
            for field_name in cls.__dataclass_fields__:
                if field_name in ('allowed_ips', 'ENV_PREFIX'):
                    continue
                env_value = getattr(env_config, field_name)
                yaml_value = getattr(config, field_name)
                default_value = getattr(cls(), field_name)
                
                # Only apply env var if it's different from default
                if env_value != default_value:
                    setattr(config, field_name, env_value)
        
        return config
    
    def load_allowed_ips(self, filepath: str = "allowed.ips") -> int:
        """
        Load allowed IPs from file.
        
        Args:
            filepath: Path to allowed IPs file.
            
        Returns:
            Number of IPs loaded.
        """
        self.allowed_ips = []
        
        if not os.path.exists(filepath):
            return 0
        
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.allowed_ips.append(line)
        except IOError as e:
            if self.verbose:
                print(f"Warning: Could not read {filepath}: {e}", file=os.sys.stderr)
        
        return len(self.allowed_ips)
    
    def to_dict(self) -> dict:
        """Convert configuration to dictionary."""
        return {
            'max_flag_count': self.max_flag_count,
            'max_flag_count_per_cidr': self.max_flag_count_per_cidr,
            'max_flag_count_per_cidr_sr': self.max_flag_count_per_cidr_sr,
            'connection_type': self.connection_type,
            'dont_unblock': self.dont_unblock,
            'test_mode': self.test_mode,
            'specific_ip': self.specific_ip,
            'verbose': self.verbose,
            'show_stats': self.show_stats,
            'flags': self.flags,
            'allowed_ips_count': len(self.allowed_ips),
        }
    
    def __str__(self) -> str:
        """String representation of configuration."""
        lines = ["FWSpoof Configuration:"]
        for key, value in self.to_dict().items():
            lines.append(f"  {key}: {value}")
        return "\n".join(lines)


# Global config instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get or create global config instance."""
    global _config
    if _config is None:
        _config = Config()
    return _config


def set_config(config: Config) -> None:
    """Set global config instance."""
    global _config
    _config = config


def init_config(yaml_path: Optional[str] = None, use_env: bool = True) -> Config:
    """
    Initialize global configuration.
    
    Args:
        yaml_path: Path to YAML config file.
        use_env: Whether to load from environment variables.
        
    Returns:
        Config instance.
    """
    config = Config.load(yaml_path, use_env)
    config.validate()
    set_config(config)
    return config
