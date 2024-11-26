from typing import List, Dict, Optional, Union, Tuple
import re
import json
from datetime import datetime
from pathlib import Path
import hashlib
from enum import Enum
from dataclasses import dataclass
import logging
from logging.handlers import RotatingFileHandler
import concurrent.futures
from functools import lru_cache

class PHICategory(Enum):
    """Enumeration of Protected Health Information (PHI) categories according to HIPAA."""
    NAME = "NAME"
    MRN = "MEDICAL_RECORD_NUMBER"
    SSN = "SOCIAL_SECURITY_NUMBER"
    EMAIL = "EMAIL"
    PHONE = "PHONE_NUMBER"
    DATE = "DATE"
    ADDRESS = "ADDRESS"
    PROVIDER = "PROVIDER_NAME"
    FACILITY = "FACILITY_NAME"
    DEVICE_ID = "DEVICE_IDENTIFIER"
    IP_ADDRESS = "IP_ADDRESS"
    URL = "URL"
    ACCOUNT = "ACCOUNT_NUMBER"

@dataclass
class DeidentificationPattern:
    """Dataclass to hold pattern information and metadata."""
    category: PHICategory
    pattern: str
    replacement: str
    description: str
    sensitivity: int  # 1-5 scale of sensitivity
    validation_func: Optional[callable] = None

class DeidentificationError(Exception):
    """Base exception class for deidentification errors."""
    pass

class ValidationError(DeidentificationError):
    """Raised when input validation fails."""
    pass

class PatternError(DeidentificationError):
    """Raised when there's an issue with regex patterns."""
    pass

class Deidentifier:
    """
    Production-grade medical data de-identification system.
    
    Features:
    - HIPAA compliance-focused patterns
    - Configurable replacement strategies
    - Input validation
    - Comprehensive logging
    - Performance optimization
    - Error handling
    - Audit trail
    """

    DEFAULT_PATTERNS = {
        PHICategory.NAME: r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}\b",
        PHICategory.SSN: r"\b\d{3}-?\d{2}-?\d{4}\b",
        PHICategory.MRN: r"\b(?:MRN|Medical Record Number)?:?\s*\d{6,10}\b",
        PHICategory.EMAIL: r"\b[\w\.-]+@[\w\.-]+\.\w+\b",
        PHICategory.PHONE: r"\b(?:\+\d{1,2}\s?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        PHICategory.DATE: r"\b(?:\d{1,2}[-/]\d{1,2}[-/]\d{2,4})|(?:(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4})\b",
        PHICategory.ADDRESS: r"\b\d{1,5}\s+[\w\s,]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr)\.?\s*,?\s*(?:[A-Za-z]+\s*,)?\s*[A-Z]{2}\s*\d{5}(?:-\d{4})?\b",
        PHICategory.PROVIDER: r"(?:Dr\.|Doctor|Provider)\s*[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}",
        PHICategory.DEVICE_ID: r"\b(?:Device|Serial)\s*(?:ID|Number)?:?\s*[\w\-]{6,}\b",
        PHICategory.IP_ADDRESS: r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        PHICategory.URL: r"https?://(?:[\w-]\.)+[\w-]+(?:/[\w-./?%&=]*)?",
        PHICategory.ACCOUNT: r"\b(?:Acct|Account)\s*(?:#|Number)?:?\s*\d{6,12}\b"
    }

    def __init__(self, 
                 config_path: Optional[Path] = None,
                 log_path: Optional[Path] = None,
                 replacement_strategy: str = "hash",
                 max_threads: int = 4) -> None:
        """
        Initialize the Deidentifier with configuration and logging setup.
        
        Args:
            config_path: Path to configuration file
            log_path: Path to log directory
            replacement_strategy: Strategy for replacing PHI ('hash', 'fixed', 'random')
            max_threads: Maximum number of threads for parallel processing
        """
        self.patterns: Dict[PHICategory, DeidentificationPattern] = {}
        self.replacement_strategy = replacement_strategy
        self.max_threads = max_threads
        self._setup_logging(log_path)
        self._load_configuration(config_path)
        self._compile_patterns()
        self.audit_trail = []

    def _setup_logging(self, log_path: Optional[Path]) -> None:
        """Configure rotating file and console logging."""
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # File handler with rotation
        if log_path:
            file_handler = RotatingFileHandler(
                log_path / 'deidentification.log',
                maxBytes=10485760,  # 10MB
                backupCount=5
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def _load_configuration(self, config_path: Optional[Path]) -> None:
        """Load patterns and configuration from file or use defaults."""
        if config_path and config_path.exists():
            with open(config_path) as f:
                config = json.load(f)
            self._validate_configuration(config)
            self.patterns = self._create_patterns_from_config(config)
        else:
            self.patterns = self._create_default_patterns()

    def _validate_configuration(self, config: Dict) -> None:
        """Validate configuration file structure and content."""
        required_keys = {'patterns', 'replacement_strategy'}
        if not all(key in config for key in required_keys):
            raise ValidationError(f"Configuration missing required keys: {required_keys}")

    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for performance."""
        self._compiled_patterns = {
            category: re.compile(pattern.pattern, re.IGNORECASE)
            for category, pattern in self.patterns.items()
        }

    @lru_cache(maxsize=1000)
    def _generate_replacement(self, text: str, category: PHICategory) -> str:
        """Generate replacement text based on strategy and category."""
        if self.replacement_strategy == "hash":
            return hashlib.sha256(text.encode()).hexdigest()[:8]
        elif self.replacement_strategy == "fixed":
            return f"[{category.value}]"
        else:  # random
            return f"[{category.value}_{hash(text) % 1000:03d}]"

    def deidentify(self, text: Union[str, List[str]]) -> Union[str, List[str]]:
        """
        De-identify text containing PHI.
        
        Args:
            text: Input text or list of texts to de-identify
            
        Returns:
            De-identified text or list of texts
            
        Raises:
            ValidationError: If input validation fails
            DeidentificationError: If processing fails
        """
        start_time = datetime.now()
        self.logger.info(f"Starting de-identification process at {start_time}")

        try:
            # Input validation
            if not text:
                raise ValidationError("Empty input provided")

            # Handle single string or list of strings
            if isinstance(text, str):
                result = self._process_single_text(text)
            else:
                result = self._process_multiple_texts(text)

            # Log completion
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            self.logger.info(f"De-identification completed in {duration:.2f} seconds")
            
            # Record audit trail
            self._record_audit(start_time, end_time, len(text) if isinstance(text, list) else 1)
            
            return result

        except Exception as e:
            self.logger.error(f"De-identification failed: {str(e)}")
            raise DeidentificationError(f"De-identification failed: {str(e)}")

    def _process_single_text(self, text: str) -> str:
        """Process a single text string."""
        for category, pattern in self._compiled_patterns.items():
            text = pattern.sub(
                lambda m: self._generate_replacement(m.group(), category),
                text
            )
        return text

    def _process_multiple_texts(self, texts: List[str]) -> List[str]:
        """Process multiple texts in parallel."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            return list(executor.map(self._process_single_text, texts))

    def _record_audit(self, start_time: datetime, end_time: datetime, 
                     num_records: int) -> None:
        """Record audit information for compliance purposes."""
        audit_entry = {
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'num_records': num_records,
            'patterns_used': len(self._compiled_patterns),
            'replacement_strategy': self.replacement_strategy
        }
        self.audit_trail.append(audit_entry)

    def export_audit_trail(self, output_path: Path) -> None:
        """Export audit trail to JSON file."""
        with open(output_path, 'w') as f:
            json.dump(self.audit_trail, f, indent=2)

    @classmethod
    def validate_patterns(cls, patterns: Dict[PHICategory, DeidentificationPattern]) -> bool:
        """Validate pattern dictionary structure and content."""
        try:
            for category, pattern in patterns.items():
                if not isinstance(category, PHICategory):
                    raise ValidationError(f"Invalid category: {category}")
                re.compile(pattern.pattern)  # Validate regex pattern
            return True
        except Exception as e:
            raise ValidationError(f"Pattern validation failed: {str(e)}")

if __name__ == "__main__":
    # Example usage with error handling
    try:
        deidentifier = Deidentifier(
            log_path=Path("./logs"),
            replacement_strategy="hash"
        )
        
        sample_text = """
        Patient Name: John Smith
        DOB: 01/15/1980
        SSN: 123-45-6789
        MRN: 12345678
        Provider: Dr. Jane Wilson
        Email: john.smith@email.com
        Phone: (555) 123-4567
        Address: 123 Main Street, Anytown, NY 12345
        """
        
        deidentified_text = deidentifier.deidentify(sample_text)
        print("\nDe-identified text:")
        print(deidentified_text)
        
        # Export audit trail
        deidentifier.export_audit_trail(Path("./audit_trail.json"))
        
    except DeidentificationError as e:
        print(f"De-identification error: {str(e)}")
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
