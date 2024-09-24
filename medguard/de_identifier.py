from typing import List
import re
from loguru import logger


class Deidentifier:
    """
    A class to de-identify sensitive information in text data.

    This class scans text for sensitive information such as names,
    Social Security numbers, email addresses, phone numbers, dates, and credit card numbers,
    and replaces them with placeholders.
    """

    def __init__(self, patterns: List[str] = None) -> None:
        """
        Initialize Deidentifier with regex patterns to identify sensitive data.

        :param patterns: A list of regex patterns to identify sensitive data.
        """
        if patterns is None:
            patterns = [
                r"\b\d{3}-\d{2}-\d{4}\b",  # SSN pattern
                r"\b[A-Z][a-z]*\s[A-Z][a-z]*\b",  # Names pattern (simple)
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",  # Email pattern
                r"\b\d{3}-\d{3}-\d{4}\b",  # Phone number pattern
                r"\b\d{1,2}/\d{1,2}/\d{2,4}\b",  # Date pattern (MM/DD/YYYY or MM/DD/YY)
                r"\b\d{4}-\d{4}-\d{4}-\d{4}\b",  # Credit card number pattern
                r"\b\d{3}-\d{4}-\d{4}-\d{4}\b",  # Credit card number pattern with dashes
                r"\b\d{16}\b",  # Credit card number pattern without dashes
            ]
        self.patterns = patterns

    def deidentify(self, text: str) -> str:
        """
        De-identify sensitive data in a given text string.

        :param text: The input text potentially containing sensitive data.
        :return: Text with sensitive data replaced by placeholders.
        """
        logger.info("De-identifying sensitive data from input text.")
        # Combine all patterns into a single regex pattern for faster processing
        combined_pattern = "|".join(self.patterns)
        text = re.sub(combined_pattern, "[REDACTED]", text)
        return text


import time

# Example usage
if __name__ == "__main__":
    deid = Deidentifier()
    sample_text = "John Doe's SSN is 123-45-6789 and his email is john.doe@example.com."
    start_time = time.time()
    clean_text = deid.deidentify(sample_text)
    end_time = time.time()
    print(
        f"Deidentification completed in {end_time - start_time} seconds."
    )
    print(clean_text)
