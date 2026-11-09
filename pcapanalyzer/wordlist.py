"""Generate bounded, targeted wordlists for authorized password audits."""

from itertools import permutations, product

MAX_WORDS = 20
MAX_WORD_LENGTH = 100
MAX_CANDIDATES = 50000
MAX_COMPONENTS = 4
CASE_RULES = {"original", "lower", "capitalized", "upper"}
SEPARATORS = {"", "_", "-", "."}
SUFFIXES = {"", "!", "123"}


def _choices(value, allowed, label, required=True):
    if not isinstance(value, list) or any(not isinstance(item, str) or item not in allowed for item in value):
        raise ValueError(f"Invalid {label}")
    choices = list(dict.fromkeys(value))
    if required and not choices:
        raise ValueError(f"Select at least one {label}")
    return choices


def generate_wordlist(words, year, cases, separators, suffixes, short_year=False, max_components=3):
    """Return unique, sorted combinations of up to max_components distinct inputs."""
    if not isinstance(words, list) or len(words) > MAX_WORDS:
        raise ValueError(f"Enter at most {MAX_WORDS} words")
    cleaned = []
    for word in words:
        if not isinstance(word, str) or len(word) > MAX_WORD_LENGTH:
            raise ValueError(f"Each word must be text of at most {MAX_WORD_LENGTH} characters")
        word = word.strip()
        if any(char in word for char in "\r\n\x00"):
            raise ValueError("Words cannot contain line breaks or null characters")
        if word and word not in cleaned:
            cleaned.append(word)
    if not isinstance(year, str) or (year and (len(year) != 4 or not year.isascii() or not year.isdigit())):
        raise ValueError("Birth year must be four digits")
    if not isinstance(short_year, bool):
        raise ValueError("Invalid short-year option")
    if type(max_components) is not int or not 1 <= max_components <= MAX_COMPONENTS:
        raise ValueError(f"Maximum components must be between 1 and {MAX_COMPONENTS}")
    cases = _choices(cases, CASE_RULES, "capitalization rule")
    separators = _choices(separators, SEPARATORS, "separator")
    suffixes = _choices(suffixes, SUFFIXES, "suffix")
    if year:
        for value in (year, year[-2:] if short_year else year):
            if value not in cleaned:
                cleaned.append(value)
    if not cleaned:
        raise ValueError("Enter at least one word or birth year")

    def variants(word):
        rules = {
            "original": word,
            "lower": word.lower(),
            "capitalized": word[:1].upper() + word[1:].lower(),
            "upper": word.upper(),
        }
        return list(dict.fromkeys(rules[rule] for rule in cases))

    parts = [variants(word) for word in cleaned]
    candidates = set()

    def add(candidate):
        candidates.add(candidate)
        if len(candidates) > MAX_CANDIDATES:
            raise ValueError(f"Wordlist exceeds {MAX_CANDIDATES:,} entries; reduce the inputs or options")

    for count in range(1, min(max_components, len(parts)) + 1):
        for indices in permutations(range(len(parts)), count):
            for components in product(*(parts[index] for index in indices)):
                for joins in product(separators, repeat=count - 1):
                    combined = components[0] + "".join(
                        separator + component for separator, component in zip(joins, components[1:])
                    )
                    for suffix in suffixes:
                        add(combined + suffix)
    return sorted(candidates)
