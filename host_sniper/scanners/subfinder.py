"""
Subdomain enumeration module
"""
from concurrent.futures import ThreadPoolExecutor, as_completed


class SubFinderBase:
    """Base subdomain finder"""
    
    def __init__(self):
        self.completed = 0
        self.results = {}

    def _fetch_from_source(self, source, domain):
        """Fetch subdomains from a single source"""
        try:
            found = source.fetch(domain) if hasattr(source, 'fetch') else set()
            return self.filter_valid_subdomains(found, domain)
        except Exception:
            return set()

    @staticmethod
    def filter_valid_subdomains(subdomains, domain):
        """Filter and validate subdomains"""
        valid = set()
        for subdomain in subdomains:
            if isinstance(subdomain, str) and domain in subdomain:
                valid.add(subdomain)
        return valid

    @staticmethod
    def is_valid_domain(domain):
        """Check if domain is valid"""
        if not domain or len(domain) > 253:
            return False
        allowed = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-')
        return all(c in allowed for c in domain)

    @staticmethod
    def save_subdomains(subdomains, output_file):
        """Save subdomains to file"""
        if subdomains:
            with open(output_file, "a", encoding="utf-8") as f:
                f.write("\n".join(sorted(subdomains)) + "\n")

    def process_domain(self, domain, output_file, sources=None):
        """Process a single domain"""
        if not self.is_valid_domain(domain):
            self.completed += 1
            return set()

        if sources is None:
            sources = []

        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [
                executor.submit(self._fetch_from_source, source, domain)
                for source in sources
            ]
            results = [f.result() for f in as_completed(futures)]

        subdomains = set().union(*results) if results else set()
        self.save_subdomains(subdomains, output_file)
        self.completed += 1

        return subdomains

    def process_domains(self, domains, output_file, sources=None):
        """Process multiple domains"""
        all_subdomains = set()
        for domain in domains:
            subdomains = self.process_domain(domain, output_file, sources)
            all_subdomains.update(subdomains)
        
        return all_subdomains
