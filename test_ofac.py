
import unittest
import shutil
from pathlib import Path
from ofac import screen_company, update_snapshot, DEFAULT_CACHE_DIR

class TestSanctionsScreening(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Ensure we have a fresh snapshot for testing.
        We'll use the current directory's .sanctions folder if it exists,
        or trigger an update if not.
        """
        cls.cache_dir = Path(".sanctions")
        if not (cls.cache_dir / "LATEST").exists():
            print("Downloading lists for testing...")
            update_snapshot(cls.cache_dir, verify_ssl=False)
        
        cls.snapshot_id = (cls.cache_dir / "LATEST").read_text().strip()
        print(f"Testing against snapshot: {cls.snapshot_id}")

    def assertMatchFound(self, query, source_code, min_score=95.0):
        """
        Helper to assert that a query returns a match from a specific source
        with at least the given score.
        """
        _, hits, _ = screen_company(
            query, 
            cache_dir=self.cache_dir, 
            snapshot_id=self.snapshot_id, 
            top_k=20, 
            review_threshold=10.0, 
            block_threshold=90.0
        )
        
        found = False
        best_hit_score = 0.0
        found_sources = []
        for h in hits:
            found_sources.append(f"{h.source_list}: {h.best_score:.1f}")
            # Check if source starts with the code (e.g. "OFAC-SDN" starts with "OFAC")
            if h.source_list.startswith(source_code):
                best_hit_score = max(best_hit_score, h.best_score)
                if h.best_score >= min_score:
                    found = True
                    break
        
        if not found:
            print(f"\nDEBUG: Hits for '{query}': {found_sources}")
        
        self.assertTrue(found, f"Expected match for '{query}' in '{source_code}' with score >={min_score}, but best was {best_hit_score}")

    def test_ofac_match(self):
        # Known OFAC SDN entity
        self.assertMatchFound("Aerospace Industries Organization", "OFAC")

    def test_bis_match(self):
        # Known BIS Entity List entity
        # Note: BIS names can be tricky, picking a distinctive one
        self.assertMatchFound("Huawei Technologies Co., Ltd", "BIS")

    def test_un_match(self):
        # Known UN entity (Al-Qaida Sanctions List)
        self.assertMatchFound("Ayman al-Zawahiri", "UN", min_score=90.0)

    def test_eu_match(self):
        # Known EU entity
        self.assertMatchFound("Iran Air", "EU")

    def test_uk_match(self):
        # Known UK entity
        self.assertMatchFound("Iran Air", "UK")

    def test_canada_match(self):
        # Canada SEMA list
        # "Vladimir Vladimirovich Putin" is likely there
        self.assertMatchFound("Vladimir Vladimirovich Putin", "CA")

    def test_australia_match(self):
        # Australia DFAT list
        self.assertMatchFound("RAAD IRAN", "AU")

    def test_switzerland_match(self):
        # Switzerland SECO list
        self.assertMatchFound("Igor Rotenberg", "CH", min_score=60.0)

    def test_worldbank_match(self):
        # World Bank Debarred list
        # "SNC-Lavalin" is a classic historical one, but let's pick a current one.
        # "Asia Construction" was in the previous output.
        self.assertMatchFound("Asia Construction", "WB", min_score=50.0)

if __name__ == '__main__':
    unittest.main()
