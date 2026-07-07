import os
import sys
import time
import subprocess
import socket
import unittest

def get_free_port():
    s = socket.socket()
    s.bind(('', 0))
    port = s.getsockname()[1]
    s.close()
    return port

class VulnScanProE2ETest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = get_free_port()
        cls.server_url = f"http://127.0.0.1:{cls.port}"
        
        # Start server in background
        # Use memory database for tests to prevent modifying user's database
        cls.env = os.environ.copy()
        cls.env['TESTING'] = '1'
        cls.env['DATABASE_URL'] = 'sqlite:///:memory:'
        cls.env['CORS_ORIGINS'] = f"http://127.0.0.1:{cls.port},http://localhost:{cls.port}"
        
        print(f"Starting test server on port {cls.port}...")
        
        # Determine Python executable (prefer venv)
        py_exe = sys.executable
        venv_py = os.path.join("venv", "Scripts", "python.exe")
        if os.path.exists(venv_py):
            py_exe = venv_py
        else:
            venv_py_unix = os.path.join("venv", "bin", "python")
            if os.path.exists(venv_py_unix):
                py_exe = venv_py_unix
        
        # Start Flask app using python and passing port variable overrides
        # Also run it with custom port env variable so the server starts on cls.port
        cls.env['PORT'] = str(cls.port)
        cls.server_proc = subprocess.Popen(
            [py_exe, "backend_app.py"],
            env=cls.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Wait for port to open
        opened = False
        for _ in range(30):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    s.connect(('127.0.0.1', cls.port))
                    opened = True
                    break
            except Exception:
                time.sleep(0.5)
                
        if not opened:
            cls.server_proc.terminate()
            raise RuntimeError("Test server failed to start within timeout.")
        print("Test server is up!")

    @classmethod
    def tearDownClass(cls):
        print("Terminating test server...")
        cls.server_proc.terminate()
        cls.server_proc.wait()

    def test_smoke_flow(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.skipTest("playwright library not installed. Install via pip install playwright && playwright install")

        with sync_playwright() as p:
            print("Launching browser...")
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            
            print(f"Navigating to {self.server_url}...")
            page.goto(self.server_url)
            
            # 1. Verify page title
            self.assertIn("VulnScan Pro", page.title())
            print("Title check: PASS")
            
            # 2. Register a new user
            page.click("text=Register")
            page.fill("#ru-name", "Smoke Test User")
            page.fill("#ru-email", "smoke@test.local")
            page.fill("#ru", "smokeuser")
            page.fill("#rp", "SmokeSecure123")
            page.fill("#rp2", "SmokeSecure123")
            
            # Intercept verification mock check
            page.click("#register-form button")
            time.sleep(1)
            
            # 3. Sign in as admin with default creds (triggering forced password change)
            page.click("text=Sign In")
            page.fill("#lu", "admin")
            page.fill("#lp", "admin123")
            page.click("#login-form button")
            
            # Check for password change modal
            page.wait_for_selector("#force-pw-modal", state="visible")
            print("Forced password change modal: DETECTED")
            
            # Fill out new password details
            page.fill("#fpc-cur", "admin123")
            page.fill("#fpc-new", "AdminSecure2026")
            page.fill("#fpc-conf", "AdminSecure2026")
            page.click("#fpc-btn")
            
            # Wait for redirect to dashboard
            page.wait_for_selector("#app", state="visible")
            print("Forced password change completed: SUCCESS")
            
            # 4. Verify dashboard loads
            self.assertTrue(page.is_visible("#page-dashboard"))
            print("Dashboard view loaded: PASS")
            
            # 5. Navigate to Projects tab
            page.click("#si-projects")
            self.assertTrue(page.is_visible("#page-projects"))
            print("Projects page navigation: PASS")
            
            # 6. Navigate to Scanner tab
            page.click("#si-scanner")
            self.assertTrue(page.is_visible("#page-scanner"))
            print("Scanner page navigation: PASS")
            
            browser.close()
            print("Smoke test flow finished successfully!")

if __name__ == '__main__':
    unittest.main()
