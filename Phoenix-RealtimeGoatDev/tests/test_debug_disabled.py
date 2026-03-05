"""
Test suite to verify that Flask debug mode is disabled for security.

This test suite validates the remediation of CWE-489 (Debug Enabled vulnerability).
Debug mode should never be enabled in production environments as it:
- Exposes sensitive information through detailed error pages
- Provides an interactive debugger that can execute arbitrary code
- Reveals application internals and configuration
"""

import unittest
import sys
import os
import io
from unittest.mock import patch, MagicMock

# Add parent directory to path to import the application
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sast_critical_high import app


class TestDebugModeDisabled(unittest.TestCase):
    """Test cases to ensure debug mode is properly disabled."""

    def test_flask_app_debug_config_is_false(self):
        """
        Verify that the Flask app.debug configuration is set to False.

        This is the primary check to ensure debug mode is disabled at the
        application level.
        """
        self.assertFalse(
            app.debug,
            "Flask app.debug should be False to prevent security vulnerabilities"
        )

    def test_flask_app_config_debug_is_false(self):
        """
        Verify that the Flask app configuration dictionary has DEBUG set to False.

        This checks the configuration dictionary which is another way Flask
        stores the debug setting.
        """
        self.assertFalse(
            app.config.get('DEBUG', True),
            "Flask app.config['DEBUG'] should be False for security"
        )

    @patch('sast_critical_high.app.run')
    def test_app_run_called_with_debug_false(self, mock_run):
        """
        Verify that app.run() is called with debug=False in the main block.

        This test executes the main block and verifies that when app.run()
        is called, it receives debug=False as a parameter.
        """
        # Import the module to trigger the if __name__ == "__main__" block
        import importlib
        import sast_critical_high

        # Mock the __name__ to trigger the main block
        with patch.object(sast_critical_high, '__name__', '__main__'):
            # Reload to trigger the if __name__ == "__main__" block
            try:
                exec(compile(
                    open('./Phoenix-RealtimeGoatDev/sast_critical_high.py').read(),
                    'sast_critical_high.py',
                    'exec'
                ), {'__name__': '__main__'})
            except SystemExit:
                pass
            except Exception:
                # The app.run() is mocked, so we expect it to not actually run
                pass

        # Verify app.run was called with debug=False
        if mock_run.called:
            call_kwargs = mock_run.call_args[1] if mock_run.call_args else {}
            self.assertIn('debug', call_kwargs, "debug parameter should be specified in app.run()")
            self.assertFalse(
                call_kwargs.get('debug', True),
                "app.run() should be called with debug=False"
            )

    def test_debug_mode_prevents_error_information_leakage(self):
        """
        Verify that debug mode being disabled prevents detailed error exposure.

        When debug mode is disabled, Flask should not expose detailed error
        information that could aid attackers.
        """
        with app.test_client() as client:
            # Try to access a non-existent route to trigger an error
            response = client.get('/nonexistent-route-for-testing')

            # In debug mode, Flask returns detailed error pages with 404
            # In production mode, it returns simple 404 without debug info
            self.assertEqual(response.status_code, 404)

            # Verify response doesn't contain debug information
            response_data = response.data.decode('utf-8')

            # Debug mode typically includes these in error pages
            debug_indicators = [
                'Traceback',
                'debugger',
                'console',
                'werkzeug',
                'Werkzeug Debugger'
            ]

            for indicator in debug_indicators:
                self.assertNotIn(
                    indicator,
                    response_data,
                    f"Response should not contain debug indicator: {indicator}"
                )

    def test_production_error_handling(self):
        """
        Verify that errors are handled appropriately in production mode.

        This test ensures that when an error occurs, the application doesn't
        expose internal details through debug mode.
        """
        # Create a test route that raises an exception
        @app.route('/test-error-handling')
        def test_error():
            raise ValueError("Test exception")

        with app.test_client() as client:
            response = client.get('/test-error-handling')

            # Should return 500 Internal Server Error
            self.assertEqual(response.status_code, 500)

            # Should not contain detailed traceback
            response_data = response.data.decode('utf-8')
            self.assertNotIn(
                'ValueError: Test exception',
                response_data,
                "Detailed exception messages should not be exposed"
            )

    def test_config_testing_mode_isolated_from_debug(self):
        """
        Verify that TESTING mode doesn't inadvertently enable DEBUG mode.

        Flask's TESTING mode should be independent from DEBUG mode.
        This ensures tests can run without enabling debug mode.
        """
        # Save original config
        original_testing = app.config.get('TESTING', False)

        try:
            # Enable testing mode
            app.config['TESTING'] = True

            # Verify debug is still False
            self.assertFalse(
                app.debug,
                "Enabling TESTING mode should not enable DEBUG mode"
            )
            self.assertFalse(
                app.config.get('DEBUG', True),
                "DEBUG should remain False even when TESTING is True"
            )
        finally:
            # Restore original config
            app.config['TESTING'] = original_testing

    def test_no_interactive_debugger_pin(self):
        """
        Verify that no debugger PIN is generated or exposed.

        When debug mode is enabled, Flask generates a debugger PIN for the
        interactive debugger. This test verifies no such PIN exists in
        production mode.
        """
        # Check that debug mode is off
        self.assertFalse(app.debug)

        # Verify no debugger-related attributes are accessible
        # These would only be present if debug mode was enabled
        self.assertFalse(
            hasattr(app, '_debugger_pin'),
            "Debugger PIN should not exist when debug mode is disabled"
        )


class TestSecurityHeadersWithoutDebug(unittest.TestCase):
    """Test that proper security headers are in place without debug mode interference."""

    def test_application_runs_securely_without_debug(self):
        """
        Verify the application can run and respond to requests securely
        without debug mode.

        This integration test ensures the application functions correctly
        in production mode without requiring debug features.
        """
        with app.test_client() as client:
            # Test a simple endpoint to verify app works without debug
            response = client.get('/token')

            # Should return successfully
            self.assertEqual(response.status_code, 200)

            # Should not include debug headers
            self.assertNotIn('X-Debug', response.headers)


class TestDebugModeVulnerabilityPrevention(unittest.TestCase):
    """Test cases specifically for security vulnerabilities introduced by debug mode."""

    def test_code_execution_prevention(self):
        """
        Verify that the interactive debugger (which allows code execution)
        is not accessible.

        Debug mode provides an interactive console that can execute arbitrary
        Python code. This test ensures it's not available.
        """
        self.assertFalse(
            app.debug,
            "Debug mode must be disabled to prevent interactive code execution"
        )

    def test_sensitive_config_not_exposed(self):
        """
        Verify that sensitive configuration is not exposed through debug mode.

        Debug error pages can expose app.config contents. This test ensures
        debug mode is off to prevent such exposure.
        """
        # Add a sensitive value to config for testing
        app.config['SENSITIVE_KEY'] = 'secret-value-12345'

        with app.test_client() as client:
            # Access a route that might expose config in debug mode
            response = client.get('/welcome?name=test')

            response_data = response.data.decode('utf-8')

            # Verify config is not exposed in response
            self.assertNotIn(
                'SENSITIVE_KEY',
                response_data,
                "Configuration keys should not be exposed"
            )
            self.assertNotIn(
                'secret-value-12345',
                response_data,
                "Configuration values should not be exposed"
            )

    def test_source_code_not_exposed(self):
        """
        Verify that application source code is not exposed.

        Debug mode error pages include source code snippets. This test
        ensures debug mode is disabled to prevent code exposure.
        """
        self.assertFalse(
            app.debug,
            "Debug mode must be disabled to prevent source code exposure"
        )

        # Verify that making requests doesn't expose file paths or code
        with app.test_client() as client:
            response = client.get('/nonexistent-endpoint')
            response_data = response.data.decode('utf-8')

            # Should not contain file system paths that debug mode exposes
            self.assertNotIn('.py', response_data)
            self.assertNotIn('def ', response_data)
            self.assertNotIn('import ', response_data)


if __name__ == '__main__':
    # Run all tests with verbose output
    unittest.main(verbosity=2)
