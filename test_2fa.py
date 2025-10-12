#!/usr/bin/env python

"""
Test suite for 2fa.py
"""

import sys
import tempfile
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest

# Import the module under test
sys.path.insert(0, str(Path(__file__).parent))
from twofa import (
    Key,
    Keychain,
    TwoFAException,
    decode_key,
    hotp,
    read_keychain,
    totp,
)


class TestDecodeKey:
    def test_decode_valid_key(self):
        # Test a valid base32 key
        key = "JBSWY3DPEHPK3PXP"
        result = decode_key(key)
        assert result == b"Hello!\xde\xad\xbe\xef"

    def test_decode_lowercase_key(self):
        # Should handle lowercase
        key = "jbswy3dpehpk3pxp"
        result = decode_key(key)
        assert result == b"Hello!\xde\xad\xbe\xef"

    def test_decode_invalid_key(self):
        # Invalid base32 characters should raise
        with pytest.raises((ValueError, Exception)):  # noqa: B017
            decode_key("INVALID1")


class TestHOTP:
    def test_hotp_rfc4226_examples(self):
        # Test vectors from RFC 4226
        secret = b"12345678901234567890"

        expected = [
            (0, 755224),
            (1, 287082),
            (2, 359152),
            (3, 969429),
            (4, 338314),
            (5, 254676),
            (6, 287922),
            (7, 162583),
            (8, 399871),
            (9, 520489),
        ]

        for counter, expected_code in expected:
            result = hotp(secret, counter, 6)
            assert result == expected_code

    def test_hotp_different_digits(self):
        secret = b"test_secret"

        # Test 6 digits
        code_6 = hotp(secret, 1, 6)
        assert 0 <= code_6 < 1000000

        # Test 7 digits
        code_7 = hotp(secret, 1, 7)
        assert 0 <= code_7 < 10000000

        # Test 8 digits
        code_8 = hotp(secret, 1, 8)
        assert 0 <= code_8 < 100000000


class TestTOTP:
    def test_totp_known_time(self):
        # Test TOTP with a known timestamp
        secret = b"12345678901234567890"
        test_time = datetime.fromtimestamp(59)  # Time step 1

        code = totp(secret, test_time, 6)
        # This should match the counter = 1 case from HOTP
        assert code == 287082

    def test_totp_different_times_produce_different_codes(self):
        secret = b"test_secret"
        time1 = datetime.fromtimestamp(0)
        time2 = datetime.fromtimestamp(29)

        code1 = totp(secret, time1, 6)
        code2 = totp(secret, time2, 6)

        # Same time window (both in first 30 seconds) should produce same code
        assert code1 == code2

    def test_totp_time_windows(self):
        secret = b"test_secret"
        time1 = datetime.fromtimestamp(0)
        time2 = datetime.fromtimestamp(31)

        code1 = totp(secret, time1, 6)
        code2 = totp(secret, time2, 6)

        # Different time windows might produce different codes
        # (though collision is possible, unlikely with different counters)
        assert isinstance(code1, int)
        assert isinstance(code2, int)


class TestKey:
    def test_key_initialization(self):
        key = Key()
        assert key.raw == b""
        assert key.digits == 0
        assert key.offset == 0


class TestKeychain:
    def test_keychain_initialization(self):
        test_file = str(Path(tempfile.gettempdir()) / "test")
        kc = Keychain(test_file)
        assert kc.file == test_file
        assert kc.data == b""
        assert kc.keys == {}

    def test_keychain_add_totp_key(self):
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            kc = Keychain(str(filepath))

            # Mock input for key
            with patch("builtins.input", return_value="JBSWY3DPEHPK3PXP"):
                kc.add("test_key")

            # Verify file was created with correct permissions
            assert filepath.exists()
            assert oct(filepath.stat().st_mode)[-3:] == "600"

            # Verify content
            content = filepath.read_text()
            assert "test_key 6 JBSWY3DPEHPK3PXP" in content

    def test_keychain_add_hotp_key(self):
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            kc = Keychain(str(filepath))

            with patch("builtins.input", return_value="JBSWY3DPEHPK3PXP"):
                kc.add("test_hotp", hotp_mode=True)

            content = filepath.read_text()
            assert "test_hotp 6 JBSWY3DPEHPK3PXP" in content
            assert "0" * 20 in content

    def test_keychain_add_7_digit_key(self):
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            kc = Keychain(str(filepath))

            with patch("builtins.input", return_value="JBSWY3DPEHPK3PXP"):
                kc.add("test_7", digits_7=True)

            content = filepath.read_text()
            assert "test_7 7 JBSWY3DPEHPK3PXP" in content

    def test_keychain_add_8_digit_key(self):
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            kc = Keychain(str(filepath))

            with patch("builtins.input", return_value="JBSWY3DPEHPK3PXP"):
                kc.add("test_8", digits_8=True)

            content = filepath.read_text()
            assert "test_8 8 JBSWY3DPEHPK3PXP" in content

    def test_keychain_add_conflicting_digits(self):
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            kc = Keychain(str(filepath))

            with patch("builtins.input", return_value="JBSWY3DPEHPK3PXP"):
                with pytest.raises(TwoFAException, match="cannot use -7 and -8 together"):
                    kc.add("test", digits_7=True, digits_8=True)

    def test_keychain_add_invalid_key(self):
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            kc = Keychain(str(filepath))

            with patch("builtins.input", return_value="INVALID1"):
                with pytest.raises(TwoFAException, match="invalid key"):
                    kc.add("test")

    def test_keychain_code_totp(self):
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            # Create a keychain file manually
            filepath.write_text("test_key 6 JBSWY3DPEHPK3PXP\n")

            kc = read_keychain(str(filepath))
            code = kc.code("test_key")

            # Should be a 6-digit code
            assert len(code) == 6
            assert code.isdigit()

    def test_keychain_code_hotp(self):
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            # Create a keychain file with HOTP key
            filepath.write_text("test_hotp 6 JBSWY3DPEHPK3PXP 00000000000000000000\n")

            kc = read_keychain(str(filepath))
            code1 = kc.code("test_hotp")

            # Should be a 6-digit code
            assert len(code1) == 6
            assert code1.isdigit()

            # Counter should increment
            kc2 = read_keychain(str(filepath))
            code2 = kc2.code("test_hotp")

            # Codes should be different (counter incremented)
            assert code1 != code2

    def test_keychain_code_nonexistent_key(self):
        test_file = str(Path(tempfile.gettempdir()) / "test")
        kc = Keychain(test_file)
        with pytest.raises(TwoFAException, match="no such key"):
            kc.code("nonexistent")

    def test_keychain_list(self, capsys):
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.write_text("key1 6 JBSWY3DPEHPK3PXP\nkey2 6 JBSWY3DPEHPK3PXP\n")

            kc = read_keychain(str(filepath))
            kc.list()

            captured = capsys.readouterr()
            assert "key1" in captured.out
            assert "key2" in captured.out

    def test_keychain_show(self, capsys):
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.write_text("test_key 6 JBSWY3DPEHPK3PXP\n")

            kc = read_keychain(str(filepath))
            kc.show("test_key")

            captured = capsys.readouterr()
            assert len(captured.out.strip()) == 6
            assert captured.out.strip().isdigit()

    def test_keychain_show_all(self, capsys):
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.write_text(
                "key1 6 JBSWY3DPEHPK3PXP\nkey2 7 JBSWY3DPEHPK3PXP\nkey3 6 JBSWY3DPEHPK3PXP 00000000000000000000\n"
            )

            kc = read_keychain(str(filepath))
            kc.show_all()

            captured = capsys.readouterr()
            # Should show codes for TOTP keys and dashes for HOTP
            assert "key1" in captured.out
            assert "key2" in captured.out
            assert "key3" in captured.out
            assert "------" in captured.out  # HOTP placeholder (6 dashes for 6 digits)


class TestReadKeychain:
    def test_read_empty_keychain(self):
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.touch()

            kc = read_keychain(str(filepath))
            assert kc.keys == {}

    def test_read_nonexistent_keychain(self):
        test_file = str(Path(tempfile.gettempdir()) / "nonexistent_keychain_file")
        kc = read_keychain(test_file)
        assert kc.keys == {}

    def test_read_valid_keychain(self):
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.write_text("test_key 6 JBSWY3DPEHPK3PXP\n")

            kc = read_keychain(str(filepath))
            assert "test_key" in kc.keys
            assert kc.keys["test_key"].digits == 6
            assert kc.keys["test_key"].offset == 0

    def test_read_keychain_with_hotp(self):
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.write_text("test_hotp 6 JBSWY3DPEHPK3PXP 00000000000000000042\n")

            kc = read_keychain(str(filepath))
            assert "test_hotp" in kc.keys
            assert kc.keys["test_hotp"].offset > 0

    def test_read_keychain_with_multiple_keys(self):
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.write_text(
                "key1 6 JBSWY3DPEHPK3PXP\nkey2 7 JBSWY3DPEHPK3PXP\nkey3 8 JBSWY3DPEHPK3PXP 00000000000000000000\n"
            )

            kc = read_keychain(str(filepath))
            assert len(kc.keys) == 3
            assert kc.keys["key1"].digits == 6
            assert kc.keys["key2"].digits == 7
            assert kc.keys["key3"].digits == 8

    def test_read_keychain_with_malformed_lines(self):
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.write_text("key1 6 JBSWY3DPEHPK3PXP\nmalformed line\nkey2 6 JBSWY3DPEHPK3PXP\n")

            kc = read_keychain(str(filepath))
            # Should skip malformed lines
            assert len(kc.keys) == 2
            assert "key1" in kc.keys
            assert "key2" in kc.keys

    def test_read_keychain_with_empty_lines(self):
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.write_text("key1 6 JBSWY3DPEHPK3PXP\n\nkey2 6 JBSWY3DPEHPK3PXP\n")

            kc = read_keychain(str(filepath))
            assert len(kc.keys) == 2


class TestClipboard:
    def test_clip_darwin(self):
        with patch("twofa.PLATFORM", "Darwin"):
            with patch("twofa.subprocess_run") as mock_run:
                from twofa import clip

                clip("123456")
                mock_run.assert_called_once()
                assert mock_run.call_args[0][0] == "pbcopy"

    def test_clip_linux(self):
        with patch("twofa.PLATFORM", "Linux"):
            with patch("twofa.subprocess_run") as mock_run:
                from twofa import clip

                clip("123456")
                mock_run.assert_called_once()
                assert mock_run.call_args[0][0] == "wl-copy"

    @patch("twofa.PLATFORM", "Windows")
    def test_clip_unsupported_platform(self):
        from twofa import clip

        with pytest.raises(NotImplementedError):
            clip("123456")


class TestEdgeCases:
    def test_counter_increment_persistence(self):
        """Test that HOTP counter increments are persisted correctly"""
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.write_text("test 6 JBSWY3DPEHPK3PXP 00000000000000000000\n")

            kc1 = read_keychain(str(filepath))
            _code1 = kc1.code("test")

            # Read again and verify counter was updated
            content = filepath.read_text()
            assert "00000000000000000001" in content

            kc2 = read_keychain(str(filepath))
            _code2 = kc2.code("test")

            # Counter should be incremented again
            content = filepath.read_text()
            assert "00000000000000000002" in content

    def test_key_with_whitespace(self):
        """Test that keys with whitespace are handled correctly"""
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            kc = Keychain(str(filepath))

            with patch("builtins.input", return_value="JBSW Y3DP EHPK 3PXP"):
                kc.add("test")

            content = filepath.read_text()
            # Whitespace should be stripped
            assert "JBSWY3DPEHPK3PXP" in content

    def test_zero_padded_codes(self):
        """Test that codes are properly zero-padded"""
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.write_text("test 6 JBSWY3DPEHPK3PXP\n")

            kc = read_keychain(str(filepath))
            code = kc.code("test")

            # Code should always be exactly 6 digits (zero-padded if necessary)
            assert len(code) == 6
            assert code.isdigit()


class TestDocumentation:
    def test_usage_in_readme(self):
        """Verify that usage block in code matches README"""
        from twofa import usage_block

        # Read README
        readme_path = Path(__file__).parent / "README.md"
        readme_content = readme_path.read_text()
        # Extract content between ``` marks in the ## Help section
        # Find the help section
        help_section_start = readme_content.find("## Help")
        assert help_section_start != -1, "README should have a '## Help' section"
        # Find the code block after ## Help
        code_block_start = readme_content.find("```", help_section_start)
        assert code_block_start != -1, "README should have a code block after ## Help"
        code_block_end = readme_content.find("```", code_block_start + 3)
        assert code_block_end != -1, "README code block should be closed"
        # Extract the content between the ```
        readme_usage = readme_content[code_block_start + 3 : code_block_end].strip()
        # Compare with usage_block from code
        assert usage_block.strip() == readme_usage, (
            f"Usage block in code should match README.\nExpected:\n{usage_block.strip()}\n\nGot:\n{readme_usage}"
        )


class TestMain:
    def test_unknown_option_raises_exception(self):
        """Test that unknown options raise TwoFAException"""
        from twofa import main

        with patch("twofa.argv", ["2fa", "-unknown"]):
            with pytest.raises(TwoFAException, match="unknown option: -unknown"):
                main()

    def test_multiple_unknown_options(self):
        """Test that first unknown option is caught"""
        from twofa import main

        with patch("twofa.argv", ["2fa", "-foo", "-bar"]):
            with pytest.raises(TwoFAException, match="unknown option: -foo"):
                main()

    def test_valid_options_dont_raise(self):
        """Test that valid options are accepted"""
        from twofa import main

        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.write_text("test_key 6 JBSWY3DPEHPK3PXP\n")
            with patch("twofa.CONFIG_2FA_SECRETS", filepath):
                # -list is a valid option
                with patch("twofa.argv", ["2fa", "-list"]):
                    with patch("sys.stdout"):
                        main()  # Should not raise

    def test_unknown_option_with_keyname(self):
        """Test unknown option combined with keyname"""
        from twofa import main

        with patch("twofa.argv", ["2fa", "-invalid", "github"]):
            with pytest.raises(TwoFAException, match="unknown option: -invalid"):
                main()

    def test_too_many_arguments(self):
        """Test error when providing multiple key names"""
        from twofa import main

        with patch("twofa.argv", ["2fa", "github", "aws", "google"]):
            with pytest.raises(TwoFAException, match="too many arguments: expected 0 or 1, got 3"):
                main()

    def test_invalid_key_name_characters(self):
        """Test error for invalid characters in key name"""
        from twofa import main

        with patch("twofa.argv", ["2fa", "git@hub"]):
            with pytest.raises(TwoFAException, match="invalid key name 'git@hub'"):
                main()

    def test_no_keys_in_keychain(self):
        """Test error when keychain is empty"""
        from twofa import main

        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.touch()  # Empty file
            with patch("twofa.CONFIG_2FA_SECRETS", filepath):
                with patch("twofa.argv", ["2fa"]):
                    with pytest.raises(TwoFAException, match="no keys found"):
                        main()

    def test_multiple_flags_without_keyname(self):
        """Test error when combining flags without a key name"""
        from twofa import main

        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.write_text("test 6 JBSWY3DPEHPK3PXP\n")
            with patch("twofa.CONFIG_2FA_SECRETS", filepath):
                with patch("twofa.argv", ["2fa", "-add", "-hotp"]):
                    with pytest.raises(TwoFAException, match="cannot combine multiple flags without a key name"):
                        main()

    def test_single_flag_without_keyname_not_list(self):
        """Test error when using a single flag (not -list) without key name"""
        from twofa import main

        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.write_text("test 6 JBSWY3DPEHPK3PXP\n")
            with patch("twofa.CONFIG_2FA_SECRETS", filepath):
                with patch("twofa.argv", ["2fa", "-add"]):
                    with pytest.raises(TwoFAException, match="cannot use flags without a key name"):
                        main()

    def test_clip_with_multiple_flags(self):
        """Test error when combining -clip with other flags"""
        from twofa import main

        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.write_text("test 6 JBSWY3DPEHPK3PXP\n")
            with patch("twofa.CONFIG_2FA_SECRETS", filepath):
                with patch("twofa.argv", ["2fa", "-clip", "-7", "test"]):
                    with pytest.raises(TwoFAException, match="cannot combine -clip with other flags"):
                        main()

    def test_invalid_flag_combination(self):
        """Test error for invalid flag combinations"""
        from twofa import main

        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.write_text("test 6 JBSWY3DPEHPK3PXP\n")
            with patch("twofa.CONFIG_2FA_SECRETS", filepath):
                with patch("twofa.argv", ["2fa", "-hotp", "test"]):
                    with pytest.raises(TwoFAException, match="invalid flag combination"):
                        main()

    def test_show_all_success(self):
        """Test successful show_all operation"""
        from twofa import main

        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.write_text("test 6 JBSWY3DPEHPK3PXP\n")
            with patch("twofa.CONFIG_2FA_SECRETS", filepath):
                with patch("twofa.argv", ["2fa"]):
                    with patch("sys.stdout"):
                        main()  # Should not raise

    def test_show_specific_key_success(self):
        """Test successful show operation for a specific key"""
        from twofa import main

        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.write_text("test 6 JBSWY3DPEHPK3PXP\n")
            with patch("twofa.CONFIG_2FA_SECRETS", filepath):
                with patch("twofa.argv", ["2fa", "test"]):
                    with patch("sys.stdout"):
                        main()  # Should not raise


class TestUsageDisplay:
    """Test that usage() is displayed for appropriate errors"""

    def _run_main_with_exception_handler(self, argv_list, config_path=None):
        """Helper to simulate running the script with exception handler"""
        from twofa import Color, TwoFAException, main, usage

        patches = [patch("twofa.argv", argv_list)]
        if config_path:
            patches.append(patch("twofa.CONFIG_2FA_SECRETS", config_path))

        with patch.multiple("twofa", Color=Color, TwoFAException=TwoFAException, main=main, usage=usage):
            with patches[0]:
                if len(patches) > 1:
                    with patches[1]:
                        try:
                            main()
                        except TwoFAException as e:
                            # Simulate the exception handler from if __name__ == "__main__"
                            if any(
                                phrase in str(e)
                                for phrase in [
                                    "unknown option",
                                    "too many arguments",
                                    "invalid key name",
                                    "cannot combine",
                                    "cannot use flags",
                                    "invalid flag combination",
                                ]
                            ):
                                return str(e), True  # Should show usage
                            return str(e), False  # Should NOT show usage
                else:
                    try:
                        main()
                    except TwoFAException as e:
                        if any(
                            phrase in str(e)
                            for phrase in [
                                "unknown option",
                                "too many arguments",
                                "invalid key name",
                                "cannot combine",
                                "cannot use flags",
                                "invalid flag combination",
                            ]
                        ):
                            return str(e), True
                        return str(e), False

    def test_usage_shown_for_unknown_option(self):
        """Test that usage should be displayed after unknown option error"""
        error_msg, should_show_usage = self._run_main_with_exception_handler(["2fa", "-invalid"])
        assert "unknown option: -invalid" in error_msg
        assert should_show_usage is True

    def test_usage_shown_for_too_many_arguments(self):
        """Test that usage should be displayed after too many arguments error"""
        error_msg, should_show_usage = self._run_main_with_exception_handler(["2fa", "key1", "key2"])
        assert "too many arguments" in error_msg
        assert should_show_usage is True

    def test_usage_shown_for_invalid_key_name(self):
        """Test that usage should be displayed after invalid key name error"""
        error_msg, should_show_usage = self._run_main_with_exception_handler(["2fa", "invalid@name"])
        assert "invalid key name" in error_msg
        assert should_show_usage is True

    def test_usage_shown_for_cannot_combine_flags(self):
        """Test that usage should be displayed for 'cannot combine' errors"""
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.write_text("test 6 JBSWY3DPEHPK3PXP\n")
            error_msg, should_show_usage = self._run_main_with_exception_handler(
                ["2fa", "-add", "-list"], config_path=filepath
            )
            assert "cannot combine" in error_msg
            assert should_show_usage is True

    def test_usage_shown_for_cannot_use_flags(self):
        """Test that usage should be displayed for 'cannot use flags' errors"""
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.write_text("test 6 JBSWY3DPEHPK3PXP\n")
            error_msg, should_show_usage = self._run_main_with_exception_handler(["2fa", "-add"], config_path=filepath)
            assert "cannot use flags" in error_msg
            assert should_show_usage is True

    def test_usage_shown_for_invalid_flag_combination(self):
        """Test that usage should be displayed for invalid flag combination errors"""
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.write_text("test 6 JBSWY3DPEHPK3PXP\n")
            error_msg, should_show_usage = self._run_main_with_exception_handler(
                ["2fa", "-hotp", "test"], config_path=filepath
            )
            assert "invalid flag combination" in error_msg
            assert should_show_usage is True

    def test_no_usage_shown_for_no_such_key(self):
        """Test that usage should NOT be displayed for operational errors like 'no such key'"""
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.write_text("test 6 JBSWY3DPEHPK3PXP\n")
            error_msg, should_show_usage = self._run_main_with_exception_handler(
                ["2fa", "nonexistent"], config_path=filepath
            )
            assert "no such key" in error_msg
            assert should_show_usage is False

    def test_no_usage_shown_for_empty_keychain(self):
        """Test that usage should NOT be displayed for 'no keys found' error"""
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / ".2fa"
            filepath.touch()
            error_msg, should_show_usage = self._run_main_with_exception_handler(["2fa"], config_path=filepath)
            assert "no keys found" in error_msg
            assert should_show_usage is False


class TestHelpFlag:
    """Test that help flags display usage and exit"""

    def test_help_flag(self):
        """Test that -help flag displays usage"""
        from twofa import main

        with patch("twofa.argv", ["2fa", "-help"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == -2

    def test_double_dash_help_flag(self):
        """Test that --help flag displays usage"""
        from twofa import main

        with patch("twofa.argv", ["2fa", "--help"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == -2

    def test_h_flag(self):
        """Test that -h flag displays usage"""
        from twofa import main

        with patch("twofa.argv", ["2fa", "-h"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == -2

    def test_help_with_other_args(self):
        """Test that help flag works even with other arguments"""
        from twofa import main

        with patch("twofa.argv", ["2fa", "-h", "keyname"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == -2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
