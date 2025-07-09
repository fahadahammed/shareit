import pytest
from shareit.cli import is_valid_ip, get_all_ip_addresses

class TestIPValidation:
    def test_valid_ipv4(self):
        assert is_valid_ip('192.168.1.1')
        assert is_valid_ip('127.0.0.1')
        assert is_valid_ip('0.0.0.0')

    def test_invalid_ipv4(self):
        assert not is_valid_ip('999.999.999.999')
        assert not is_valid_ip('abc.def.ghi.jkl')
        assert not is_valid_ip('256.256.256.256')

    def test_valid_ipv6(self):
        assert is_valid_ip('::1')
        assert is_valid_ip('2001:0db8:85a3:0000:0000:8a2e:0370:7334')

    def test_invalid_ipv6(self):
        assert not is_valid_ip('2001:0db8:85a3:0000:0000:8a2e:0370:zzzz')
        assert not is_valid_ip(':::')

class TestGetAllIPAddresses:
    def test_get_all_ip_addresses(self):
        ips = get_all_ip_addresses()
        assert isinstance(ips, dict)
        assert any(isinstance(ip, str) for ips_list in ips.values() for ip in ips_list)

