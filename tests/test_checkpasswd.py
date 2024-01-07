import pytest
from requests.models import Response
from unittest.mock import Mock

from src.checkpasswd import get_passwd_leaks_count


@pytest.mark.parametrize(
    "hashes, hash_to_check, expected_result",
    [
        (
            "943B1609FFFBFC51AAD666D0A04ADF83C9D:25",
            "943B1609FFFBFC51AAD666D0A04ADF83C9D",
            25,
        ),
        (
            "943B1609FFFBFC51AAD666D0A04ADF83C9D:25",
            "256B2614FFFBFC64AAD666D0A08ADF73F5J",
            0,
        ),
        (
            "",
            "256B2614FFFBFC64AAD666D0A08ADF73F5J",
            0,
        ),
    ],
)
def test_get_passwd_leaks_count(hashes, hash_to_check, expected_result):
    mock_response = Mock(spec=Response)
    mock_response.text = hashes
    leaked_count = get_passwd_leaks_count(mock_response, hash_to_check)
    assert leaked_count == expected_result
