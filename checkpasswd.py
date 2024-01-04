import requests
import hashlib
import sys


def requests_api_ada(query_char: str) -> requests.Response:
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f"Error fetching: {res.status_code}, check API and try again"
        )
    return res


def get_passwd_leaks_count(hashes: requests.Response, hash_to_check: str) -> int:
    matched_hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in matched_hashes:
        if h == hash_to_check:
            return int(count)
    return 0


def pwned_api_check(passwd: str) -> int:
    sha1passwd = hashlib.sha1(passwd.encode("utf-8")).hexdigest().upper()
    first5_char, tail = sha1passwd[:5], sha1passwd[5:]
    response = requests_api_ada(first5_char)
    return get_passwd_leaks_count(response, tail)


def main(args: list) -> str:
    for passwd in args:
        count = pwned_api_check(passwd)
        if count:
            print(f"{passwd} was found {count} time(s)... Change it!")
        else:
            print(f"{passwd} was NOT found. Carry on!")
    return "Done!"


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
