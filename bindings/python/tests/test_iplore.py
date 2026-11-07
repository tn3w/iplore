import json
import os
import random
import subprocess
from pathlib import Path

import pytest

import iplore

ROOT = Path(__file__).resolve().parents[3]
ADDRESSES = json.loads((ROOT / "reader" / "tests" / "addresses.json").read_text())
DATA = Path(os.environ.get("IPLORE_DATA", ROOT / "bindings" / "data"))
CLI = os.environ.get("IPLORE_CLI", ROOT / "target" / "release" / "iplore")

KNOWN = [
    "1.1.1.1",
    "8.8.8.8",
    "185.220.101.1",
    "66.249.66.1",
    "172.224.226.1",
    "98.97.0.1",
    "2606:4700:4700::1111",
    "2001:4860:4860::8888",
]


def database_file(name):
    return DATA / f"iplore-{name}.ipl"


def native(name, address):
    output = subprocess.run(
        [CLI, database_file(name), address], capture_output=True, check=True, text=True
    )
    return json.loads(output.stdout)


def random_addresses(count):
    generator = random.Random(7)
    addresses = []
    for index in range(count):
        if index % 4 < 3:
            addresses.append(".".join(str(generator.randrange(256)) for _ in range(4)))
            continue
        digits = "2" + "".join(generator.choices("0123456789abcdef", k=31))
        addresses.append(":".join(digits[start : start + 4] for start in range(0, 32, 4)))
    return addresses


@pytest.fixture(scope="module")
def full():
    return iplore.open(database_file("full"))


@pytest.fixture(scope="module")
def country():
    return iplore.open(database_file("country"))


def test_full_database_knows_cloudflare(full):
    answer = full.lookup("1.1.1.1")
    assert answer["place"]["country"]["code"] == "AU"
    assert answer["network"]["asn"] == 13335
    assert "Cloudflare" in answer["network"]["operator"]["company"]
    assert answer["abuse"]["flags"] == ["anycast"]


def test_ipv6(full):
    assert full.lookup("2606:4700:4700::1111")["network"]["asn"] == 13335


def test_anonymizer_flags_tor_exits():
    database = iplore.open(database_file("anonymizer"))
    assert database.lookup("185.220.101.1")["abuse"]["service"] == "tor_exit_node"


def test_country_database_answers_only_the_country(country):
    answer = country.lookup("1.1.1.1")
    assert answer["place"]["country"]["code"] == "AU"
    assert answer["network"] is None


def test_reserved_space_answers_null(full):
    assert full.lookup("10.0.0.1") == {"place": None, "network": None, "abuse": None}


@pytest.mark.parametrize("spelling, canonical", ADDRESSES["valid"].items())
def test_valid_address_spellings(full, spelling, canonical):
    assert full.lookup(spelling) == full.lookup(canonical)


@pytest.mark.parametrize("address", ADDRESSES["invalid"])
def test_invalid_address_raises_value_error(country, address):
    with pytest.raises(ValueError, match="invalid address") as caught:
        country.lookup(address)
    assert not isinstance(caught.value, iplore.DatabaseError)


@pytest.mark.parametrize("source", [bytes(64), b"", b"IPLORE\0\x01" + bytes(4096)])
def test_corrupt_file_raises_database_error(source):
    with pytest.raises(iplore.DatabaseError, match="not an iplore|corrupt") as caught:
        iplore.open(source)
    assert not isinstance(caught.value, ValueError)


@pytest.mark.parametrize("cut", [100, 12 + 30000, -1])
def test_truncated_file_raises_database_error(cut):
    data = database_file("country").read_bytes()
    with pytest.raises(iplore.DatabaseError):
        iplore.open(data[:cut])


def test_corrupt_blocks_raise_database_error_on_lookup():
    data = bytearray(database_file("country").read_bytes())
    start = 12 + int.from_bytes(data[8:12], "little")
    for position in range(start, len(data), 1500):
        data[position] ^= 0xFF
    database = iplore.open(bytes(data))
    with pytest.raises(iplore.DatabaseError):
        database.lookup("1.1.1.1")
    with pytest.raises(ValueError):
        database.lookup("nope")


def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        iplore.open("does-not-exist.ipl")


def test_accepts_path_str_bytes_and_bytearray(country):
    path = database_file("country")
    expected = country.lookup("1.1.1.1")
    for source in [path, str(path), path.read_bytes(), bytearray(path.read_bytes())]:
        assert iplore.open(source).lookup("1.1.1.1") == expected


def test_about_lists_fields_and_sources(country):
    about = country.about()
    assert any(field["name"] == "place.country.code" for field in about["fields"])
    assert all("offsets" not in section for section in about["sections"])


@pytest.mark.parametrize("name, count", [("full", 100), ("place", 20), ("traffic", 20)])
def test_matches_native_cli(name, count):
    database = iplore.open(database_file(name))
    for address in KNOWN + random_addresses(count):
        assert database.lookup(address) == native(name, address), address
