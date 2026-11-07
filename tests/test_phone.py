from vship_monitor import phone

DNS = "laptop.tail1234.ts.net"


def test_finds_existing_serve_for_our_port():
    cfg = {"Web": {f"{DNS}:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8080"}}}}}
    assert phone._serving(cfg, DNS, 8080) == f"https://{DNS}"
    assert phone._serving(cfg, DNS, 8091) is None


def test_non_standard_https_port_is_kept_in_url():
    cfg = {"Web": {f"{DNS}:8443": {"Handlers": {"/": {"Proxy": "8080"}}}}}
    assert phone._serving(cfg, DNS, 8080) == f"https://{DNS}:8443"


def test_does_not_take_over_someone_elses_serve():
    cfg = {"Web": {f"{DNS}:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:3000"}}}}}
    assert phone._root_taken(cfg, DNS)
    assert not phone._root_taken({}, DNS)


def test_json_tolerates_noise_and_empty_output():
    assert phone._json('warning: something\n{"a": 1}') == {"a": 1}
    assert phone._json("") == {}


def test_missing_tailscale_gives_a_hint(monkeypatch):
    monkeypatch.setattr(phone, "tailscale_exe", lambda: None)
    info = phone.check(8080)
    assert not info["url"] and "not installed" in info["hint"]


def test_qr_outputs():
    url = f"https://{DNS}"
    svg = phone.qr_svg(url)
    assert svg.startswith("<svg") and 'fill="#000"' in svg
    lines = phone.qr_text(url).splitlines()
    assert len(lines) > 10 and len({len(x) for x in lines}) == 1   # square block, even rows
