import pytest

from cyber_swarm.runner import build_parser, main


def test_build_parser_has_help():
    parser = build_parser()
    help_text = parser.format_help()
    assert "Cyber Swarm Python agent runtime" in help_text


def test_main_help_exits_zero():
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
