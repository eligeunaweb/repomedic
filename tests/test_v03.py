from repomedic.audit import scan, html_report


def setup_module_root(root):
    (root / "__manifest__.py").write_text("{'name':'Example','license':'LGPL-3','depends':['base']}")


def test_xml_error_and_line(tmp_path):
    setup_module_root(tmp_path)
    (tmp_path / "views.xml").write_text("<odoo><broken></odoo>")
    findings = scan(tmp_path, "odoo")["findings"]
    assert any(x["id"] == "odoo-invalid-xml" and x["line"] == 1 for x in findings)


def test_python_risk_patterns(tmp_path):
    setup_module_root(tmp_path)
    (tmp_path / "models.py").write_text("eval(user_input)\nos.system(command)\nself.env.cr.execute(query)\n")
    ids = {f["id"] for f in scan(tmp_path, "odoo")["findings"]}
    assert {"odoo-dynamic-execution-review", "odoo-process-execution-review", "odoo-raw-sql-review"} <= ids


def test_html_escape_and_scope(tmp_path):
    setup_module_root(tmp_path)
    (tmp_path / "views.xml").write_text("<x><y></x>")
    report = scan(tmp_path, "odoo")
    html = html_report(report)
    assert "Checks executed" in html and "Limitations" in html
    assert 'lang="en"' in html and 'scope="col"' in html


def test_generic_has_scope(tmp_path):
    report = scan(tmp_path, "generic")
    assert report["checks_run"] and report["limitations"]
