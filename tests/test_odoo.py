from repomedic.audit import scan

def test_odoo_manifest_and_nested_tests(tmp_path):
    (tmp_path / "__manifest__.py").write_text("{'name': 'Example', 'license': 'LGPL-3', 'depends': ['base']}")
    (tmp_path / "analyzer" / "tests").mkdir(parents=True)
    report = scan(tmp_path, profile="odoo")
    assert report["profile"] == "odoo"
    assert not any(f["id"].startswith("missing-") for f in report["findings"])

def test_odoo_broad_access(tmp_path):
    (tmp_path / "__manifest__.py").write_text("{'name':'Test','license':'LGPL-3','depends':['base']}")
    security = tmp_path / "security"
    security.mkdir()
    (security / "ir.model.access.csv").write_text("id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink\na,a,model_x,,1,1,0,0\n")
    report = scan(tmp_path, profile="odoo")
    assert any(f["id"] == "odoo-broad-access" for f in report["findings"])

def test_sudo_review(tmp_path):
    (tmp_path / "__manifest__.py").write_text("{'name':'Test','license':'LGPL-3','depends':['base']}")
    (tmp_path / "model.py").write_text("records.sudo().write({'x': 1})\n")
    report = scan(tmp_path, profile="odoo")
    assert any(f["id"] == "odoo-sudo-review" for f in report["findings"])
