from conftest import families, rules


def test_python_security_rules(scan_files):
    r = scan_files({"app.py": '''
        import os, pickle, hashlib, yaml, requests
        from flask import request
        def a(cur):
            name = request.args.get("n")
            cur.execute(f"SELECT * FROM t WHERE n = '{name}'")
            os.system("ls " + name)
            pickle.loads(request.data)
            yaml.load(request.data)
            hashlib.md5(b"x")
            requests.get(name, verify=False, timeout=3)
            eval(name)
    '''})
    assert {"sql-injection", "unsafe-deserialization", "tls-verification-disabled", "dangerous-function",
            "command-injection", "weak-crypto"} <= families(r, "Security")
    # independent detectors on the same line are merged, not double counted
    sqli = [f for f in r["findings"] if f["family"] == "sql-injection"]
    assert len(sqli) == 1 and len(sqli[0]["detected_by"]) >= 1


def test_safe_python_not_flagged(scan_files):
    r = scan_files({"safe.py": '''
        import sqlite3, yaml, subprocess, ast
        def q(conn, name):
            cur = conn.cursor()
            cur.execute("SELECT * FROM t WHERE n = ?", (name,))
            yaml.safe_load("a: 1")
            subprocess.run(["ls", "-l"], check=True, timeout=5)
            return ast.literal_eval("[1,2]")
    '''})
    assert not rules(r, "Security")


def test_secret_detection_and_masking(scan_files):
    fake = "AKIA" + "IOSFODNN7EXAMPLE"
    r = scan_files({"conf.py": f'KEY = "{fake}"\nPASSWORD = "hunter2hunter2"\nTOKEN = os.environ["T"]\n'
                              'password = "changeme"\nlabel_password = "${DB_PASS}"\n'})
    sec = [f for f in r["findings"] if f["family"] == "hardcoded-secret"]
    assert len(sec) == 2
    blob = str(r["findings"])
    assert fake not in blob and "hunter2hunter2" not in blob


def test_js_rules(scan_files):
    r = scan_files({"s.js": '''
        const { exec } = require('child_process');
        app.get('/x', (req, res) => {
          exec('ls ' + req.query.d);
          el.innerHTML = req.query.name;
          res.send(eval(req.body.x));
        });
        el.innerHTML = "<b>static</b>";
    '''})
    got = rules(r, "Security")
    assert "SEC-CMDI-JS" in got and "SEC-DANGEROUS-EVAL" in got
    assert got.count("SEC-XSS-INNERHTML") == 1  # literal assignment is not flagged


def test_java_rules(scan_files):
    r = scan_files({"A.java": '''
        class A {
          void f(java.sql.Statement st, String n) throws Exception {
            st.executeQuery("SELECT * FROM u WHERE n='" + n + "'");
            java.security.MessageDigest.getInstance("MD5");
          }
        }
    '''})
    assert {"SEC-SQLI-CONCAT", "SEC-CRYPTO-HASH-JAVA"} <= set(rules(r))


def test_comments_and_strings_do_not_trigger(scan_files):
    r = scan_files({"c.py": '''
        # eval(x) is dangerous; hashlib.md5 is weak
        DOC = "never call eval(x) or os.system('rm')"
        def f():
            """pickle.loads(data) is unsafe"""
            return 1
    '''})
    assert not rules(r, "Security")


def test_http_url_and_localhost(scan_files):
    r = scan_files({"u.py": 'A = "http://api.vendor-service.net/login"\nB = "http://localhost:8000/x"\nC = "https://ok.com"\n'})
    http = [f for f in r["findings"] if f["rule_id"] == "SEC-HTTP-URL"]
    assert len(http) == 1 and http[0]["line"] == 1


def test_html_rules(scan_files):
    r = scan_files({"i.html": '<html><a href="x" target="_blank">x</a><script src="http://a.b-c.net/x.js"></script>'
                              '<form method="get"><input type="password"></form></html>'})
    assert {"HTML-BLANK-NOOPENER", "HTML-HTTP-RESOURCE", "HTML-PASSWORD-GET"} <= set(rules(r))


def test_findings_have_required_fields(scan_files):
    r = scan_files({"a.py": 'import pickle\npickle.loads(b"")\n'})
    f = r["findings"][0]
    for key in ("id", "rule_id", "title", "category", "severity", "file", "line", "evidence", "explanation", "impact",
                "remediation", "confidence", "source", "verification", "detected_by", "context"):
        assert key in f and f[key] not in (None, "") or key == "context"
    assert f["verification"] in ("static-match", "potential-risk", "heuristic")
