from flask import Flask, render_template, request, jsonify
import dns.resolver
import requests

app = Flask(__name__)

FINGERPRINTS = {
    "github.io": "There is no repository",
    "herokuapp.com": "No such app",
    "s3.amazonaws.com": "NoSuchBucket",
    "azurewebsites.net": "404 WebSite not found",
    "bitbucket.io": "Repository not found",
    "readthedocs.io": "Unknown Domain",
    "unbouncepages.com": "Page not found",
    "surge.sh": "project not found",
}

def get_cname(domain):
    try:
        answer = dns.resolver.resolve(domain, 'CNAME')
        for r in answer:
            return str(r.target).rstrip('.')
    except:
        return None

def get_http_status(domain):
    try:
        resp = requests.get(f"http://{domain}", timeout=4)
        return resp.status_code, resp.text[:1000]
    except:
        return None, ""

def scan_subdomain(domain):
    result = {"domain": domain, "cname": "", "status": "", "vulnerable": False, "reason": ""}
    cname = get_cname(domain)
    result["cname"] = cname if cname else "None"

    status, content = get_http_status(domain)
    result["status"] = status if status else "Unreachable"

    for service, keyword in FINGERPRINTS.items():
        if (cname and service in cname) or (keyword.lower() in content.lower()):
            result["vulnerable"] = True
            result["reason"] = f"Matched: {service} - {keyword}"
            break

    return result

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/check", methods=["POST"])
def check():
    domains = request.json.get("domains", "")
    domain_list = [d.strip() for d in domains.splitlines() if d.strip()]
    results = [scan_subdomain(domain) for domain in domain_list]
    return jsonify(results)

if __name__ == "__main__":
    app.run(debug=True)
