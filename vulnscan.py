import requests
import json

def get_vulnerabilities(url):
    response = requests.get(url)
    if response.status_code == 200:
        data = json.loads(response.content)
        return data
    else:
        raise Exception("Error getting vulnerabilities: {} {}".format(response.status_code, response.content))

def main():
    url = "https://nvd.nist.gov/vuln/api/v3/vuln/export/all?format=json"
    vulnerabilities = get_vulnerabilities(url)

    print("CVE ID | Description | Impact | Remediation measures | Link to scripts/exploits")
    for vulnerability in vulnerabilities:
        print("{:<15} | {:<20} | {:<10} | {:<20} | {:<20}".format(vulnerability["id"], vulnerability["description"], vulnerability["impact"], vulnerability["remediation_measures"], vulnerability["links"]["exploits"]))

if __name__ == "__main__":
    main()
