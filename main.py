import requests, json

OUTPUT_PATH = "virustotal"
API_KEY = "4b4683363546116d2a7b7e0875e8ed964264c49eb8842f39a6b63cfa1e37b278"
ENGINES = ["FireEye", "Cylance", "Cybereason", "SentinelOne", "CrowdStrike", "Microsoft"]

hashes = []
results = {
    "hash_id": "",
    "weight" : 0,
    "summary": "",
    "details": []
}

def import_hash():
    with open("hash.txt", "r") as file:
        for f in file:
            hashes.append(f.strip())


def connect(hash_id):
    url = f"https://www.virustotal.com/api/v3/files/{hash_id}"
    headers = {
        "x-apikey": API_KEY
    }
    results["hash_id"] = hash_id

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            return data
        else:
            print("Request failed with status code:", response.status_code)
            print("Response content:", response.content)
    except:
        pass

def parse(data):
    malicious_counter = 0
    results["details"] = []

    for key, value in data["data"]["attributes"]["last_analysis_results"].items():
        engine_name = key
        if engine_name in ENGINES:
            category = value['category']
            result = value['result']
            results["details"].append({
                    "Engine Name": engine_name,
                    "Category": category,
                    "Result": result
            })

            if category == "malicious":
                malicious_counter += 1

    results["weight"] = malicious_counter

    if malicious_counter >= 3:
        results["summary"] = "Target is potentially malicious"
    else:
        results["summary"] = "Target is not malicious"


    output_json = json.dumps(results, indent=2)

    return output_json

def export_output(output_json, hash):
    try:
        with open(f"{OUTPUT_PATH}_{hash}.json", "w") as output_file:
            output_file.write(output_json)
    except:
        pass


import_hash()
for hash in hashes:
    response = connect(hash)
    output = parse(response)
    export_output(output, hash[-4:])
