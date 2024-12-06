from fastapi import FastAPI
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
from migration import create_cve_index

client = Elasticsearch(
    "https://ed1193e810684c1e9ffbfccb08b30ed3.us-central1.gcp.cloud.es.io:443",  
    api_key="RkhONmVaTUJQU0FZZUZGV2NBSHo6RG40bHBYVUpRcTJWVm1oQ3lGY09Qdw==",
)

app = FastAPI()

app.include_router(create_cve_index.router)

index = "cves"

# /info - Має виводити інформацію про додаток, вас як автора
@app.get("/info")
def inform():
    return {
        "author": "Marko Yavorskiy",
        "about application": "This FastAPI application pulls data from elastic database about CVEs and displays it to you."
    }
# /get/all - Має виводити CVE за останні 5 днів. Максимум 40 CVE
@app.get("/get/all")
def five_days_cve():
    try:
        current_date = datetime.now()
        f_ago_date = current_date - timedelta(days=5)
        query = {
            "query": {
                "range": {
                    "dateAdded": {
                        "gte": f_ago_date.isoformat() 
                    }
                }
            },
            "size": 40
        }

        response = client.search(index=index, body=query)

        if response["hits"]["total"]["value"] > 0:
            return response["hits"]["hits"]
        else:
            return "No vulnerabilities for last 5 days"
        
    except Exception as e:
        return f"Something went wrong, problem is {e}"

# /get/new - Має виводити 10 найновіших CVE
@app.get("/get/new")
def ten_new_cve():
    try:
        query = {
            "query": {
                "match_all": {}
            },
            "sort": [
                {"dateAdded": {"order": "desc"}}
            ],
            "size": 10
        }
        response = client.search(index=index, body=query)

        if response["hits"]["total"]["value"] > 0:
            return response["hits"]["hits"]
        else:
            return "No vulnerabilities found"
        
    except Exception as e:
        return f"Something went wrong, problem is {e}"

# /get/known - Має виводити CVE в яких knownRansomwareCampaignUse - Known, максимум 10.@app.get("/get/known")
@app.get("/get/known")
def critical_cve():
    try:
        query = {
            "query": {
                "match": {
                    "knownRansomwareCampaignUse": "Known"
                }
            },
            "size": 10
        }

        response = client.search(index=index, body=query)

        if response["hits"]["total"]["value"] > 0:
            return response["hits"]["hits"]
        else:
            return "No critical vulnerabilities"
        
    except Exception as e:
        return f"Something went wrong, problem is {e}"

# /get?query="key" - Має виводити CVE які містять ключове слово@app.get("/get")
@app.get("/get")
def get_keyword_cve(query: str):
    try:
        query_body = {
            "query": {
                "multi_match": {
                    "query": query,
                    "fields": ["shortDescription", "vulnerabilityName", "vendorProject", "product", "knownRansomwareCampaignUse"]
                }
            }
        }

        response = client.search(index=index, body=query_body)

        if response["hits"]["total"]["value"] > 0:
            return response["hits"]["hits"]
        else:
            return "No vulnerabilities with this keyword"

    except Exception as e:
        return f"Something went wrong, problem is {e}"
