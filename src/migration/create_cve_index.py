import json
import requests
from fastapi import APIRouter
from elasticsearch import Elasticsearch

router = APIRouter(tags=["init endpoint"])

client = Elasticsearch(
    "https://ed1193e810684c1e9ffbfccb08b30ed3.us-central1.gcp.cloud.es.io:443",  
    api_key="RkhONmVaTUJQU0FZZUZGV2NBSHo6RG40bHBYVUpRcTJWVm1oQ3lGY09Qdw==",
)

with open("vuln.json", "r", encoding="utf8") as f:
    vuln = json.load(f)

# /init-db - Ендпоінт має ініціалізувати базу даних даними з файлу.
@router.post("/init-db")
def init_database():
    try:
        if not client.indices.exists(index="cves"):
            client.indices.create(index="cves")
        else: 
            return "Database already exist"
        client.index(index='cves', id=1, document=vuln)
        return "Success"
    except Exception as error:
        return error
