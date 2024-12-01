import json
from uuid import uuid4
from fastapi import FastAPI, Query
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
from migration import create_cve_index

from fastapi import Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

client = Elasticsearch(
    "https://ed1193e810684c1e9ffbfccb08b30ed3.us-central1.gcp.cloud.es.io:443",  
    api_key="RkhONmVaTUJQU0FZZUZGV2NBSHo6RG40bHBYVUpRcTJWVm1oQ3lGY09Qdw==",
)

app = FastAPI()

app.include_router(create_cve_index.router)

index = "cves"

templates = Jinja2Templates(directory="src/templates")

# / - для того щоб вибрати ендпоінт
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("start_page.html", {"request": request})

@app.get("/info", response_class=HTMLResponse)
def inform(request: Request):
    return templates.TemplateResponse(name="inform.html", request=request, context={
        "author": "Marko Yavorskiy",
        "about_application": "This FastAPI application pulls data from elastic database about CVEs and displays it to you."
    })

# /get/all - Має виводити CVE за останні 5 днів. Максимум 40 CVE
@app.get('/get/all/', response_class=HTMLResponse)
def five_days_cve(request: Request):
    try:
        response = client.get(index=index, id=1)

        current_date = datetime.now()
        f_ago_date = current_date - timedelta(days=5)

        f_days_cve = []

        for i in response['_source']['vulnerabilities']:
            add_date = datetime.fromisoformat(i["dateAdded"])
            if add_date >= f_ago_date:
                f_days_cve.append(i)
                
        if f_days_cve:
            return templates.TemplateResponse(name="cve.html", request=request, context={"cves": f_days_cve[:40]})
        else:
            return "No vulnerabilities for last 5 days"
        
    except Exception as e:
        return f"Something went wrong, problem is {e}"
    
# /get/new - Має виводити 10 найновіших CVE
@app.get("/get/new", response_class=HTMLResponse)
def ten_new_cve(request: Request):
    try:
        response = client.get(index=index, id=1)

        if response['_source']['vulnerabilities']:
            sort_response = sorted(response['_source']['vulnerabilities'], key=lambda x: x['dateAdded'])
            return templates.TemplateResponse(name="cve.html", request=request, context={"cves": sort_response[-10:]})
        else:
            return "No vulneabilities"
        
    except Exception as e:
        return f"Something went wrong, problem is {e}"
    

# /get/critical - Має виводити 10 критичних CVE
@app.get("/get/known", response_class=HTMLResponse)
def critical_cve(request: Request):
    all_know_cve = []
    
    try:
        response = client.get(index=index, id=1)

        for i in response['_source']['vulnerabilities']:
            if "Known" == i["knownRansomwareCampaignUse"]:
                all_know_cve.append(i)

        if all_know_cve:
            return templates.TemplateResponse(name="cve.html", request=request, context={"cves": all_know_cve[:10]})
        else:
            return "No critical vulneabilities"
        
    except Exception as e:
        return f"Something went wrong, problem is {e}"


# #  /get?query="key" - Має виводити CVE які містять ключове слово
@app.get("/get", response_class=HTMLResponse)
def get_keyword_cve(query, request: Request):
    response = client.get(index=index, id=1)

    keyword_cve = []

    for i in response['_source']['vulnerabilities']:
        if query in i["shortDescription"] or query in i["vulnerabilityName"] or query in i["vendorProject"] or query in i["product"] or query in i["knownRansomwareCampaignUse"]:
            keyword_cve.append(i)

    if keyword_cve:
        return templates.TemplateResponse(name="cve.html", request=request, context={"cves": keyword_cve})
    else:
        return "No vulneabilities with this keyword"

        