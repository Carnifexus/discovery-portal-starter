"""Azure Functions Flex entry point for a dedicated discovery intake deployment."""
import os
import azure.functions as func
from azure.identity import ManagedIdentityCredential
from config import cookie_domain_mode
from portal import configured_key
from storage import AzureStateAndObjects, SnapshotApp

app=func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

def runtime():
    origin=os.environ['INTAKE_V2_ORIGIN']
    exact=cookie_domain_mode(origin,os.environ.get('INTAKE_V2_COOKIE_MODE','auto'))
    store=AzureStateAndObjects(os.environ['INTAKE_V2_ACCOUNT_URL'],
                               os.environ.get('INTAKE_V2_STATE_CONTAINER','v2-state'),
                               os.environ.get('INTAKE_V2_QUARANTINE_CONTAINER','v2-quarantine'),
                               ManagedIdentityCredential())
    return SnapshotApp(store,store,configured_key(),origin,os.environ['INTAKE_V2_WORKER_TOKEN'],
                       exact_cookie_domain=exact)

@app.route(route='{*path}',methods=['GET','POST'])
def handle(req: func.HttpRequest,context: func.Context) -> func.HttpResponse:
    return func.WsgiMiddleware(runtime()).handle(req,context)
