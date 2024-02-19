from starlette.types import ASGIApp
from starlette.types import ASGIApp, Message
from fastapi import FastAPI, Request
import ast
from dotenv import load_dotenv
import requests
from sixth.utils import encryption_utils
import json
from starlette.datastructures import MutableHeaders
from fastapi import Response
from sixth.middlewares.six_base_http_middleware import SixBaseHTTPMiddleware, _StreamingResponse
from fastapi import HTTPException
import time
from sixth import schemas
import re
load_dotenv()


class EncryptionMiddleware(SixBaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, apikey: str, fastapi_app: FastAPI):
        super().__init__(app)
        self._app = app
        self._apikey = apikey
        self._logs_sent = {}
        self._last_updated = 0
        self._encryption_enabled = False
        self._update_encryption_details()
        
        for route in fastapi_app.router.routes:
            if type(route.app) == FastAPI:
                for new_route in route.app.routes:
                    path = "/v"+str(route.app.version)+new_route.path
                    edited_route = re.sub(r'\W+', '~', path)
                    self._logs_sent[str(edited_route)] = 0
            else:
                edited_route = re.sub(r'\W+', '~', route.path)
                self._logs_sent[str(edited_route)] = 0 



    async def set_body(self, request: Request, body: bytes):
        async def receive() -> Message:
            return {'type': 'http.request', 'body': body}
        request._receive = receive

    async def _parse_bools(self, string: bytes)-> str:
        string = string.decode("utf-8")
        string = string.replace(' ', "")
        string = string.replace('true,', "True,")
        string = string.replace(",true", "True,")
        string = string.replace('false,', "False,")
        string = string.replace(",false", "False,")
        out=ast.literal_eval(string)
        return out
    
    async def _send_logs(self, route: str, header, body, query)-> None:
        timestamp = time.time()
        last_log_sent = self._logs_sent[route]
        if timestamp - last_log_sent > 10:
            requests.post("https://backend.withsix.co/slack/send_message_to_slack_user", json=schemas.SlackMessageSchema(
                header=header, 
                user_id=self._apikey, 
                body=str(body), 
                query_args=str(query), 
                timestamp=timestamp, 
                attack_type="Encryption Bypass", 
                cwe_link="https://cwe.mitre.org/data/definitions/311.html", 
                status="MITIGATED", 
                learn_more_link="https://en.wikipedia.org/wiki/Rate_limiting", 
                route=route
            ).dict())
            self._logs_sent[route]=timestamp

    def _update_encryption_details(self):
        timestamp = time.time()
        if timestamp - self._last_updated <10:
            return 
        response = requests.get(f"https://backend.withsix.co/encryption-service/get-encryption-setting-for-user?user_id={self._apikey}")
        if response.status_code == 200:
            self._encryption_enabled = response.json()["enabled"]
            self._last_updated=timestamp
        else:
            self._encryption_enabled=False

    async def dispatch(self,request: Request,call_next) -> None:
        self._update_encryption_details()
        if self._encryption_enabled:
            route = request.scope["path"]
            route = re.sub(r'\W+', '~', route)
            req_body = await request.body()
            await self.set_body(request, req_body)
            req_body =await self._parse_bools(req_body)
            headers = dict(request.headers)
            try:
                output = await encryption_utils.post_order_decrypt(req_body)
                output = json.dumps(output)
                headers["content-length"]= str(len(output.encode()))
            except Exception as e:
                await self._send_logs(route=route, header=headers, body=req_body, query="")
                output= {
                    "data": "UnAuthorized"
                }
                headers = MutableHeaders(headers={"content-length": str(len(str(output).encode())), 'content-type': 'application/json'})
                return Response(json.dumps(output), status_code=401, headers=headers)
            request._cached_body = output
            response: Response = await call_next(output)

            # Get the response body content from the custom property
            response_body = b"".join([part async for part in response.body_iterator])
            response_body = response_body.decode("utf-8")
            try:
                output = {
                    "data": await encryption_utils.post_order_encrypt(response_body)
                }
                output = json.dumps(output)
                response.headers["content-length"]= str(len(output.encode()))
                return Response(
                    content=output, 
                    headers=response.headers,
                    media_type=response.media_type, 
                    background=response.background
                )
                
            except Exception as e:
                output= {
                    "data": "UnAuthorized"
                }
                headers = MutableHeaders(headers={"content-length": str(len(str(output).encode())), 'content-type': 'application/json'})
                return Response(json.dumps(output), status_code=401, headers=headers)
        else:
            _response = await call_next(request)
            return _response