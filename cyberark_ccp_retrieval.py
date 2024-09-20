import json
import ssl
import argparse
from urllib.parse import quote, urlencode
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from http.client import HTTPException

def retrieve_credential(api_base_url, app_id, safe, folder, object_name, 
                        connection_timeout=30, query_format="Exact", 
                        fail_request_on_password_change=True, reason=None,
                        validate_certs=True, client_cert=None, client_key=None):
    
    query_params = {
        "AppID": app_id,
        "Safe": safe,
        "Folder": folder,
        "Object": object_name,
        "ConnectionTimeout": connection_timeout,
        "QueryFormat": query_format,
        "FailRequestOnPasswordChange": str(fail_request_on_password_change).lower()
    }
    
    if reason:
        query_params["reason"] = reason

    end_point = f"/AIMWebService/api/Accounts?{urlencode(query_params)}"

    try:
        context = ssl.create_default_context()
        if not validate_certs:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        
        if client_cert and client_key:
            context.load_cert_chain(client_cert, client_key)

        request = Request(api_base_url + end_point, method="GET")
        response = urlopen(request, context=context, timeout=connection_timeout)

        if response.getcode() == 200:
            result = json.loads(response.read())
            return result, response.getcode()
        else:
            raise Exception(f"Error in end_point: {end_point}")

    except (HTTPError, URLError, HTTPException) as http_exception:
        raise Exception(
            f"Error while retrieving credential. "
            f"Please validate parameters provided, and permissions for "
            f"the application and provider in CyberArk."
            f"\n*** end_point={api_base_url}{end_point}\n ==> {str(http_exception)}"
        ) from http_exception

    except Exception as unknown_exception:
        raise Exception(
            f"Unknown error while retrieving credential."
            f"\n*** end_point={api_base_url}{end_point}\n{str(unknown_exception)}"
        ) from unknown_exception

def main():
    parser = argparse.ArgumentParser(description="Retrieve credentials from CyberArk CCP")
    parser.add_argument("--api-base-url", required=True, help="Base URL of the CyberArk API")
    parser.add_argument("--app-id", required=True, help="Application ID")
    parser.add_argument("--safe", required=True, help="Safe name")
    parser.add_argument("--folder", required=True, help="Folder name")
    parser.add_argument("--object", required=True, help="Object name")
    parser.add_argument("--connection-timeout", type=int, default=30, help="Connection timeout")
    parser.add_argument("--query-format", default="Exact", help="Query format")
    parser.add_argument("--fail-request-on-password-change", type=lambda x: (str(x).lower() == 'true'), default=True, help="Fail request on password change")
    parser.add_argument("--reason", help="Reason for accessing the credential")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Do not verify SSL certificate (equivalent to curl's -k)")
    parser.add_argument("--cert", help="Path to client certificate file")
    parser.add_argument("--key", help="Path to client key file")

    args = parser.parse_args()

    try:
        result, status_code = retrieve_credential(
            api_base_url=args.api_base_url,
            app_id=args.app_id,
            safe=args.safe,
            folder=args.folder,
            object_name=args.object,
            connection_timeout=args.connection_timeout,
            query_format=args.query_format,
            fail_request_on_password_change=args.fail_request_on_password_change,
            reason=args.reason,
            validate_certs=not args.no_verify_ssl,
            client_cert=args.cert,
            client_key=args.key
        )
        print(f"Credential retrieved successfully. Status code: {status_code}")
        print(f"Credential info: {json.dumps(result, indent=2)}")
    except Exception as e:
        print(f"Error retrieving credential: {str(e)}")

if __name__ == "__main__":
    main()
