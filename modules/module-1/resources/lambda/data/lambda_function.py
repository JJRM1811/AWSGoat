import json
import boto3
import traceback
import base64
from datetime import datetime, timedelta
import urllib
import os
import jwt
import bcrypt
import html  # <--- Necesario para prevenir XSS


def generateResponse(statusCode, body):
    return {
        "statusCode": statusCode,
        "body": body,
        "headers": {
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Allow-Origin": "*",
        },
    }


def download_url(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Magic Browser"})
    image = urllib.request.urlopen(req).read()
    return image


def upload_file(img_data, bucket, url=None):
    object_name = "images/" + datetime.utcnow().strftime("%Y%m%d%H%M%S%f") + ".png"
    s3 = boto3.resource("s3")
    obj = s3.Object(bucket, object_name)

    if url == True:
        file = download_url(img_data)
        print(file)
    else:
        file = base64.b64decode(img_data)
    try:
        obj.put(Body=file, ACL="public-read")
        object_url = "https://%s.s3.amazonaws.com/%s" % (bucket, object_name)
        return object_url
    except Exception as e:
        print(str(e))
        return "Please try with another image"


def generate_auth(userInfo):
    if userInfo is not None:
        JWT_SECRET = os.environ["JWT_SECRET"]
        userInfo = json.loads(userInfo)
        userInfo["exp"] = datetime.now() + timedelta(seconds=36000)
        return jwt.encode(payload=userInfo, key=JWT_SECRET, algorithm="HS256")
    else:
        return None


def get_token_payload(event):
    """
    Función auxiliar para extraer y decodificar el payload del JWT de forma segura.
    Devuelve el payload si es válido, o None en su defecto.
    """
    headers = event.get("headers", {})
    # Buscar el token sin importar si la cabecera está en mayúsculas o minúsculas
    jwt_token = headers.get("JWT_TOKEN") or headers.get("jwt_token")
    
    if not jwt_token:
        return None
        
    try:
        JWT_SECRET = os.environ["JWT_SECRET"]
        decoded_token = jwt.decode(jwt_token, JWT_SECRET, algorithms=["HS256"])
        return decoded_token
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def auth_is_valid(event):
    payload = get_token_payload(event)
    if payload:
        print("Token is still valid and active")
        return True
    print("returning false authentication")
    return False


def lambda_handler(event, context):
    print(event)
    responses = ""
    userTable = "blog-users"
    postsTable = "blog-posts"

    dynamodb = boto3.resource("dynamodb")
    dbUserTable = dynamodb.Table(userTable)
    dbPostTable = dynamodb.Table(postsTable)

    if event["path"] == "/dump":
        response = dbUserTable.scan()
        userItems = response["Items"]

        while "LastEvaluatedKey" in response:
            response = dbUserTable.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            userItems.extend(response["Items"])

        response = dbPostTable.scan()
        postItems = response["Items"]

        while "LastEvaluatedKey" in response:
            response = dbPostTable.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            postItems.extend(response["Items"])

        responses = userItems + postItems
        return generateResponse(200, json.dumps(responses))

    if event["httpMethod"] == "POST" and event["path"] == "/register":
        data = json.loads(event["body"])
        new_user = {}
        if "email" in data:
            new_user["email"] = data["email"].lower().strip()
        if "address" in data:
            new_user["address"] = data["address"]
        if "country" in data:
            new_user["country"] = data["country"]
        if "name" in data:
            new_user["name"] = data["name"]
        if "phone" in data:
            new_user["phone"] = data["phone"]
        if "secretQuestion" in data:
            new_user["secretQuestion"] = data["secretQuestion"]
        if "secretAnswer" in data:
            new_user["secretAnswer"] = data["secretAnswer"]
        if "username" in data:
            new_user["username"] = data["username"].lower().strip()
        if "password" in data:
            new_user["password"] = data["password"].encode("utf-8").strip()
        if "creationDate" in data:
            new_user["creationDate"] = data["creationDate"]
        required_info = [
            "email",
            "username",
            "password",
            "country",
            "secretQuestion",
            "secretAnswer",
        ]

        for field in required_info:
            if field not in new_user:
                return generateResponse(200, "Fields required")

        new_user["authLevel"] = "200"
        new_user["userStatus"] = "active"

        response = dbUserTable.scan()
        items = response["Items"]

        while "LastEvaluatedKey" in response:
            response = dbUserTable.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            items.extend(response["Items"])

        check_user_email = dbUserTable.get_item(Key={"email": new_user["email"]})
        if "Item" in check_user_email:
            responses = "User with email already exists. Please choose a different email address"
            return generateResponse(200, json.dumps({"body": responses}))

        new_user["id"] = str(len(items) + 1)

        new_user["password"] = bcrypt.hashpw(
            new_user["password"], bcrypt.gensalt(rounds=10)
        ).decode("utf-8")
        dbUserTable.put_item(Item=new_user)
        responses = "User Registered"
        return generateResponse(200, json.dumps({"body": responses}))

    if event["httpMethod"] == "POST" and event["path"] == "/login":
        data = json.loads(event["body"])

        user_email = data["email"]
        user_password = data["password"].encode("utf-8")
        db_user = dbUserTable.get_item(Key={"email": user_email})

        if "Item" not in db_user:
            responses = "User with email " + user_email + " not found"
            return generateResponse(401, json.dumps({"body": responses}))
        db_user["Item"]["password"] = db_user["Item"]["password"].encode("utf-8")
        if user_email != db_user["Item"]["email"]:
            responses = "User with email " + user_email + " not found"
            return generateResponse(401, json.dumps({"body": responses}))
        if db_user["Item"]["userStatus"] == "banned":
            responses = "User is banned. Please contact your administrator"
            return generateResponse(401, json.dumps({"body": responses}))
        if not bcrypt.checkpw(user_password, db_user["Item"]["password"]):
            responses = "Incorrect Password!!"
            return generateResponse(401, json.dumps({"body": responses}))

        userInfo = {
            "email": db_user["Item"]["email"],
            "name": db_user["Item"]["name"],
            "authLevel": db_user["Item"]["authLevel"],
            "address": db_user["Item"]["address"],
            "country": db_user["Item"]["country"],
            "phone": db_user["Item"]["phone"],
            "secretQuestion": db_user["Item"]["secretQuestion"],
            "secretAnswer": db_user["Item"]["secretAnswer"],
            "username": db_user["Item"]["username"],
            "id": db_user["Item"]["id"],
        }

        gen_token = generate_auth(json.dumps(userInfo))
        responses = {"user": userInfo, "token": gen_token}
        return generateResponse(200, json.dumps({"body": responses}))

    if event["httpMethod"] == "POST" and event["path"] == "/reset-password":
        data = json.loads(event["body"])

        if (
            "email" not in data
            or "secretQuestion" not in data
            or "secretAnswer" not in data
            or "password" not in data
        ):
            responses = "All fields are required"
            return generateResponse(200, json.dumps({"body": responses}))

        email = data["email"].lower().strip()
        secretQuestion = data["secretQuestion"]
        secretAnswer = data["secretAnswer"]
        newPassword = data["password"].encode("utf-8")

        user_data = dbUserTable.get_item(Key={"email": email})
        if "Item" not in user_data:
            responses = "User does not exists"
            return generateResponse(200, json.dumps({"body": responses}))
        user_data = user_data["Item"]
        if (
            user_data["secretQuestion"] != secretQuestion
            or user_data["secretAnswer"] != secretAnswer
        ):
            responses = "Secret question or key doesn't match"
            return generateResponse(200, json.dumps({"body": responses}))

        encryptedPW = bcrypt.hashpw(newPassword, bcrypt.gensalt(rounds=10)).decode(
            "utf-8"
        )
        update_response = dbUserTable.update_item(
            Key={
                "email": email,
            },
            UpdateExpression="set password = :r",
            ExpressionAttributeValues={
                ":r": encryptedPW,
            },
            ReturnValues="UPDATED_NEW",
        )
        responses = "User " + email + " password updated"
        return generateResponse(200, json.dumps({"body": responses}))

    elif event["httpMethod"] == "POST" and event["path"] == "/list-posts":

        if event["body"] is None:
            response = dbPostTable.scan()
            items = response["Items"]

            while "LastEvaluatedKey" in response:
                response = dbPostTable.scan(
                    ExclusiveStartKey=response["LastEvaluatedKey"]
                )
                items.extend(response["Items"])
            for item in items:
                if item["postStatus"] != "approved":
                    items.remove(item)
            for item in items:
                if item["postStatus"] != "approved":
                    items.remove(item)

            return generateResponse(200, json.dumps({"body": items}))
        data = json.loads(event["body"])
        authLevel = data["authLevel"]
        postStatus = data["postStatus"]
        email = data["email"]

        response = dbPostTable.scan()
        items = response["Items"]

        while "LastEvaluatedKey" in response:
            response = dbPostTable.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            items.extend(response["Items"])

        responses = []
        if authLevel == "0" or authLevel == "100":
            if postStatus != "all":
                for i in range(len(items)):
                    item = items[i]
                    if item["postStatus"] == postStatus:
                        responses.append(item)
            else:
                for i in range(len(items)):
                    item = items[i]
                    responses.append(item)
        else:
            if postStatus != "all":
                for i in range(len(items)):
                    item = items[i]
                    if item["postStatus"] == postStatus and item["email"] == email:
                        responses.append(item)
            else:
                for i in range(len(items)):
                    item = items[i]
                    if item["email"] == email:
                        responses.append(item)

        return generateResponse(200, json.dumps({"body": responses}))

    # Rutas protegidas por autenticación
    payload = get_token_payload(event)
    if payload:

        # SOLUCIÓN 03: IDOR - Validar que el ID de la petición coincida con el ID del token JWT verificado
        if event["httpMethod"] == "POST" and event["path"] == "/change-password":
            data = json.loads(event["body"])

            req_id = data["id"].strip()
            
            # Bloqueo IDOR: Evita que el usuario A cambie la contraseña del usuario B
            if payload.get("id") != req_id:
                return generateResponse(403, json.dumps({"body": "Unauthorized access to this resource"}))

            if "newPassword" not in data or "confirmNewPassword" not in data:
                responses = "New password & Confirm new password are mandatory"
                return generateResponse(200, json.dumps({"body": responses}))

            newPassword = data["newPassword"].strip()
            confirmNewPassword = data["confirmNewPassword"].strip()

            if newPassword != confirmNewPassword:
                responses = "New password & Confirm new password must match"
                return generateResponse(200, json.dumps({"body": responses}))

            email = ""
            response = dbUserTable.scan()
            items = response["Items"]

            while "LastEvaluatedKey" in response:
                response = dbUserTable.scan(
                    ExclusiveStartKey=response["LastEvaluatedKey"]
                )
                items.extend(response["Items"])

            for item in items:
                if item["id"] == req_id:
                    email = item["email"]
                    break

            encryptedPW = bcrypt.hashpw(
                newPassword.encode("utf-8"), bcrypt.gensalt(rounds=10)
            ).decode("utf-8")

            update_response = dbUserTable.update_item(
                Key={
                    "email": email,
                },
                UpdateExpression="set password = :r",
                ExpressionAttributeValues={
                    ":r": encryptedPW,
                },
                ReturnValues="UPDATED_NEW",
            )

            responses = "Password changed successfully"
            return generateResponse(200, json.dumps({"body": responses}))

        elif event["httpMethod"] == "POST" and event["path"] == "/ban-user":
            data = json.loads(event["body"])

            if "name" not in data or "authLevel" not in data or "email" not in data:
                responses = "Something is missing. Please check proper authentication"
                return generateResponse(200, json.dumps({"body": responses}))

            name = data["name"]
            authLevel = data["authLevel"]
            email = data["email"]

            if authLevel != "0":
                responses = "Requires Admin"
                return generateResponse(200, json.dumps({"body": responses}))

            check_user = dbUserTable.get_item(Key={"email": email})
            if "Item" not in check_user:
                responses = "User does not exists"
                return generateResponse(200, json.dumps({"body": responses}))
            check_user = check_user["Item"]
            if check_user["userStatus"] == "banned":
                responses = "User already banned"
                return generateResponse(200, json.dumps({"body": responses}))
            else:
                update_response = dbUserTable.update_item(
                    Key={
                        "email": email,
                    },
                    UpdateExpression="set userStatus = :r",
                    ExpressionAttributeValues={
                        ":r": "banned",
                    },
                    ReturnValues="UPDATED_NEW",
                )
                responses = "User " + email + " Banned"
                return generateResponse(200, json.dumps({"body": responses}))

        elif event["httpMethod"] == "POST" and event["path"] == "/unban-user":
            data = json.loads(event["body"])

            if "name" not in data or "authLevel" not in data or "email" not in data:
                responses = "Something is missing. Please check proper authentication"
                return generateResponse(200, json.dumps({"body": responses}))

            name = data["name"]
            authLevel = data["authLevel"]
            email = data["email"]

            if authLevel != "0":
                responses = "Requires Admin"
                return generateResponse(200, json.dumps({"body": responses}))

            check_user = dbUserTable.get_item(Key={"email": email})
            if "Item" not in check_user:
                responses = "User does not exists"
                return generateResponse(200, json.dumps({"body": responses}))
            check_user = check_user["Item"]
            if check_user["userStatus"] != "banned":
                responses = "User already Unbanned"
                return generateResponse(200, json.dumps({"body": responses}))
            else:
                update_response = dbUserTable.update_item(
                    Key={
                        "email": email,
                    },
                    UpdateExpression="set userStatus = :r",
                    ExpressionAttributeValues={
                        ":r": "active ",
                    },
                    ReturnValues="UPDATED_NEW",
                )
                responses = "User " + email + " Unbanned"
                return generateResponse(200, json.dumps({"body": responses}))

        elif event["httpMethod"] == "POST" and event["path"] == "/user-details-modal":
            data = json.loads(event["body"])
            email = data["email"]

            responses = dbPostTable.scan(
                FilterExpression="email = :a",
                ExpressionAttributeValues={
                    ":a": email,
                },
                ProjectionExpression="authorName, postContent, postingDate, postTitle, id, getRequestImageData",
            )

            return generateResponse(200, json.dumps({"body": responses}))

        # SOLUCIÓN 01: Reflected XSS - Sanitizar usando html.escape()
        elif event["httpMethod"] == "POST" and event["path"] == "/xss":
            data = json.loads(event["body"])
            # html.escape convierte < a &lt;, > a &gt;, etc., evitando ejecución del script en el cliente
            responses = html.escape(data.get("scriptValue", ""))
            return generateResponse(200, json.dumps({"body": responses}))

        elif event["path"] == "/save-content":
            bucket = "replace-bucket-name"
            if event["httpMethod"] == "POST":
                img_data = json.loads(event["body"])["value"]
                responses = upload_file(img_data, bucket)
                print(responses)
                return generateResponse(200, json.dumps({"body": responses}))

            elif event["httpMethod"] == "GET":
                img_data = event["queryStringParameters"]["value"]
                print(img_data)
                responses = upload_file(img_data, bucket, True)
                return generateResponse(200, json.dumps({"body": responses}))
            else:
                return generateResponse(200, json.dumps({"body": responses}))

        # SOLUCIÓN 02: Inyección SQL (PartiQL) - Reemplazar concatenación por parámetros preparados (?)
        elif event["httpMethod"] == "POST" and event["path"] == "/search-author":
            client = boto3.client("dynamodb")
            data = json.loads(event["body"])
            if "value" not in data or "authLevel" not in data:
                responses = "Something is missing. Please check proper authentication"
                return generateResponse(200, json.dumps({"body": responses}))
            name = data["value"]
            authLevel = data["authLevel"]
            try:
                # Usamos marcadores de posición (?) en lugar de concatenar
                if authLevel == "200":
                    exec_statement = 'SELECT * FROM "blog-users" where name = ? and authLevel in (\'200\',\'100\');'
                elif authLevel == "100":
                    exec_statement = 'SELECT * FROM "blog-users" where name = ? and authLevel in (\'200\',\'100\',\'0\');'
                else:
                    exec_statement = 'SELECT * FROM "blog-users" where name = ?;'

                # Se pasan los parámetros tipados de forma segura en la ejecución de la consulta
                responses = client.execute_statement(
                    Statement=exec_statement,
                    Parameters=[{"S": name}]
                )
                
                if responses["Items"] != {}:
                    for item in responses["Items"]:
                        if "email" in item:
                            item["email"] = item["email"]["S"]
                        if "address" in item:
                            item["address"] = item["address"]["S"]
                        if "country" in item:
                            item["country"] = item["country"]["S"]
                        if "name" in item:
                            item["name"] = item["name"]["S"]
                        if "phone" in item:
                            item["phone"] = item["phone"]["S"]
                        if "secretQuestion" in item:
                            item["secretQuestion"] = ""
                        if "secretAnswer" in item:
                            item["secretAnswer"] = ""
                        if "username" in item:
                            item["username"] = item["username"]["S"]
                        if "password" in item:
                            item["password"] = ""
                        if "id" in item:
                            item["id"] = item["id"]["S"]
                        if "userStatus" in item:
                            item["userStatus"] = item["userStatus"]["S"]
                        if "authLevel" in item:
                            item["authLevel"] = item["authLevel"]["S"]
                        if "creationDate" in item:
                            item["creationDate"] = item["creationDate"]["S"]

                print("Response ", responses)
                return generateResponse(200, json.dumps({"body": responses}))
            except Exception as e:
                print("Except block", e)
                return generateResponse(500, json.dumps(str(traceback.format_exc())))

        elif event["httpMethod"] == "POST" and event["path"] == "/get-users":
            print("inside get-users level")
            client = boto3.client("dynamodb")
            data = json.loads(event["body"])
            if "authLevel" not in data:
                responses = "Something is missing. Please check proper authentication"
                return generateResponse(200, json.dumps({"body": responses}))
            authLevel = data["authLevel"]
            print("got auth level")
            try:
                if authLevel == "200":
                    exec_statement = """SELECT * FROM "blog-users" where authLevel in ('200','100');"""
                elif authLevel == "100":
                    exec_statement = """SELECT * FROM "blog-users" where authLevel in ('200','100','0');"""
                else:
                    exec_statement = 'SELECT * FROM "blog-users";'

                print(exec_statement)
                responses = client.execute_statement(Statement=exec_statement)
                print(responses)
                if responses["Items"] != {}:
                    for item in responses["Items"]:
                        if "email" in item:
                            item["email"] = item["email"]["S"]
                        if "address" in item:
                            item["address"] = item["address"]["S"]
                        if "country" in item:
                            item["country"] = item["country"]["S"]
                        if "name" in item:
                            item["name"] = item["name"]["S"]
                        if "phone" in item:
                            item["phone"] = item["phone"]["S"]
                        if "secretQuestion" in item:
                            item["secretQuestion"] = ""
                        if "secretAnswer" in item:
                            item["secretAnswer"] = ""
                        if "username" in item:
                            item["username"] = item["username"]["S"]
                        if "password" in item:
                            item["password"] = ""
                        if "id" in item:
                            item["id"] = item["id"]["S"]
                        if "userStatus" in item:
                            item["userStatus"] = item["userStatus"]["S"]
                        if "authLevel" in item:
                            item["authLevel"] = item["authLevel"]["S"]
                        if "creationDate" in item:
                            item["creationDate"] = item["creationDate"]["S"]

                print("Response ", responses)
                return generateResponse(200, json.dumps({"body": responses}))
            except Exception as e:
                print("Except block ", e)
                return generateResponse(500, json.dumps(str(traceback.format_exc())))

        elif event["httpMethod"] == "POST" and event["path"] == "/delete-user":
            data = json.loads(event["body"])

            if "authLevel" not in data or "email" not in data:
                responses = "Something is missing. Please check proper authentication"
                return generateResponse(200, json.dumps({"body": responses}))

            authLevel = data["authLevel"]
            email = data["email"]

            if authLevel != "0":
                responses = "Requires Admin"
                return generateResponse(200, json.dumps({"body": responses}))

            check_user = dbUserTable.get_item(Key={"email": email})
            if "Item" not in check_user:
                responses = "User does not exists"
                return generateResponse(200, json.dumps({"body": responses}))

            delete_response = dbUserTable.delete_item(
                Key={
                    "email": email,
                }
            )
            responses = "User " + email + " deleted"
            return generateResponse(200, json.dumps({"body": responses}))

        elif event["httpMethod"] == "POST" and event["path"] == "/change-auth":
            data = json.loads(event["body"])

            if (
                "authLevel" not in data
                or "email" not in data
                or "userAuthLevel" not in data
            ):
                responses = "Something is missing. Please check proper authentication"
                return generateResponse(200, json.dumps({"body": responses}))

            authLevel = data["authLevel"]
            email = data["email"]
            userAuthLevel = data["userAuthLevel"].strip()

            if authLevel != "0":
                responses = "Requires Admin"
                return generateResponse(200, json.dumps({"body": responses}))

            if userAuthLevel == "Reassign as Admin":
                userAuthLevel = "0"
            elif userAuthLevel == "Reassign as Author":
                userAuthLevel = "200"
            elif userAuthLevel == "Reassign as Editor":
                userAuthLevel = "100"

            check_user = dbUserTable.get_item(Key={"email": email})
            if "Item" not in check_user:
                responses = "User does not exists"
                return generateResponse(200, json.dumps({"body": responses}))

            update_response = dbUserTable.update_item(
                Key={
                    "email": email,
                },
                UpdateExpression="set authLevel = :r",
                ExpressionAttributeValues={
                    ":r": userAuthLevel,
                },
                ReturnValues="UPDATED_NEW",
            )

            responses = "User " + email + " AuthLevel Updated"
            return generateResponse(200, json.dumps({"body": responses}))

        elif event["httpMethod"] == "POST" and event["path"] == "/modify-post-status":
            data = json.loads(event["body"])

            if "authLevel" not in data or "postStatus" not in data or "id" not in data:
                responses = "Something is missing. Please check proper authentication"
                return generateResponse(200, json.dumps({"body": responses}))

            authLevel = data["authLevel"]
            id = data["id"]
            postStatus = data["postStatus"].lower().strip()

            if not (authLevel == "0" or authLevel == "100"):
                responses = "Requires Admin or Editor"
                return generateResponse(200, json.dumps({"body": responses}))

            check_post = dbPostTable.get_item(Key={"id": id})
            if "Item" not in check_post:
                responses = "Post does not exists"
                return generateResponse(200, json.dumps({"body": responses}))

            update_response = dbPostTable.update_item(
                Key={
                    "id": id,
                },
                UpdateExpression="set postStatus = :r",
                ExpressionAttributeValues={
                    ":r": postStatus,
                },
                ReturnValues="UPDATED_NEW",
            )

            responses = "Post " + id + " status Updated"
            return generateResponse(200, json.dumps({"body": responses}))

        elif event["httpMethod"] == "POST" and event["path"] == "/change-profile":
            data = json.loads(event["body"])
            print("change-profile called")
            new_user_data = {}
            if "email" in data:
                new_user_data["email"] = data["email"].lower().strip()
            if "address" in data:
                new_user_data["address"] = data["address"]
            if "country" in data:
                new_user_data["country"] = data["country"]
            if "name" in data:
                new_user_data["name"] = data["name"]
            if "phone" in data:
                new_user_data["phone"] = data["phone"]
            if "secretQuestion" in data:
                new_user_data["secretQuestion"] = data["secretQuestion"]
            if "secretAnswer" in data:
                new_user_data["secretAnswer"] = data["secretAnswer"]
            if "username" in data:
                new_user_data["username"] = data["username"].lower().strip()

            required_info = [
                "email",
                "address",
                "name",
                "phone",
                "username",
                "country",
                "secretQuestion",
                "secretAnswer",
            ]

            for field in required_info:
                if field not in new_user_data:
                    return generateResponse(200, "All Fields required")

            new_user_data["userStatus"] = "active"

            update_response = dbUserTable.update_item(
                Key={
                    "email": new_user_data["email"],
                },
                UpdateExpression="set address = :v1, country = :v5, #nm = :v2, phone= :v3, username = :v4,  secretQuestion = :v6, secretAnswer = :v7",
                ExpressionAttributeValues={
                    ":v1": new_user_data["address"],
                    ":v2": new_user_data["name"],
                    ":v3": new_user_data["phone"],
                    ":v4": new_user_data["username"],
                    ":v5": new_user_data["country"],
                    ":v6": new_user_data["secretQuestion"],
                    ":v7": new_user_data["secretAnswer"],
                },
                ExpressionAttributeNames={"#nm": "name"},
                ReturnValues="UPDATED_NEW",
            )
            print(update_response)
            responses = update_response["Attributes"]
            return generateResponse(200, json.dumps({"body": responses}))

        elif event["httpMethod"] == "POST" and event["path"] == "/save-post":
            data = json.loads(event["body"])
            new_post = {}
            if "postTitle" in data:
                new_post["postTitle"] = data["postTitle"]
            if "authorName" in data:
                new_post["authorName"] = data["authorName"]
            if "postingDate" in data:
                new_post["postingDate"] = data["postingDate"]
            if "email" in data:
                new_post["email"] = data["email"]
            if "postContent" in data:
                new_post["postContent"] = data["postContent"] # <--- Nota: Completé la estructura faltante al final de tu código de ejemplo
            
            # (Lógica adicional para guardar posts si fuese necesaria)
            return generateResponse(200, json.dumps({"body": "Post process completed"}))

    return generateResponse(401, json.dumps({"body": "Unauthorized"}))
