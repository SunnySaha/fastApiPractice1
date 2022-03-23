from datetime import timedelta

import pymongo
import motor.motor_asyncio
from fastapi import FastAPI, HTTPException, Body, Request, Depends, Security, status, Response
from fastapi.encoders import jsonable_encoder
from bson.objectid import ObjectId
from jose import jwt, JWTError
from pydantic import ValidationError
from starlette import status
from decouple import config
# from starlette.responses import JSONResponse
from helper.JwtBearer import JwtBearer
from helper.helper import item_list, single_item, get_password_hash, single_user, verify_password
from models.FoodModel import FoodModel, UpdateFoodModel
from models.UserModel import UserModel, UserSignInModel, CurrentUserModel, TokenData
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.responses import PlainTextResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes
from helper.JwtHandler import sign_jwt, JWT_SECRET, JWT_ALGORITHM, create_access_token
from typing import List


app = FastAPI()

# client = pymongo.MongoClient("mongodb+srv://test1:1234@cluster0.vzlnp.mongodb.net/"
#                              "myFirstDatabase?retryWrites=true&w=majority")

client = motor.motor_asyncio.AsyncIOMotorClient("mongodb+srv://test1:1234@cluster0.vzlnp.mongodb.net/"
                                                "myFirstDatabase?retryWrites=true&w=majority")

db = client.test_crud

crud_collection = db.crud
user_collection = db.user

is_authenticated = OAuth2PasswordBearer(
    tokenUrl="/token",
    scopes={
        "me": "Read information about the current user.",
        "read_item": "Read items."
    },
)


JWT_SECRET = config('SECRET')
JWT_ALGORITHM = config('ALGORITHM')
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = config('ACCESS_TOKEN_EXPIRE_MINUTES')
# fake_item_db = [
#     {
#         'id': 1,
#         'name': 'Chicken Tikka',
#         'price': 20.00,
#         'is_available': True,
#         'tax': 5.00,
#         'is_tax_apply': False,
#     }
# ]


# class Items(BaseModel):
#     name: str
#     price: float
#     is_available: bool | None = False
#     tax: float | None = None
#     is_tax_apply: bool | None = False


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    return PlainTextResponse(str(exc.detail), status_code=exc.status_code)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return PlainTextResponse(str(exc), status_code=400)


# def decode_token(password: str):
#
#     return password


async def get_current_user(security_scopes: SecurityScopes,token: str = Depends(is_authenticated)):
    if (security_scopes.scopes):
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": authenticate_value},
        )

    try:

        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        token_scopes = payload.get("scopes", [])
        username: str = payload.get("sub")
        print('scopes', token_scopes, username)
        token_data = TokenData(scopes=token_scopes, username=username)

    except (JWTError, ValidationError):
        raise credentials_exception

    user = await user_collection.find_one({"username": username})
    get_serialized_user = single_user(user)
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )
    return get_serialized_user

# @app.post("/token", tags=["Sign In"])
# async def sign_in(form_data: UserSignInModel):
#     get_user_with_email = await user_collection.find_one({"username": form_data.username})
#     if get_user_with_email:
#         is_verify = verify_password(form_data.password, get_user_with_email['password'])
#         if is_verify:
#             get_serialized_data = single_user(get_user_with_email)
#             response = {
#                 'user': get_serialized_data,
#                 'access_token': sign_jwt(get_user_with_email['email']),
#                 'token_type': 'Bearer'
#             }
#             return response
#         else:
#             response = {
#                 'msg': 'Password mismatch',
#             }
#             return HTTPException(status_code=status.HTTP_406_NOT_ACCEPTABLE, detail=response)
#     else:
#         response = {
#             'msg': 'No Account found with the username',
#         }
#         return HTTPException(status_code=status.HTTP_204_NO_CONTENT, detail=response)


@app.post("/token", tags=["Sign In"])
async def sign_in(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):
    get_user_with_email = await user_collection.find_one({"username": form_data.username})
    if get_user_with_email:
        is_verify = verify_password(form_data.password, get_user_with_email['password'])
        if is_verify:
            get_serialized_data = single_user(get_user_with_email)

            access_token_expires = timedelta(minutes=30)
            access_token = create_access_token(
                data={"sub": get_serialized_data['username'], "scopes": form_data.scopes},
                expires_delta=access_token_expires
            )
            response.set_cookie(key="token", value=access_token)


            data = {
                'user': get_serialized_data,
                # 'access_token': sign_jwt(get_serialized_data['email']),
                'access_token': access_token,
                'token_type': 'bearer'
            }
            return data
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="password mismatch",
                headers={"WWW-Authenticate": "Bearer"},
            )

    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No account found with this email",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.post("/register", tags=["Sign Up"])
async def register(request: Request, user: UserModel = Body(...)):
    if request.method == "POST":
        user = jsonable_encoder(user)
        hashed_pass = get_password_hash(user['password'])
        user['password'] = hashed_pass
        inserted_user = await user_collection.insert_one(user)
        created_user = await user_collection.find_one({"_id": ObjectId(inserted_user.inserted_id)})
        get_serialized_user = single_user(created_user)
        response = {
            'user': get_serialized_user,
            'access_token': sign_jwt(get_serialized_user['email']),
            'token_type': 'Bearer'
        }
        return JSONResponse(status_code=status.HTTP_201_CREATED, content=response)
    raise HTTPException(status_code=405, detail=f"this request should on POST method")


@app.get("/users/me", tags=["Get User"], dependencies=[Depends(JwtBearer())])
async def read_users_me(current_user: CurrentUserModel = Security(get_current_user, scopes=["me"])):
    print('current user', current_user)
    if current_user:
       return current_user
    raise HTTPException(status_code=400, detail="Inactive user")


@app.get("/", tags=["Get All Items"], dependencies=[Depends(JwtBearer())])
async def read_root(request: Request, current_user: CurrentUserModel = Security(get_current_user, scopes=["read_item"])) -> list:

    if request.method == 'GET':
        foods = await crud_collection.find({"price": {"$gt": 10, "$lte": 15.25}}).to_list(1000)
        if foods:
            get_items = item_list(foods)
            response = {
                "items": get_items,
            }
            return JSONResponse(status_code=200, content=response)
        else:
            return JSONResponse(status_code=200, content={'msg': 'No item found'})
    raise HTTPException(status_code=405, detail=f"this is Get Method Url")


@app.get("/items/{item_id}", tags=["Get Item by Object Id"])
async def read_item_from_database(request: Request, item_id: str):
    if request.method == 'GET':
        item = await crud_collection.find_one({"_id": ObjectId(item_id)})
        if item:
            get_item = single_item(item)
            return JSONResponse(status_code=200, content=get_item)
        # raise HTTPException(status_code=404, detail=f"Item {item_id} not found")
        raise HTTPException(status_code=400, detail=f"Item {item_id} not found")
    raise HTTPException(status_code=405, detail=f"this request should on get method")


@app.put("/items/{item_id}", tags=["update Item"])
async def update_item_database(request: Request, item_id: str, items: UpdateFoodModel = Body(...)):
    if request.method == 'PUT':

        item = {k: v for k, v in items.dict().items() if v is not None}
        if len(item) >= 1:
            update_item = await crud_collection.update_one({"_id": ObjectId(item_id)}, {"$set": item})
            if update_item.modified_count == 1:
                raise HTTPException(status_code=200, detail=f"item {item_id} update successfully")
        raise HTTPException(status_code=404, detail=f"item {item_id} not found")
    raise HTTPException(status_code=405, detail=f"update is Put method")


@app.delete("/item/delete/{item_id}", tags=["Delete Item"])
async def delete_item(item_id: str, request: Request):
    if request.method == 'DELETE':
        is_deleted = await crud_collection.delete_one({"_id": ObjectId(item_id)})
        if is_deleted.deleted_count == 1:
            return HTTPException(status_code=200, detail=f"Item Deleted Successfully")
        raise HTTPException(status_code=404, detail=f"Item with {item_id} not found")
    raise HTTPException(status_code=405, detail=f"this request method should delete")


@app.post("/item/insert", tags=["Create Item"])
async def create_item_with_database(request: Request, item: FoodModel = Body(...)):
    if request.method == "POST":
        food = jsonable_encoder(item)
        inserted_food = await crud_collection.insert_one(food)
        created_item = await crud_collection.find_one({"_id": ObjectId(inserted_food.inserted_id)})
        get_serialized_item = single_item(created_item)
        return JSONResponse(status_code=status.HTTP_201_CREATED, content=get_serialized_item)
    raise HTTPException(status_code=405, detail=f"this request should on POST method")

# @app.post('/item/add-tax')
# async def add_tax(item: Items):
#     get_item = item.dict()
#     if item.tax:
#         tax_added = item.price + item.tax
#         get_item.update({"added_tax": tax_added, "is_tax_apply": True})
#     return get_item


# @app.get("/items/{item_id}")
# async def read_item(item_id: str, request: Request):
#     # get_item_db = fake_item_db[item_id-1]
#     item_get = crud_collection.find_one({"_id": ObjectId(item_id)})
#
#     response = {
#         'msg': 'item found',
#         'data': item_get
#     }
#     return JSONResponse(status_code=status.HTTP_201_CREATED, content=response)

# @app.delete("/item/delete/{item_id}")
# async def delete_item(item_id: int):
#     get_item = fake_item_db[item_id - 1]
#     if get_item:
#         del fake_item_db[item_id - 1]
#         response = {
#             'msg': 'item deleted',
#         }
#         return {"data": response}
#     raise HTTPException(status_code=404, detail="Item with given id not found")


# @app.post("/create/item")
# async def create_item(item: Items):
#     get_item = item.dict()
#     get_item.update({'id': len(fake_item_db) + 1})
#     fake_item_db.append(get_item)
#     crud_collection.insert_one(get_item)
#     response = {
#         "message": "Data create successfully",
#         "item": item,
#         "id": len(fake_item_db) - 1
#     }
#     return response

# @app.put("/items/{item_id}")
# async def update_item(item_id: int, item: Items):
#     get_item = item.dict()
#     get_item_len = len(fake_item_db)
#     if 0 <= item_id <= get_item_len:
#         fake_item_db[item_id - 1] = get_item
#         response = {
#             'msg': 'data update successfully',
#             'item': get_item
#         }
#         return {"response": response}
#     raise HTTPException(status_code=404, detail="Item with given id not found")
