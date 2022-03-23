from passlib.context import CryptContext


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_serialized_credential(data) -> dict:
    return {
        'email': data['email'],
        'password': data['password']
    }


def item_schema(item) -> dict:
    return {
        "id": str(item["_id"]),
        "name": item["name"],
        "price": item["price"],
        "is_available": item["is_available"],
        "tax": item["tax"],
        "is_tax_apply": item["is_tax_apply"],
    }


def single_item(item) -> dict:
    return {
        "name": item["name"],
        "price": item["price"],
        "is_available": item["is_available"],
        "tax": item["tax"],
        "is_tax_apply": item["is_tax_apply"],
    }


def single_user(user) -> dict:
    return {
        "email": user['email'],
        "username": user['username'],
        "full_name": user['full_name'],
        "userType": user['userType']
    }


def item_list(entity) -> list:
    return [item_schema(item) for item in entity]



