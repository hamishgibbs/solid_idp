import json
import uuid

import pydantic
import graphene

from graphene_pydantic import PydanticObjectType

from typing import Optional


class UserModel(pydantic.BaseModel):
    id: uuid.UUID
    username: str
    hashed_password: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    disabled: Optional[bool] = None


class User(PydanticObjectType):
    class Meta:
        model = UserModel


class Query(graphene.ObjectType):
    list_users = graphene.List(User)

    def resolve_list_users(self, info):
        """Dummy resolver that creates a tree of Pydantic objects"""
        return [
            User(id=uuid.uuid4(),
                 username='johndoe',
                 hashed_password="$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"),
            User(id=uuid.uuid4(),
                 username='deffjoe',
                 hashed_password="$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW")
        ]


if __name__ == "__main__":
    schema = graphene.Schema(query=Query)
    query = """
        query {
            listUsers {
                id,
                hashedPassword
            }
    }
    """
    result = schema.execute(query)

    print(result.errors)
    print(json.dumps(result.data, indent=2))
