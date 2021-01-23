import os
from rdflib import Graph, Literal, Namespace, URIRef
from rdflib.namespace import FOAF, RDF


def init_user_data(path: str, username: str):

    data_paths = [
        '/' + username,
        '/' + username + '/profile'
    ]

    for p in data_paths:

        if not os.path.exists(path + p):

            os.mkdir(path + p)


def create_personal_profile_document(username: str,
                                     data_path: str,
                                     iss: str = 'http://127.0.0.1:8000'):

    init_user_data(path=data_path, username=username)

    SOLID = Namespace('http://www.w3.org/ns/solid/terms#')
    SCHEMA = Namespace('http://schema.org/')

    g = Graph()
    g.bind("solid", SOLID)
    g.bind("foaf", FOAF)
    g.bind("schema", SCHEMA)
    g.bind("rdf", RDF)

    card = URIRef(iss + '/' + username + '/card')
    me = URIRef(iss + '/' + username + '/card#me')

    g.add((card, RDF.type, FOAF.PersonalProfileDocument))
    g.add((card, FOAF.maker, me))
    g.add((card, FOAF.primaryTopic, me))

    g.add((me, RDF.type, FOAF.Person))
    g.add((me, RDF.type, SCHEMA.Person))
    g.add((me, FOAF.name, Literal('Test')))
    g.add((me, SOLID.oidcIssuer, Literal(iss)))

    profile_path = data_path + '/' + username + '/profile/card.ttl'

    with open(profile_path, 'wb') as f:

        g.serialize(destination=f,
                    format='turtle')
