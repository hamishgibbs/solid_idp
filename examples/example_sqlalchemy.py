from rdflib import Graph, Namespace, URIRef, Literal
from rdflib.namespace import FOAF, RDF
import rdflib.graph as g
graph = g.Graph()

SOLID = Namespace('http://www.w3.org/ns/solid/terms#')
SCHEMA = Namespace('http://schema.org/')

iss = 'test'
username = 'test'

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

print(g.serialize(format='n3').decode('utf-8'))
