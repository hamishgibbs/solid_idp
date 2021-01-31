from rdflib import Graph, Namespace, URIRef, Literal, XSD, BNode

from rdflib.namespace import FOAF, RDF
import datetime
import rdflib.graph as g

graph = g.Graph()

ST = Namespace('http://www.w3.org/ns/posix/stat#')

TERMS = Namespace('http://purl.org/dc/terms/')
LDP = Namespace('http://www.w3.org/ns/ldp#')
SOLID = Namespace('http://www.w3.org/ns/solid/terms#')
SCHEMA = Namespace('http://schema.org/')
FILES = Namespace('')

iss = 'test'
username = 'test'

g = Graph()

g.add((FILES.files, RDF.type, LDP.BasicContainer))
g.add((FILES.files, RDF.type, LDP.Container))

g.add((FILES.files, TERMS.modified, Literal(datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'),
                                           datatype=XSD.dateTime)))


doc = BNode()
g.add((doc, RDF.type, LDP.Resource))
g.add((doc, TERMS.modified, Literal(datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'),
                                           datatype=XSD.dateTime)))

g.add((FILES.files, LDP.contains, doc))

print(g.serialize(format='json-ld').decode('utf-8'))
