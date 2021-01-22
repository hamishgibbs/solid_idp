
# auth flow

# SQL db of login credentials (username & password)
# redirect to solid_idp domain to login
# redirect to "XXX would like to access XXX"
# redirect to redirect uri (stored in "redirect_uris" of solid:oidcRegistration)
# check client secret with stored secret initiated by client
# Grant tokens to client
# client uses token to gain access to thing
# list of scope types understood - contacts.read contacts.write etc.
#


from fastapi import FastAPI

app = FastAPI()


@app.get("/")
async def root():
    return {"message": "Solid IdP Provider"}
