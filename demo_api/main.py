from fastapi import FastAPI
import uvicorn

from . import api


app = FastAPI(title="Padding Oracle Demo API")
app.include_router(api.router, prefix="/api")


if __name__ == "__main__":
    uvicorn.run("demo_api.main:app", host="127.0.0.1", port=8000, reload=True)
