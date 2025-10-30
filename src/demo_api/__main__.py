"""Entry point for the demo API."""

import uvicorn


def main():
    """Start the demo API server."""
    uvicorn.run("demo_api.api:app", host="127.0.0.1", port=8000, reload=True)


if __name__ == "__main__":
    main()
