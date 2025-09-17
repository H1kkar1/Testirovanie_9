import uvicorn
from fastapi import FastAPI
from fastapi.openapi.docs import get_swagger_ui_html, get_swagger_ui_oauth2_redirect_html, get_redoc_html


from app.config import settings
from app.user.router import user_router


app = FastAPI()
app.include_router(user_router)

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        reload=settings.run.reload,
        host=settings.run.host,
        port=settings.run.port,
    )


# На случай если свагер откажется жить

# @app.get("/docs", include_in_schema=False)
# async def custom_swagger_ui_html():
#     return get_swagger_ui_html(
#         openapi_url=app.openapi_url,
#         title=app.title + " - Swagger UI",
#         oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
#         swagger_js_url="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js",
#         swagger_css_url="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css",
#     )
#
#
# @app.get(app.swagger_ui_oauth2_redirect_url, include_in_schema=False)
# async def swagger_ui_redirect():
#     return get_swagger_ui_oauth2_redirect_html()
#
#
# @app.get("/redoc", include_in_schema=False)
# async def redoc_html():
#     return get_redoc_html(
#         openapi_url=app.openapi_url,
#         title=app.title + " - ReDoc",
#         redoc_js_url="https://unpkg.com/redoc@next/bundles/redoc.standalone.js",
#     )
#