FROM python:3.9


# RUN apt-get update && apt-get install --no-install-recommends -y ffmpeg libsm6 libxext6 && rm -rf /var/lib/apt/lists/*

COPY ./requirements.txt requirements.txt

# RUN python -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple --upgrade pip && pip install -i https://pypi.tuna.tsinghua.edu.cn/simple --no-cache-dir -r requirements.txt
RUN python -m pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt
RUN mkdir -p tmp/

COPY .env .env
COPY ./src /src
COPY ./alembic /alembic
COPY ./alembic.ini .

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "9000"]
