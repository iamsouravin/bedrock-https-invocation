# bedrock-https-invocation
Simple HTTPS invocation of bedrock model in Python. This may be useful for consumers unable to update AWS SDKs to versions supporting Bedrock invocation.

NOTE: This is a very naive HTTPS implementation and is not meant for production use as it does not include resiliency mechanisms like robust error handling, retries with exponential backoff and jitter.

To run the sample execute the commands in a compatible shell terminal.

1. Create a Python virtual environment.

```bash
python -m venv venv
```

2. Activate the virtual environment.

```bash
source venv/bin/activate
```

3. Install dependencies.

```bash
python -m pip install -r requirements.txt
```

4. Run `main.py`

```bash
python main.py
```