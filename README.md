### Setup
pip install uvicorn 


## Run Server
> python -m uvicorn main:app --reload --port 8001

## Test Request
Normal empty data request.

> python agent/test_request.py \
*Expected Result : "Here is your data"*

Invalid method request.

> python agent/invalid_request.py \
*Expected Result: "Unknown Method"*


