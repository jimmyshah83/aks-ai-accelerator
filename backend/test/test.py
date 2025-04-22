import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

API_URL = "http://localhost:8000/v1/chat/completions"
HEADERS = {"Content-Type": "application/json"}
PAYLOAD = {
    "model": "meta-llama/Meta-Llama-3-8B-Instruct",
    "messages": [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Provide a brief sentence describing the Ray open-source project."}
    ],
    "temperature": 0.7
}

def send_request():
    try:
        response = requests.post(API_URL, headers=HEADERS, data=json.dumps(PAYLOAD), timeout=10)
        return response.status_code, response.text
    except Exception as e:
        return None, str(e)

def load_test(num_requests=100, concurrency=10):
    results = []
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(send_request) for _ in range(num_requests)]
        for future in as_completed(futures):
            status, text = future.result()
            results.append((status, text))
            print(f"Status: {status}, Response: {text[:100]}")  # Print first 100 chars of response
    return results

if __name__ == "__main__":
    load_test(num_requests=50, concurrency=5)