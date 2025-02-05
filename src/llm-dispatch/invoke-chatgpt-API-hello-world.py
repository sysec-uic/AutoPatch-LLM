import os
import requests

# Set up the environment variables
API_KEY = os.getenv("OPENAI_API_KEY")
API_URL = "https://api.openai.com/v1/chat/completions"

# Check if the API key is available
if not API_KEY:
    raise ValueError("API key not found. Please set OPENAI_API_KEY environment variable.")

# Set the headers for the request
headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json",
}

# Define the payload with the "Hello, world!" prompt
data = {
    "model": "gpt-3.5-turbo",
    "messages": [
        {"role": "user", "content": "Hello, world!"}
    ]
}

# Make the API request
response = requests.post(API_URL, headers=headers, json=data)

# Check for a successful response
if response.status_code == 200:
    result = response.json()
    # Print the response from ChatGPT
    print(result['choices'][0]['message']['content'])
else:
    print(f"Error: {response.status_code}")
    print(response.json())
