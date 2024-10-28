from openai import OpenAI
from dotenv import load_dotenv
import os

def ask_llm_for_patch(client, code, sanitizer_output):
    prompt = f"Here's a piece of code: {code}\nThe sanitizer detected this issue: {sanitizer_output}\nPlease provide a patch to fix this issue."
    chat_completion = client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": prompt,
            },
            {
                "role": "user",
                "content": prompt,
            }
        ],
        model="text-embedding-ada-002",
    )
    #return chat_completion.choices[0].message
    return chat_completion['choices'][0]['text']

def main():
    # Load the openai API key from .env file
    load_dotenv()
    global client
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    res = ask_llm_for_patch(client, "Hello", "Hello!")
    print(res)

if __name__ == "__main__":
    main()