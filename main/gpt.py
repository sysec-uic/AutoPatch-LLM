import openai
from openai import OpenAI
import os

def ask_llm_for_patch(client, code, sanitizer_output):
    prompt = f"Here's a piece of code: {code}\nThe sanitizer detected this issue: {sanitizer_output}\nPlease provide a patch to fix this issue."
    chat_completion = client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": prompt,
            }
        ],
        model="gpt-4o-mini",
    )
    return chat_completion.choices[0].message.content

def main():
    client = OpenAI(api_key=os.environ["OPEN_API_KEY"])
    res = ask_llm_for_patch(client, "Hello", "Hello!")
    print(res)

if __name__ == "__main__":
    main()
