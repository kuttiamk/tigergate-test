import os
import openai

# Hardcoded AI Secret
openai.api_key = "sk-OPENAI_DUMMY_KEY_FOR_TESTING_12345"

def chat(user_input):
    # Prompt injection vulnerability - absolutely no sanitization or system prompt isolation
    prompt = f"Act as a helpful assistant. User says: {user_input}"
    response = openai.Completion.create(model="text-davinci-003", prompt=prompt)
    return response
