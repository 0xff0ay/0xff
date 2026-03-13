import os
import sys

agent = os.getenv('AGENT', 'gpt')
task = os.getenv('TASK', 'Improve documentation')

if agent == 'gpt':
    from openai import OpenAI
    client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "system", "content": f"You are GPT, an AI contributor. Task: {task}"}]
    )
    result = response.choices[0].message.content
    emoji = "🟢"
    name = "GPT AI"
elif agent == 'gemini':
    import google.generativeai as genai
    genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
    model = genai.GenerativeModel('gemini-pro')
    response = model.generate_content(task)
    result = response.text
    emoji = "🟡"
    name = "Gemini AI"
elif agent == 'llama':
    result = f"LLaMA AI: Task - {task}"
    emoji = "🟣"
    name = "LLaMA AI"
elif agent == 'mistral':
    result = f"Mistral AI: Task - {task}"
    emoji = "🔵"
    name = "Mistral AI"
else:
    result = f"AI Agent: Task - {task}"
    emoji = "⚪"
    name = "AI Agent"

print(f"{emoji} {result}")

# Write contribution file
with open('ai_contribution.md', 'w') as f:
    f.write(f"# {name}\n\nTask: {task}\n\n{result}\n")

# Set output for GitHub
with open(os.getenv('GITHUB_OUTPUT', '/tmp/output'), 'a') as f:
    f.write(f"CONTRIBUTION={result}\n")
