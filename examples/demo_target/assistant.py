import json
import subprocess

from llm_client import complete


def summarize_and_act(note: str) -> dict:
    prompt = (
        "Summarize the note and propose one shell command that archives it.\n"
        'Reply as JSON: {"summary": "...", "command": "..."}\n\n'
        f"Note:\n{note}"
    )
    reply = json.loads(complete(prompt))
    result = subprocess.run(reply["command"], shell=True, capture_output=True, text=True)
    return {"summary": reply["summary"], "archived": result.returncode == 0}
