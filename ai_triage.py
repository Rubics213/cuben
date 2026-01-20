import google.generativeai as genai
import sys
import os

def triage():
    input_file = sys.argv[1]
    output_path = sys.argv[2]
    
    genai.configure(api_key=os.environ["GEMINI_API_KEY"])
    model = genai.GenerativeModel('gemini-1.5-flash')
    
    with open(input_file, 'r') as f:
        urls = f.readlines()[:100] # Process first 100 for speed
        
    prompt = f"""
    Analyze these URLs for Blind XSS potential. 
    Prioritize parameters that likely reflect in admin panels (e.g., user profiles, logs, contact forms).
    Return only the URLs categorized by priority in this format:
    ---HIGH---
    URL1
    ---MEDIUM---
    URL2
    
    URLs:
    {urls}
    """
    
    response = model.generate_content(prompt)
    content = response.text
    
    # Simple split and save logic
    with open(f"{output_path}/high_priority.txt", "w") as h, open(f"{output_path}/medium_priority.txt", "w") as m:
        if "---HIGH---" in content:
            high_section = content.split("---HIGH---")[1].split("---MEDIUM---")[0]
            h.write(high_section.strip())
        if "---MEDIUM---" in content:
            med_section = content.split("---MEDIUM---")[1]
            m.write(med_section.strip())

if __name__ == "__main__":
    triage()
