#!/usr/bin/env python3
"""
Jarwis AGI - Model Training Script
Creates a custom fine-tuned Ollama model with Jarwis knowledge
"""

import subprocess
import sys
import os
from pathlib import Path

def check_ollama_running():
    """Check if Ollama is running"""
    import requests
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=5)
        return response.status_code == 200
    except:
        return False

def get_available_models():
    """Get list of available Ollama models"""
    import requests
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return [model.get("name", "") for model in data.get("models", [])]
    except:
        pass
    return []

def create_jarwis_model():
    """Create the Jarwis fine-tuned model using Ollama"""
    print("\n" + "="*60)
    print("  Jarwis AGI - Model Training")
    print("="*60 + "\n")
    
    # Check if Ollama is running
    if not check_ollama_running():
        print("  Ã¢Å“â€” Ollama is not running!")
        print("  Ã¢â€ â€™ Please start Ollama first: ollama serve")
        return False
    
    print("  Ã¢Å“â€œ Ollama is running")
    
    # Check if base model exists
    models = get_available_models()
    if not any("llama3" in m for m in models):
        print("  Ã¢Å¡Â  llama3 model not found. Pulling it now...")
        result = subprocess.run(["ollama", "pull", "llama3"], capture_output=False)
        if result.returncode != 0:
            print("  Ã¢Å“â€” Failed to pull llama3 model")
            return False
        print("  Ã¢Å“â€œ llama3 model pulled successfully")
    else:
        print("  Ã¢Å“â€œ Base model (llama3) available")
    
    # Get the path to the Modelfile
    script_dir = Path(__file__).parent
    modelfile_path = script_dir / "Modelfile"
    
    if not modelfile_path.exists():
        print(f"  Ã¢Å“â€” Modelfile not found at {modelfile_path}")
        return False
    
    print(f"  Ã¢Å“â€œ Modelfile found: {modelfile_path}")
    
    # Create the custom model
    print("\n  Creating Jarwis AGI model...")
    print("  This may take a few minutes...\n")
    
    result = subprocess.run(
        ["ollama", "create", "jarwis", "-f", str(modelfile_path)],
        capture_output=False
    )
    
    if result.returncode == 0:
        print("\n  Ã¢Å“â€œ Jarwis AGI model created successfully!")
        print("\n  You can now use the model with:")
        print("    ollama run jarwis")
        print("\n  Or in the application, set ai.model to 'jarwis'")
        return True
    else:
        print("\n  Ã¢Å“â€” Failed to create Jarwis model")
        return False

def test_jarwis_model():
    """Test the Jarwis model with a sample query"""
    print("\n" + "="*60)
    print("  Testing Jarwis AGI Model")
    print("="*60 + "\n")
    
    import requests
    
    test_prompt = "What is Jarwis AGI and who founded it?"
    
    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "jarwis",
                "prompt": test_prompt,
                "stream": False
            },
            timeout=60
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"  Prompt: {test_prompt}\n")
            print(f"  Response:\n  {data.get('response', 'No response')[:500]}")
            print("\n  Ã¢Å“â€œ Model is working correctly!")
            return True
        else:
            print(f"  Ã¢Å“â€” Error: {response.status_code}")
            return False
    except Exception as e:
        print(f"  Ã¢Å“â€” Error testing model: {e}")
        return False

if __name__ == "__main__":
    # Install requests if needed
    try:
        import requests
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "requests", "-q"])
        import requests
    
    if create_jarwis_model():
        print("\n" + "-"*60)
        test_jarwis_model()
    
    print("\n" + "="*60)
    print("  Training Complete!")
    print("="*60 + "\n")
