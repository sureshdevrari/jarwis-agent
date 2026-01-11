#!/usr/bin/env python3
"""
Jarwis AGI Chatbot - Terminal Interface
Talk directly to Jarwis AI from the command line
"""

import sys
sys.path.insert(0, '.')

from jarwis_ai.chatbot import JarwisChatbot
import yaml

def main():
    # Load config
    with open('config/config.yaml', 'r') as f:
        config = yaml.safe_load(f)

    print('=' * 50)
    print('  JARWIS AGI CHATBOT - Terminal Mode')
    print('=' * 50)
    print('Type your message and press Enter.')
    print('Type "exit" to quit.')
    print()

    chatbot = JarwisChatbot(config)
    session_id = 'terminal-session'

    if not chatbot._available:
        print('Warning: AI backend not available. Running in offline mode.')
        print()

    while True:
        try:
            user_input = input('You: ')
            if user_input.lower() in ['exit', 'quit', 'bye']:
                print('Jarwis: Goodbye! Stay secure!')
                break
            if not user_input.strip():
                continue
            
            response = chatbot.chat(session_id, user_input)
            # Handle generator (streaming) response
            if hasattr(response, '__iter__') and not isinstance(response, str):
                print('Jarwis: ', end='', flush=True)
                full_response = ''
                for chunk in response:
                    print(chunk, end='', flush=True)
                    full_response += chunk
                print()
            else:
                print(f'Jarwis: {response}')
            print()
        except KeyboardInterrupt:
            print('\nJarwis: Goodbye!')
            break
        except Exception as e:
            print(f'Error: {e}')

if __name__ == '__main__':
    main()
